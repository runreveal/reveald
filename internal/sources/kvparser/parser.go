// Package kvparser provides a middleware that wraps any kawa.Source[types.Event]
// and applies configurable key=value parsing rules to extract structured fields
// from text in rawLog.
//
// Handles both logfmt-style (key=value key2="quoted value") and kernel-style
// (PREFIX IN=eth0 OUT= SRC=10.0.0.1) key-value formats.
//
// Two modes (same as regexparser):
//   - Field set: parse a nested field inside a JSON rawLog object, merge under Target
//   - Field omitted: parse rawLog itself as a bare JSON string, replace with JSON object
package kvparser

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"log/slog"

	"github.com/runreveal/kawa"
	"github.com/runreveal/reveald/internal/types"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

// Rule defines a kv parsing rule.
type Rule struct {
	// Match conditions — same semantics as refiner/regex: gjson paths into rawLog,
	// all must be true.
	Match []Condition `json:"match"`

	// Field is a gjson path to the text field to parse inside rawLog.
	// If set: extract the string, parse kv, merge into rawLog under Target.
	// If omitted: treat rawLog as a bare JSON string, parse kv, replace rawLog.
	Field string `json:"field,omitempty"`

	// PairSep separates key=value pairs. Default is whitespace (empty string).
	PairSep string `json:"pairSep,omitempty"`

	// KVSep separates keys from values. Default is "=".
	KVSep string `json:"kvSep,omitempty"`

	// Target key under which parsed fields are merged into rawLog.
	// Only used when Field is set. Defaults to "parsed".
	Target string `json:"target,omitempty"`
}

// Condition matches against event state.
type Condition struct {
	Path  string `json:"path"`
	Op    string `json:"op,omitempty"` // "eq" (default), "contains", "prefix", "exists"
	Value string `json:"value,omitempty"`
}

// KVParser wraps a source and applies kv parsing rules to events.
type KVParser struct {
	inner kawa.Source[types.Event]
	rules []Rule
}

// New creates a KVParser wrapping the given source.
func New(inner kawa.Source[types.Event], rules []Rule) (*KVParser, error) {
	for i := range rules {
		if len(rules[i].Match) == 0 {
			return nil, fmt.Errorf("rule %d: at least one match condition is required", i)
		}
		if rules[i].KVSep == "" {
			rules[i].KVSep = "="
		}
		if rules[i].Target == "" {
			rules[i].Target = "parsed"
		}
	}
	return &KVParser{inner: inner, rules: rules}, nil
}

// Run delegates to the inner source.
func (kp *KVParser) Run(ctx context.Context) error {
	type runner interface {
		Run(context.Context) error
	}
	if r, ok := kp.inner.(runner); ok {
		return r.Run(ctx)
	}
	<-ctx.Done()
	return ctx.Err()
}

// Recv receives an event and applies the first matching kv rule.
func (kp *KVParser) Recv(ctx context.Context) (kawa.Message[types.Event], func(), error) {
	msg, ack, err := kp.inner.Recv(ctx)
	if err != nil {
		return msg, ack, err
	}
	kp.apply(&msg.Value)
	return msg, ack, nil
}

func (kp *KVParser) apply(event *types.Event) {
	for i := range kp.rules {
		if kp.rules[i].matches(event) {
			kp.rules[i].applyTo(event)
			return
		}
	}
}

func (r *Rule) matches(event *types.Event) bool {
	for _, cond := range r.Match {
		if !cond.evaluate(event) {
			return false
		}
	}
	return true
}

func (c *Condition) evaluate(event *types.Event) bool {
	actual := resolveRead(event, c.Path)
	op := c.Op
	if op == "" {
		op = "eq"
	}
	switch op {
	case "eq":
		return actual == c.Value
	case "contains":
		return strings.Contains(actual, c.Value)
	case "prefix":
		return strings.HasPrefix(actual, c.Value)
	case "exists":
		return actual != ""
	default:
		return false
	}
}

func resolveRead(event *types.Event, path string) string {
	if path == "sourceType" {
		return event.SourceType
	}
	if strings.HasPrefix(path, "rawLog.") {
		gjsonPath := strings.TrimPrefix(path, "rawLog.")
		if !json.Valid(event.RawLog) {
			return ""
		}
		result := gjson.GetBytes(event.RawLog, gjsonPath)
		if result.Exists() {
			return result.String()
		}
	}
	return ""
}

func (r *Rule) applyTo(event *types.Event) {
	if r.Field != "" {
		r.applyFieldMode(event)
	} else {
		r.applyBareMode(event)
	}
}

func (r *Rule) applyFieldMode(event *types.Event) {
	if !json.Valid(event.RawLog) {
		return
	}
	result := gjson.GetBytes(event.RawLog, r.Field)
	if !result.Exists() {
		return
	}

	pairs := parseKV(result.String(), r.KVSep)
	if len(pairs) == 0 {
		return
	}

	raw := []byte(event.RawLog)
	for k, v := range pairs {
		path := r.Target + "." + k
		var err error
		raw, err = sjson.SetBytes(raw, path, v)
		if err != nil {
			slog.Warn("kvparser: sjson.SetBytes failed",
				"path", path, "err", err)
		}
	}
	event.RawLog = json.RawMessage(raw)
}

func (r *Rule) applyBareMode(event *types.Event) {
	var text string
	if err := json.Unmarshal(event.RawLog, &text); err != nil {
		if json.Valid(event.RawLog) {
			return // JSON object/array, not a string
		}
		text = string(event.RawLog)
	}

	pairs := parseKV(text, r.KVSep)
	if len(pairs) == 0 {
		return
	}

	raw := []byte(`{}`)
	var err error
	raw, err = sjson.SetBytes(raw, "_raw", text)
	if err != nil {
		return
	}
	for k, v := range pairs {
		raw, err = sjson.SetBytes(raw, k, v)
		if err != nil {
			slog.Warn("kvparser: sjson.SetBytes failed",
				"key", k, "err", err)
		}
	}
	event.RawLog = json.RawMessage(raw)
}

// parseKV parses a key=value string into a map. Handles:
//   - Unquoted values: key=value (terminated by whitespace)
//   - Quoted values: key="value with spaces" (double quotes, backslash escapes)
//   - Empty values: key= (value is empty string)
//   - Prefix text before the first key=value pair → stored as "_prefix"
func parseKV(input string, sep string) map[string]string {
	if input == "" {
		return nil
	}

	result := make(map[string]string)
	i := 0
	n := len(input)
	prefixEnd := -1

	// Find the first occurrence of sep to determine where kv pairs start.
	// Everything before the key of the first pair is the prefix.
	firstSep := strings.Index(input, sep)
	if firstSep < 0 {
		return nil // no kv pairs at all
	}

	// Walk back from firstSep to find the start of the first key.
	keyStart := firstSep
	for keyStart > 0 && input[keyStart-1] != ' ' && input[keyStart-1] != '\t' {
		keyStart--
	}
	if keyStart > 0 {
		prefix := strings.TrimSpace(input[:keyStart])
		if prefix != "" {
			result["_prefix"] = prefix
		}
	}
	prefixEnd = keyStart
	_ = prefixEnd
	i = keyStart

	for i < n {
		// Skip whitespace between pairs.
		for i < n && (input[i] == ' ' || input[i] == '\t') {
			i++
		}
		if i >= n {
			break
		}

		// Find the separator.
		sepIdx := strings.Index(input[i:], sep)
		if sepIdx < 0 {
			break // no more kv pairs
		}
		sepIdx += i

		// The key is from current position to the separator.
		key := input[i:sepIdx]
		// Key should not contain spaces — if it does, we've overshot.
		if spaceIdx := strings.IndexAny(key, " \t"); spaceIdx >= 0 {
			// There's a space in what we thought was the key.
			// The real key starts after the last space.
			key = key[spaceIdx+1:]
		}

		i = sepIdx + len(sep)
		if i >= n {
			// key= at end of string — empty value
			result[key] = ""
			break
		}

		// Parse the value.
		if input[i] == '"' {
			// Quoted value — find closing quote.
			i++ // skip opening quote
			var val strings.Builder
			for i < n {
				if input[i] == '\\' && i+1 < n {
					val.WriteByte(input[i+1])
					i += 2
				} else if input[i] == '"' {
					i++ // skip closing quote
					break
				} else {
					val.WriteByte(input[i])
					i++
				}
			}
			result[key] = val.String()
		} else {
			// Unquoted value — read until whitespace.
			valStart := i
			for i < n && input[i] != ' ' && input[i] != '\t' {
				i++
			}
			result[key] = input[valStart:i]
		}
	}

	if len(result) == 0 {
		return nil
	}
	return result
}
