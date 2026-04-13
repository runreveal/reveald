// Package regexparser provides a middleware that wraps any kawa.Source[types.Event]
// and applies configurable regex rules to parse text fields in rawLog into
// structured JSON fields.
//
// Two modes:
//   - Field set: parse a nested field inside a JSON rawLog object, merge captures under Target
//   - Field omitted: parse rawLog itself as a bare JSON string, replace with structured JSON
package regexparser

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"log/slog"

	"github.com/runreveal/kawa"
	"github.com/runreveal/reveald/internal/types"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

// Rule defines a regex parsing rule.
type Rule struct {
	Match   []Condition `json:"match"`
	Field   string      `json:"field,omitempty"`
	Pattern string      `json:"pattern"`
	Target  string      `json:"target,omitempty"`

	compiled *regexp.Regexp
}

// Condition is the same structure as the refiner's — match against event state.
type Condition struct {
	Path  string `json:"path"`
	Op    string `json:"op,omitempty"` // "eq" (default), "contains", "prefix", "exists"
	Value string `json:"value,omitempty"`
}

// RegexParser wraps a source and applies regex parsing rules to events.
type RegexParser struct {
	inner kawa.Source[types.Event]
	rules []Rule
}

// New creates a RegexParser. Compiles all regex patterns and validates rules.
func New(inner kawa.Source[types.Event], rules []Rule) (*RegexParser, error) {
	for i := range rules {
		if rules[i].Pattern == "" {
			return nil, fmt.Errorf("rule %d: pattern is required", i)
		}
		compiled, err := regexp.Compile(rules[i].Pattern)
		if err != nil {
			return nil, fmt.Errorf("rule %d: compiling pattern: %w", i, err)
		}
		names := compiled.SubexpNames()
		hasNamed := false
		for _, n := range names {
			if n != "" {
				hasNamed = true
				break
			}
		}
		if !hasNamed {
			return nil, fmt.Errorf("rule %d: pattern must have at least one named capture group (?P<name>)", i)
		}
		rules[i].compiled = compiled
		if rules[i].Target == "" {
			rules[i].Target = "parsed"
		}
		if len(rules[i].Match) == 0 {
			return nil, fmt.Errorf("rule %d: at least one match condition is required", i)
		}
	}
	return &RegexParser{inner: inner, rules: rules}, nil
}

// Run delegates to the inner source.
func (rp *RegexParser) Run(ctx context.Context) error {
	type runner interface {
		Run(context.Context) error
	}
	if r, ok := rp.inner.(runner); ok {
		return r.Run(ctx)
	}
	<-ctx.Done()
	return ctx.Err()
}

// Recv receives an event and applies the first matching regex rule.
func (rp *RegexParser) Recv(ctx context.Context) (kawa.Message[types.Event], func(), error) {
	msg, ack, err := rp.inner.Recv(ctx)
	if err != nil {
		return msg, ack, err
	}
	rp.apply(&msg.Value)
	return msg, ack, nil
}

func (rp *RegexParser) apply(event *types.Event) {
	for i := range rp.rules {
		if rp.rules[i].matches(event) {
			rp.rules[i].applyTo(event)
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
		return ""
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

// applyFieldMode: rawLog is a JSON object, parse a nested field, merge captures.
func (r *Rule) applyFieldMode(event *types.Event) {
	if !json.Valid(event.RawLog) {
		return
	}
	result := gjson.GetBytes(event.RawLog, r.Field)
	if !result.Exists() {
		return
	}
	text := result.String()

	captures := r.extractCaptures(text)
	if captures == nil {
		slog.Debug("regexparser: regex did not match", "field", r.Field)
		return
	}

	raw := []byte(event.RawLog)
	for name, val := range captures {
		path := r.Target + "." + name
		var err error
		raw, err = sjson.SetBytes(raw, path, val)
		if err != nil {
			slog.Warn("regexparser: sjson.SetBytes failed", "path", path, "err", err)
		}
	}
	event.RawLog = json.RawMessage(raw)
}

// applyBareMode: rawLog is a bare JSON string, parse it, replace with JSON object.
func (r *Rule) applyBareMode(event *types.Event) {
	var text string
	if err := json.Unmarshal(event.RawLog, &text); err != nil {
		// rawLog might be a JSON object, not a string — try getting it as-is
		if json.Valid(event.RawLog) {
			// It's a JSON object/array, not a string — nothing to do in bare mode
			return
		}
		// Not valid JSON at all — try using raw bytes as the text
		text = string(event.RawLog)
	}

	captures := r.extractCaptures(text)
	if captures == nil {
		slog.Debug("regexparser: regex did not match bare string")
		return
	}

	// Build a new JSON object with _raw + captures.
	raw := []byte(`{}`)
	var err error
	raw, err = sjson.SetBytes(raw, "_raw", text)
	if err != nil {
		return
	}
	for name, val := range captures {
		raw, err = sjson.SetBytes(raw, name, val)
		if err != nil {
			slog.Warn("regexparser: sjson.SetBytes failed", "key", name, "err", err)
		}
	}
	event.RawLog = json.RawMessage(raw)
}

func (r *Rule) extractCaptures(text string) map[string]string {
	match := r.compiled.FindStringSubmatch(text)
	if match == nil {
		return nil
	}
	captures := make(map[string]string)
	for i, name := range r.compiled.SubexpNames() {
		if i != 0 && name != "" && match[i] != "" {
			captures[name] = match[i]
		}
	}
	if len(captures) == 0 {
		return nil
	}
	return captures
}
