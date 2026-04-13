// Package refiner provides a middleware that wraps any kawa.Source[types.Event]
// and applies configurable extraction rules to refine events — setting specific
// sourceTypes and extracting fields from rawLog into the Normalized struct.
//
// The refiner operates on events that already have baseline normalization from
// their source. It adds detail, not replaces it.
package refiner

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"log/slog"

	"github.com/runreveal/kawa"
	"github.com/runreveal/reveald/internal/types"
	"github.com/tidwall/gjson"
)

// Rule defines a set of match conditions and the extractions to apply.
//
// Example config:
//
//	{
//	  "match": [{"path": "rawLog.SYSLOG_IDENTIFIER", "value": "coredns"}],
//	  "extract": [
//	    {"to": "sourceType",  "from": "rawLog.SYSLOG_IDENTIFIER"},
//	    {"to": "service.name", "from": "rawLog.SYSLOG_IDENTIFIER"},
//	    {"to": "tags.qname",   "from": "rawLog.MESSAGE.qname"}
//	  ]
//	}
type Rule struct {
	// Match is a list of conditions that must ALL be true for this rule to apply.
	Match []Condition `json:"match"`
	// Extract maps fields from the event into Normalized fields or sourceType.
	Extract []Extraction `json:"extract,omitempty"`
}

// Condition defines a single match condition against the event.
// Path is prefixed to indicate what to query:
//   - "rawLog.<gjson_path>" — gjson query into the raw log JSON
//   - "sourceType" — the event's current SourceType
//   - "normalized.<field>" — a normalized field (e.g., "normalized.service.name")
type Condition struct {
	Path  string `json:"path"`
	Op    string `json:"op,omitempty"` // "eq" (default), "contains", "prefix", "exists"
	Value string `json:"value,omitempty"`
}

// Extraction maps a source field to a target field on the event.
// To targets:
//   - "sourceType" — override the event's SourceType
//   - "eventName", "src.ip", "src.port", "dst.ip", "dst.port"
//   - "service.name", "actor.id", "actor.email", "actor.username"
//   - "tags.<key>" — set a tag
type Extraction struct {
	// To is the target field on the event.
	To string `json:"to"`
	// From is a gjson path into rawLog (prefixed with "rawLog.") or a literal value.
	From string `json:"from"`
}

// Refiner wraps a source and applies rules to refine events.
type Refiner struct {
	inner kawa.Source[types.Event]
	rules []Rule
}

// New creates a Refiner wrapping the given source with the given rules.
func New(inner kawa.Source[types.Event], rules []Rule) (*Refiner, error) {
	for i, r := range rules {
		if len(r.Match) == 0 {
			return nil, fmt.Errorf("rule %d: at least one match condition is required", i)
		}
		for j, c := range r.Match {
			if c.Path == "" {
				return nil, fmt.Errorf("rule %d, condition %d: path is required", i, j)
			}
		}
	}
	return &Refiner{inner: inner, rules: rules}, nil
}

// Run delegates to the inner source if it implements a Run method.
func (r *Refiner) Run(ctx context.Context) error {
	type runner interface {
		Run(context.Context) error
	}
	if rn, ok := r.inner.(runner); ok {
		return rn.Run(ctx)
	}
	<-ctx.Done()
	return ctx.Err()
}

// Recv receives an event from the inner source and applies matching rules.
func (r *Refiner) Recv(ctx context.Context) (kawa.Message[types.Event], func(), error) {
	msg, ack, err := r.inner.Recv(ctx)
	if err != nil {
		return msg, ack, err
	}
	r.apply(&msg.Value)
	return msg, ack, nil
}

func (r *Refiner) apply(event *types.Event) {
	for i := range r.rules {
		if r.rules[i].matches(event) {
			r.rules[i].applyTo(event)
			return // first match wins
		}
	}
}

func (r *Rule) matches(event *types.Event) bool {
	for _, cond := range r.Match {
		if !cond.evaluate(event) {
			return false // AND: all conditions must match
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
		slog.Warn("refiner: unknown match operator", "op", op)
		return false
	}
}

// resolveRead extracts a string value from the event by path.
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

	if strings.HasPrefix(path, "normalized.") {
		field := strings.TrimPrefix(path, "normalized.")
		return getNormalized(&event.Normalized, field)
	}

	return ""
}

func (r *Rule) applyTo(event *types.Event) {
	for _, ext := range r.Extract {
		val := resolveRead(event, ext.From)
		if val == "" {
			continue
		}
		setField(event, ext.To, val)
	}
}

// setField writes a value to the event by target path.
func setField(event *types.Event, path string, val string) {
	if path == "sourceType" {
		event.SourceType = val
		return
	}
	setNormalized(&event.Normalized, path, val)
}

// getNormalized reads a field from the Normalized struct by dot-path.
func getNormalized(n *types.Normalized, path string) string {
	switch path {
	case "eventName":
		return n.EventName
	case "src.ip":
		if n.Src.IP.IsValid() {
			return n.Src.IP.String()
		}
		return ""
	case "src.port":
		if n.Src.Port != 0 {
			return strconv.FormatUint(uint64(n.Src.Port), 10)
		}
		return ""
	case "dst.ip":
		if n.Dst.IP.IsValid() {
			return n.Dst.IP.String()
		}
		return ""
	case "dst.port":
		if n.Dst.Port != 0 {
			return strconv.FormatUint(uint64(n.Dst.Port), 10)
		}
		return ""
	case "service.name":
		return n.Service.Name
	case "actor.id":
		return n.Actor.ID
	case "actor.email":
		return n.Actor.Email
	case "actor.username":
		return n.Actor.Username
	default:
		if strings.HasPrefix(path, "tags.") {
			key := strings.TrimPrefix(path, "tags.")
			if n.Tags != nil {
				return n.Tags[key]
			}
		}
	}
	return ""
}

// setNormalized writes a value to the Normalized struct by dot-path.
func setNormalized(n *types.Normalized, path string, val string) {
	switch path {
	case "eventName":
		n.EventName = val
	case "src.ip":
		if addr, err := netip.ParseAddr(val); err == nil {
			n.Src.IP = addr
		}
	case "src.port":
		if p, err := strconv.ParseUint(val, 10, 32); err == nil {
			n.Src.Port = uint(p)
		}
	case "dst.ip":
		if addr, err := netip.ParseAddr(val); err == nil {
			n.Dst.IP = addr
		}
	case "dst.port":
		if p, err := strconv.ParseUint(val, 10, 32); err == nil {
			n.Dst.Port = uint(p)
		}
	case "service.name":
		n.Service.Name = val
	case "actor.id":
		n.Actor.ID = val
	case "actor.email":
		n.Actor.Email = val
	case "actor.username":
		n.Actor.Username = val
	default:
		if strings.HasPrefix(path, "tags.") {
			key := strings.TrimPrefix(path, "tags.")
			if n.Tags == nil {
				n.Tags = make(map[string]string)
			}
			n.Tags[key] = val
		} else {
			slog.Warn("refiner: unknown target path", "path", path)
		}
	}
}
