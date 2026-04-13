package refiner

import (
	"context"
	"encoding/json"
	"net/netip"
	"testing"

	"github.com/runreveal/kawa"
	"github.com/runreveal/reveald/internal/types"
)

type fakeSource struct {
	events []types.Event
	idx    int
}

func (f *fakeSource) Run(ctx context.Context) error {
	<-ctx.Done()
	return ctx.Err()
}

func (f *fakeSource) Recv(ctx context.Context) (kawa.Message[types.Event], func(), error) {
	if f.idx >= len(f.events) {
		<-ctx.Done()
		return kawa.Message[types.Event]{}, nil, ctx.Err()
	}
	e := f.events[f.idx]
	f.idx++
	return kawa.Message[types.Event]{Value: e}, func() {}, nil
}

func rawJSON(t *testing.T, v any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func recv(t *testing.T, r *Refiner) types.Event {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	msg, _, err := r.Recv(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return msg.Value
}

func TestRefiner(t *testing.T) {
	tests := []struct {
		name  string
		rules []Rule
		event types.Event
		check func(t *testing.T, e types.Event)
	}{
		{
			name:  "no rules passthrough",
			rules: nil,
			event: types.Event{
				SourceType: "journald",
				RawLog:     rawJSON(t, map[string]any{"SYSLOG_IDENTIFIER": "sshd"}),
			},
			check: func(t *testing.T, e types.Event) {
				if e.SourceType != "journald" {
					t.Errorf("sourceType = %q, want journald", e.SourceType)
				}
			},
		},
		{
			name: "no match passthrough",
			rules: []Rule{{
				Match:   []Condition{{Path: "rawLog.SYSLOG_IDENTIFIER", Value: "coredns"}},
				Extract: []Extraction{{To: "sourceType", From: "rawLog.SYSLOG_IDENTIFIER"}},
			}},
			event: types.Event{
				SourceType: "journald",
				RawLog:     rawJSON(t, map[string]any{"SYSLOG_IDENTIFIER": "sshd"}),
			},
			check: func(t *testing.T, e types.Event) {
				if e.SourceType != "journald" {
					t.Errorf("sourceType = %q, want journald", e.SourceType)
				}
			},
		},
		{
			name: "match rawLog and override sourceType",
			rules: []Rule{{
				Match: []Condition{{Path: "rawLog.SYSLOG_IDENTIFIER", Value: "coredns"}},
				Extract: []Extraction{
					{To: "sourceType", From: "rawLog.SYSLOG_IDENTIFIER"},
				},
			}},
			event: types.Event{
				SourceType: "journald",
				RawLog:     rawJSON(t, map[string]any{"SYSLOG_IDENTIFIER": "coredns"}),
			},
			check: func(t *testing.T, e types.Event) {
				if e.SourceType != "coredns" {
					t.Errorf("sourceType = %q, want coredns", e.SourceType)
				}
			},
		},
		{
			name: "match on normalized field",
			rules: []Rule{{
				Match: []Condition{{Path: "normalized.service.name", Value: "coredns"}},
				Extract: []Extraction{
					{To: "sourceType", From: "rawLog.SYSLOG_IDENTIFIER"},
				},
			}},
			event: types.Event{
				SourceType: "journald",
				RawLog:     rawJSON(t, map[string]any{"SYSLOG_IDENTIFIER": "coredns"}),
				Normalized: types.Normalized{Service: types.Service{Name: "coredns"}},
			},
			check: func(t *testing.T, e types.Event) {
				if e.SourceType != "coredns" {
					t.Errorf("sourceType = %q, want coredns", e.SourceType)
				}
			},
		},
		{
			name: "match on sourceType",
			rules: []Rule{{
				Match: []Condition{{Path: "sourceType", Value: "journald"}},
				Extract: []Extraction{
					{To: "service.name", From: "rawLog.SYSLOG_IDENTIFIER"},
				},
			}},
			event: types.Event{
				SourceType: "journald",
				RawLog:     rawJSON(t, map[string]any{"SYSLOG_IDENTIFIER": "sshd"}),
			},
			check: func(t *testing.T, e types.Event) {
				if e.Normalized.Service.Name != "sshd" {
					t.Errorf("service.name = %q, want sshd", e.Normalized.Service.Name)
				}
			},
		},
		{
			name: "contains operator",
			rules: []Rule{{
				Match: []Condition{{Path: "rawLog.MESSAGE", Op: "contains", Value: "REJECT"}},
				Extract: []Extraction{
					{To: "sourceType", From: "rawLog.SYSLOG_IDENTIFIER"},
				},
			}},
			event: types.Event{
				SourceType: "journald",
				RawLog:     rawJSON(t, map[string]any{"SYSLOG_IDENTIFIER": "kernel", "MESSAGE": "REJECT IN=eth0 OUT="}),
			},
			check: func(t *testing.T, e types.Event) {
				if e.SourceType != "kernel" {
					t.Errorf("sourceType = %q, want kernel", e.SourceType)
				}
			},
		},
		{
			name: "prefix operator",
			rules: []Rule{{
				Match: []Condition{{Path: "rawLog.MESSAGE", Op: "prefix", Value: "DROP"}},
				Extract: []Extraction{
					{To: "tags.action", From: "rawLog.MESSAGE"},
				},
			}},
			event: types.Event{
				SourceType: "syslog",
				RawLog:     rawJSON(t, map[string]any{"MESSAGE": "DROP IN=eth0"}),
			},
			check: func(t *testing.T, e types.Event) {
				if e.Normalized.Tags["action"] != "DROP IN=eth0" {
					t.Errorf("tags.action = %q", e.Normalized.Tags["action"])
				}
			},
		},
		{
			name: "exists operator",
			rules: []Rule{{
				Match: []Condition{{Path: "rawLog.special_field", Op: "exists"}},
				Extract: []Extraction{
					{To: "tags.found", From: "rawLog.special_field"},
				},
			}},
			event: types.Event{
				SourceType: "file",
				RawLog:     rawJSON(t, map[string]any{"special_field": "yes"}),
			},
			check: func(t *testing.T, e types.Event) {
				if e.Normalized.Tags["found"] != "yes" {
					t.Errorf("tags.found = %q, want yes", e.Normalized.Tags["found"])
				}
			},
		},
		{
			name: "AND conditions",
			rules: []Rule{{
				Match: []Condition{
					{Path: "rawLog.SYSLOG_IDENTIFIER", Value: "kernel"},
					{Path: "rawLog.MESSAGE", Op: "contains", Value: "REJECT"},
				},
				Extract: []Extraction{
					{To: "sourceType", From: "rawLog.SYSLOG_IDENTIFIER"},
				},
			}},
			event: types.Event{
				SourceType: "journald",
				RawLog:     rawJSON(t, map[string]any{"SYSLOG_IDENTIFIER": "kernel", "MESSAGE": "REJECT IN=eth0"}),
			},
			check: func(t *testing.T, e types.Event) {
				if e.SourceType != "kernel" {
					t.Errorf("sourceType = %q, want kernel", e.SourceType)
				}
			},
		},
		{
			name: "AND conditions partial fail",
			rules: []Rule{{
				Match: []Condition{
					{Path: "rawLog.SYSLOG_IDENTIFIER", Value: "kernel"},
					{Path: "rawLog.MESSAGE", Op: "contains", Value: "ACCEPT"},
				},
				Extract: []Extraction{
					{To: "sourceType", From: "rawLog.SYSLOG_IDENTIFIER"},
				},
			}},
			event: types.Event{
				SourceType: "journald",
				RawLog:     rawJSON(t, map[string]any{"SYSLOG_IDENTIFIER": "kernel", "MESSAGE": "REJECT IN=eth0"}),
			},
			check: func(t *testing.T, e types.Event) {
				if e.SourceType != "journald" {
					t.Errorf("sourceType = %q, want journald (no match)", e.SourceType)
				}
			},
		},
		{
			name: "first match wins",
			rules: []Rule{
				{
					Match:   []Condition{{Path: "rawLog.SYSLOG_IDENTIFIER", Value: "coredns"}},
					Extract: []Extraction{{To: "sourceType", From: "rawLog.SYSLOG_IDENTIFIER"}},
				},
				{
					Match:   []Condition{{Path: "rawLog.SYSLOG_IDENTIFIER", Op: "exists"}},
					Extract: []Extraction{{To: "tags.catchall", From: "rawLog.SYSLOG_IDENTIFIER"}},
				},
			},
			event: types.Event{
				SourceType: "journald",
				RawLog:     rawJSON(t, map[string]any{"SYSLOG_IDENTIFIER": "coredns"}),
			},
			check: func(t *testing.T, e types.Event) {
				if e.SourceType != "coredns" {
					t.Errorf("sourceType = %q, want coredns", e.SourceType)
				}
				if _, ok := e.Normalized.Tags["catchall"]; ok {
					t.Error("catchall tag should not be set (first match wins)")
				}
			},
		},
		{
			name: "extract IP and port",
			rules: []Rule{{
				Match: []Condition{{Path: "rawLog.type", Value: "conn"}},
				Extract: []Extraction{
					{To: "src.ip", From: "rawLog.src_ip"},
					{To: "src.port", From: "rawLog.src_port"},
					{To: "dst.ip", From: "rawLog.dst_ip"},
					{To: "dst.port", From: "rawLog.dst_port"},
				},
			}},
			event: types.Event{
				SourceType: "file",
				RawLog: rawJSON(t, map[string]any{
					"type":     "conn",
					"src_ip":   "192.168.1.100",
					"src_port": "43210",
					"dst_ip":   "10.0.0.1",
					"dst_port": "22",
				}),
			},
			check: func(t *testing.T, e types.Event) {
				if e.Normalized.Src.IP != netip.MustParseAddr("192.168.1.100") {
					t.Errorf("src.ip = %v", e.Normalized.Src.IP)
				}
				if e.Normalized.Src.Port != 43210 {
					t.Errorf("src.port = %d", e.Normalized.Src.Port)
				}
				if e.Normalized.Dst.IP != netip.MustParseAddr("10.0.0.1") {
					t.Errorf("dst.ip = %v", e.Normalized.Dst.IP)
				}
				if e.Normalized.Dst.Port != 22 {
					t.Errorf("dst.port = %d", e.Normalized.Dst.Port)
				}
			},
		},
		{
			name: "extract actor fields",
			rules: []Rule{{
				Match: []Condition{{Path: "rawLog.app", Value: "myapp"}},
				Extract: []Extraction{
					{To: "actor.id", From: "rawLog.user.id"},
					{To: "actor.email", From: "rawLog.user.email"},
					{To: "actor.username", From: "rawLog.user.name"},
					{To: "eventName", From: "rawLog.action"},
				},
			}},
			event: types.Event{
				SourceType: "file",
				RawLog: rawJSON(t, map[string]any{
					"app":    "myapp",
					"action": "login",
					"user":   map[string]any{"id": "usr_123", "email": "a@b.com", "name": "alice"},
				}),
			},
			check: func(t *testing.T, e types.Event) {
				if e.Normalized.Actor.ID != "usr_123" {
					t.Errorf("actor.id = %q", e.Normalized.Actor.ID)
				}
				if e.Normalized.Actor.Email != "a@b.com" {
					t.Errorf("actor.email = %q", e.Normalized.Actor.Email)
				}
				if e.Normalized.Actor.Username != "alice" {
					t.Errorf("actor.username = %q", e.Normalized.Actor.Username)
				}
				if e.Normalized.EventName != "login" {
					t.Errorf("eventName = %q", e.Normalized.EventName)
				}
			},
		},
		{
			name: "non-JSON rawLog passthrough",
			rules: []Rule{{
				Match:   []Condition{{Path: "rawLog.anything", Op: "exists"}},
				Extract: []Extraction{{To: "sourceType", From: "rawLog.anything"}},
			}},
			event: types.Event{
				SourceType: "syslog",
				RawLog:     json.RawMessage(`not valid JSON`),
			},
			check: func(t *testing.T, e types.Event) {
				if e.SourceType != "syslog" {
					t.Errorf("sourceType = %q, want syslog (passthrough)", e.SourceType)
				}
			},
		},
		{
			name: "missing from field skips extraction",
			rules: []Rule{{
				Match: []Condition{{Path: "rawLog.type", Value: "test"}},
				Extract: []Extraction{
					{To: "service.name", From: "rawLog.nonexistent"},
					{To: "eventName", From: "rawLog.action"},
				},
			}},
			event: types.Event{
				SourceType: "file",
				RawLog:     rawJSON(t, map[string]any{"type": "test", "action": "do_thing"}),
			},
			check: func(t *testing.T, e types.Event) {
				if e.Normalized.Service.Name != "" {
					t.Errorf("service.name = %q, want empty", e.Normalized.Service.Name)
				}
				if e.Normalized.EventName != "do_thing" {
					t.Errorf("eventName = %q, want do_thing", e.Normalized.EventName)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var r *Refiner
			var err error
			if len(tt.rules) == 0 {
				// New requires at least one match condition per rule,
				// so for the no-rules case, build directly.
				r = &Refiner{inner: &fakeSource{events: []types.Event{tt.event}}}
			} else {
				r, err = New(&fakeSource{events: []types.Event{tt.event}}, tt.rules)
				if err != nil {
					t.Fatal(err)
				}
			}
			e := recv(t, r)
			tt.check(t, e)
		})
	}
}

func TestNewValidation(t *testing.T) {
	_, err := New(nil, []Rule{{Match: nil}})
	if err == nil {
		t.Error("expected error for rule with no match conditions")
	}

	_, err = New(nil, []Rule{{Match: []Condition{{Path: ""}}}})
	if err == nil {
		t.Error("expected error for condition with empty path")
	}
}
