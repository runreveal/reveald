package regexparser

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/runreveal/kawa"
	"github.com/runreveal/reveald/internal/types"
	"github.com/tidwall/gjson"
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

func recv(t *testing.T, rp *RegexParser) types.Event {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	msg, _, err := rp.Recv(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return msg.Value
}

func TestRegexParser(t *testing.T) {
	tests := []struct {
		name  string
		rules []Rule
		event types.Event
		check func(t *testing.T, e types.Event)
	}{
		{
			name: "mode1: unbound DNS field parsing",
			rules: []Rule{{
				Match:   []Condition{{Path: "rawLog.SYSLOG_IDENTIFIER", Value: "unbound"}},
				Field:   "MESSAGE.text",
				Pattern: `\[\d+:\d+\] (?P<action>\w+): (?P<client_ip>[\d.]+) (?P<qname>\S+)\. (?P<qtype>\w+) (?P<qclass>\w+) (?P<rcode>\w+)`,
				Target:  "parsed",
			}},
			event: types.Event{
				SourceType: "journald",
				RawLog: rawJSON(t, map[string]any{
					"SYSLOG_IDENTIFIER": "unbound",
					"MESSAGE": map[string]any{
						"text": "[1107:1] reply: 172.16.20.145 slack.com. A IN NOERROR 0.004161 0 171",
					},
				}),
			},
			check: func(t *testing.T, e types.Event) {
				if gjson.GetBytes(e.RawLog, "parsed.action").String() != "reply" {
					t.Errorf("parsed.action = %q, want reply", gjson.GetBytes(e.RawLog, "parsed.action"))
				}
				if gjson.GetBytes(e.RawLog, "parsed.client_ip").String() != "172.16.20.145" {
					t.Errorf("parsed.client_ip = %q", gjson.GetBytes(e.RawLog, "parsed.client_ip"))
				}
				if gjson.GetBytes(e.RawLog, "parsed.qname").String() != "slack.com" {
					t.Errorf("parsed.qname = %q", gjson.GetBytes(e.RawLog, "parsed.qname"))
				}
				if gjson.GetBytes(e.RawLog, "parsed.qtype").String() != "A" {
					t.Errorf("parsed.qtype = %q", gjson.GetBytes(e.RawLog, "parsed.qtype"))
				}
				if gjson.GetBytes(e.RawLog, "parsed.rcode").String() != "NOERROR" {
					t.Errorf("parsed.rcode = %q", gjson.GetBytes(e.RawLog, "parsed.rcode"))
				}
				// Original fields preserved
				if gjson.GetBytes(e.RawLog, "SYSLOG_IDENTIFIER").String() != "unbound" {
					t.Error("original SYSLOG_IDENTIFIER lost")
				}
			},
		},
		{
			name: "mode1: kernel firewall field parsing",
			rules: []Rule{{
				Match: []Condition{
					{Path: "rawLog.SYSLOG_IDENTIFIER", Value: "kernel"},
					{Path: "rawLog.MESSAGE.text", Op: "contains", Value: "REJECT"},
				},
				Field:   "MESSAGE.text",
				Pattern: `SRC=(?P<src_ip>\S+).*DST=(?P<dst_ip>\S+).*PROTO=(?P<proto>\S+).*SPT=(?P<src_port>\d+).*DPT=(?P<dst_port>\d+)`,
				Target:  "parsed",
			}},
			event: types.Event{
				SourceType: "journald",
				RawLog: rawJSON(t, map[string]any{
					"SYSLOG_IDENTIFIER": "kernel",
					"MESSAGE": map[string]any{
						"text": "filter_IN_FedoraServer_REJECT: IN=podman1 OUT= SRC=10.89.0.2 DST=10.89.0.1 LEN=94 PROTO=UDP SPT=60232 DPT=53 LEN=74",
					},
				}),
			},
			check: func(t *testing.T, e types.Event) {
				if gjson.GetBytes(e.RawLog, "parsed.src_ip").String() != "10.89.0.2" {
					t.Errorf("parsed.src_ip = %q", gjson.GetBytes(e.RawLog, "parsed.src_ip"))
				}
				if gjson.GetBytes(e.RawLog, "parsed.dst_ip").String() != "10.89.0.1" {
					t.Errorf("parsed.dst_ip = %q", gjson.GetBytes(e.RawLog, "parsed.dst_ip"))
				}
				if gjson.GetBytes(e.RawLog, "parsed.proto").String() != "UDP" {
					t.Errorf("parsed.proto = %q", gjson.GetBytes(e.RawLog, "parsed.proto"))
				}
				if gjson.GetBytes(e.RawLog, "parsed.src_port").String() != "60232" {
					t.Errorf("parsed.src_port = %q", gjson.GetBytes(e.RawLog, "parsed.src_port"))
				}
				if gjson.GetBytes(e.RawLog, "parsed.dst_port").String() != "53" {
					t.Errorf("parsed.dst_port = %q", gjson.GetBytes(e.RawLog, "parsed.dst_port"))
				}
			},
		},
		{
			name: "mode2: bare string conntrack parsing",
			rules: []Rule{{
				Match:   []Condition{{Path: "sourceType", Value: "command"}},
				Pattern: `\[(?P<event>\w+)\].*src=(?P<src_ip>\S+) dst=(?P<dst_ip>\S+) sport=(?P<src_port>\d+) dport=(?P<dst_port>\d+)`,
			}},
			event: types.Event{
				SourceType: "command",
				RawLog: rawJSON(
					t,
					"[1776041793.453375]\t    [NEW] ipv4     2 tcp      6 120 SYN_SENT src=10.89.0.2 dst=34.160.81.0 sport=35950 dport=443",
				),
			},
			check: func(t *testing.T, e types.Event) {
				if gjson.GetBytes(e.RawLog, "event").String() != "NEW" {
					t.Errorf("event = %q, want NEW", gjson.GetBytes(e.RawLog, "event"))
				}
				if gjson.GetBytes(e.RawLog, "src_ip").String() != "10.89.0.2" {
					t.Errorf("src_ip = %q", gjson.GetBytes(e.RawLog, "src_ip"))
				}
				if gjson.GetBytes(e.RawLog, "dst_ip").String() != "34.160.81.0" {
					t.Errorf("dst_ip = %q", gjson.GetBytes(e.RawLog, "dst_ip"))
				}
				if gjson.GetBytes(e.RawLog, "src_port").String() != "35950" {
					t.Errorf("src_port = %q", gjson.GetBytes(e.RawLog, "src_port"))
				}
				if gjson.GetBytes(e.RawLog, "_raw").Exists() {
					// _raw should contain the original text
					if !gjson.GetBytes(e.RawLog, "_raw").Exists() {
						t.Error("_raw field missing")
					}
				}
			},
		},
		{
			name: "no match passthrough",
			rules: []Rule{{
				Match:   []Condition{{Path: "rawLog.SYSLOG_IDENTIFIER", Value: "coredns"}},
				Field:   "MESSAGE.text",
				Pattern: `(?P<x>\w+)`,
			}},
			event: types.Event{
				SourceType: "journald",
				RawLog: rawJSON(t, map[string]any{
					"SYSLOG_IDENTIFIER": "sshd",
					"MESSAGE":           map[string]any{"text": "hello"},
				}),
			},
			check: func(t *testing.T, e types.Event) {
				if gjson.GetBytes(e.RawLog, "parsed").Exists() {
					t.Error("parsed field should not exist on non-matching event")
				}
			},
		},
		{
			name: "regex no match passthrough",
			rules: []Rule{{
				Match:   []Condition{{Path: "rawLog.SYSLOG_IDENTIFIER", Value: "unbound"}},
				Field:   "MESSAGE.text",
				Pattern: `WILL_NOT_MATCH_(?P<x>\d{100})`,
			}},
			event: types.Event{
				SourceType: "journald",
				RawLog: rawJSON(t, map[string]any{
					"SYSLOG_IDENTIFIER": "unbound",
					"MESSAGE":           map[string]any{"text": "some text"},
				}),
			},
			check: func(t *testing.T, e types.Event) {
				if gjson.GetBytes(e.RawLog, "parsed").Exists() {
					t.Error("parsed field should not exist when regex doesn't match")
				}
			},
		},
		{
			name: "first match wins",
			rules: []Rule{
				{
					Match:   []Condition{{Path: "rawLog.app", Value: "test"}},
					Field:   "msg",
					Pattern: `(?P<first>\w+)`,
					Target:  "a",
				},
				{
					Match:   []Condition{{Path: "rawLog.app", Op: "exists"}},
					Field:   "msg",
					Pattern: `(?P<second>\w+)`,
					Target:  "b",
				},
			},
			event: types.Event{
				SourceType: "file",
				RawLog:     rawJSON(t, map[string]any{"app": "test", "msg": "hello"}),
			},
			check: func(t *testing.T, e types.Event) {
				if !gjson.GetBytes(e.RawLog, "a.first").Exists() {
					t.Error("first rule should have matched")
				}
				if gjson.GetBytes(e.RawLog, "b.second").Exists() {
					t.Error("second rule should not have matched (first match wins)")
				}
			},
		},
		{
			name: "mode1: default target is parsed",
			rules: []Rule{{
				Match:   []Condition{{Path: "rawLog.x", Value: "y"}},
				Field:   "msg",
				Pattern: `(?P<val>\w+)`,
				// Target omitted — should default to "parsed"
			}},
			event: types.Event{
				SourceType: "test",
				RawLog:     rawJSON(t, map[string]any{"x": "y", "msg": "hello"}),
			},
			check: func(t *testing.T, e types.Event) {
				if gjson.GetBytes(e.RawLog, "parsed.val").String() != "hello" {
					t.Errorf("parsed.val = %q, want hello", gjson.GetBytes(e.RawLog, "parsed.val"))
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rp, err := New(&fakeSource{events: []types.Event{tt.event}}, tt.rules)
			if err != nil {
				t.Fatal(err)
			}
			e := recv(t, rp)
			tt.check(t, e)
		})
	}
}

func TestNewValidation(t *testing.T) {
	t.Run("empty pattern", func(t *testing.T) {
		_, err := New(nil, []Rule{{
			Match: []Condition{{Path: "rawLog.x", Value: "y"}},
		}})
		if err == nil {
			t.Error("expected error for empty pattern")
		}
	})

	t.Run("invalid regex", func(t *testing.T) {
		_, err := New(nil, []Rule{{
			Match:   []Condition{{Path: "rawLog.x", Value: "y"}},
			Pattern: `(?P<broken`,
		}})
		if err == nil {
			t.Error("expected error for invalid regex")
		}
	})

	t.Run("no named groups", func(t *testing.T) {
		_, err := New(nil, []Rule{{
			Match:   []Condition{{Path: "rawLog.x", Value: "y"}},
			Pattern: `\w+`,
		}})
		if err == nil {
			t.Error("expected error for pattern without named groups")
		}
	})

	t.Run("no match conditions", func(t *testing.T) {
		_, err := New(nil, []Rule{{
			Pattern: `(?P<x>\w+)`,
		}})
		if err == nil {
			t.Error("expected error for rule with no match conditions")
		}
	})
}
