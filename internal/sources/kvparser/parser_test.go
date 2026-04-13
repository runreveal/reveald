package kvparser

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

func (f *fakeSource) Recv(
	ctx context.Context,
) (kawa.Message[types.Event], func(), error) {
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

func recv(t *testing.T, kp *KVParser) types.Event {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	msg, _, err := kp.Recv(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return msg.Value
}

func TestKVParser(t *testing.T) {
	tests := []struct {
		name  string
		rules []Rule
		event types.Event
		check func(t *testing.T, e types.Event)
	}{
		{
			name: "bare mode: kernel firewall log",
			rules: []Rule{{
				Match: []Condition{
					{Path: "sourceType", Value: "syslog"},
				},
			}},
			event: types.Event{
				SourceType: "syslog",
				RawLog: rawJSON(
					t,
					"REJECT IN=eth0 OUT= SRC=10.89.0.2 DST=10.89.0.1 PROTO=UDP SPT=60232 DPT=53",
				),
			},
			check: func(t *testing.T, e types.Event) {
				get := func(key string) string {
					return gjson.GetBytes(e.RawLog, key).String()
				}
				if get("_prefix") != "REJECT" {
					t.Errorf("_prefix = %q, want REJECT", get("_prefix"))
				}
				if get("IN") != "eth0" {
					t.Errorf("IN = %q, want eth0", get("IN"))
				}
				if get("OUT") != "" {
					t.Errorf("OUT = %q, want empty", get("OUT"))
				}
				if get("SRC") != "10.89.0.2" {
					t.Errorf("SRC = %q", get("SRC"))
				}
				if get("DST") != "10.89.0.1" {
					t.Errorf("DST = %q", get("DST"))
				}
				if get("PROTO") != "UDP" {
					t.Errorf("PROTO = %q", get("PROTO"))
				}
				if get("SPT") != "60232" {
					t.Errorf("SPT = %q", get("SPT"))
				}
				if get("DPT") != "53" {
					t.Errorf("DPT = %q", get("DPT"))
				}
				if !gjson.GetBytes(e.RawLog, "_raw").Exists() {
					t.Error("_raw should be present")
				}
			},
		},
		{
			name: "bare mode: logfmt with quoted values",
			rules: []Rule{{
				Match: []Condition{
					{Path: "sourceType", Value: "app"},
				},
			}},
			event: types.Event{
				SourceType: "app",
				RawLog: rawJSON(
					t,
					`level=info msg="request completed" method=GET path=/api/v1 status=200 duration=0.042`,
				),
			},
			check: func(t *testing.T, e types.Event) {
				get := func(key string) string {
					return gjson.GetBytes(e.RawLog, key).String()
				}
				if get("level") != "info" {
					t.Errorf("level = %q", get("level"))
				}
				if get("msg") != "request completed" {
					t.Errorf(
						"msg = %q, want 'request completed'",
						get("msg"),
					)
				}
				if get("method") != "GET" {
					t.Errorf("method = %q", get("method"))
				}
				if get("path") != "/api/v1" {
					t.Errorf("path = %q", get("path"))
				}
				if get("status") != "200" {
					t.Errorf("status = %q", get("status"))
				}
				if get("duration") != "0.042" {
					t.Errorf("duration = %q", get("duration"))
				}
			},
		},
		{
			name: "field mode: parse nested field in JSON rawLog",
			rules: []Rule{{
				Match: []Condition{
					{Path: "rawLog.SYSLOG_IDENTIFIER", Value: "kernel"},
				},
				Field:  "MESSAGE.text",
				Target: "parsed",
			}},
			event: types.Event{
				SourceType: "journald",
				RawLog: rawJSON(t, map[string]any{
					"SYSLOG_IDENTIFIER": "kernel",
					"MESSAGE": map[string]any{
						"text": "IN=eth0 OUT= SRC=192.168.1.1 DST=10.0.0.1 PROTO=TCP SPT=443 DPT=80",
					},
				}),
			},
			check: func(t *testing.T, e types.Event) {
				get := func(key string) string {
					return gjson.GetBytes(e.RawLog, key).String()
				}
				if get("parsed.SRC") != "192.168.1.1" {
					t.Errorf("parsed.SRC = %q", get("parsed.SRC"))
				}
				if get("parsed.DST") != "10.0.0.1" {
					t.Errorf("parsed.DST = %q", get("parsed.DST"))
				}
				if get("parsed.PROTO") != "TCP" {
					t.Errorf("parsed.PROTO = %q", get("parsed.PROTO"))
				}
				// Original fields preserved
				if get("SYSLOG_IDENTIFIER") != "kernel" {
					t.Error("original field lost")
				}
			},
		},
		{
			name: "no match passthrough",
			rules: []Rule{{
				Match: []Condition{
					{Path: "sourceType", Value: "syslog"},
				},
			}},
			event: types.Event{
				SourceType: "journald",
				RawLog:     rawJSON(t, "SRC=1.2.3.4"),
			},
			check: func(t *testing.T, e types.Event) {
				// Should be unchanged — still a bare string
				var s string
				if err := json.Unmarshal(e.RawLog, &s); err != nil {
					t.Errorf(
						"rawLog should still be a JSON string, got: %s",
						e.RawLog,
					)
				}
			},
		},
		{
			name: "no kv pairs passthrough",
			rules: []Rule{{
				Match: []Condition{
					{Path: "sourceType", Value: "syslog"},
				},
			}},
			event: types.Event{
				SourceType: "syslog",
				RawLog:     rawJSON(t, "just plain text with no equals"),
			},
			check: func(t *testing.T, e types.Event) {
				var s string
				if err := json.Unmarshal(e.RawLog, &s); err != nil {
					t.Errorf(
						"rawLog should still be a JSON string, got: %s",
						e.RawLog,
					)
				}
			},
		},
		{
			name: "first match wins",
			rules: []Rule{
				{
					Match:  []Condition{{Path: "sourceType", Value: "syslog"}},
					Target: "a",
					Field:  "msg",
				},
				{
					Match:  []Condition{{Path: "sourceType", Op: "exists"}},
					Target: "b",
					Field:  "msg",
				},
			},
			event: types.Event{
				SourceType: "syslog",
				RawLog: rawJSON(t, map[string]any{
					"msg": "key=val",
				}),
			},
			check: func(t *testing.T, e types.Event) {
				if !gjson.GetBytes(e.RawLog, "a.key").Exists() {
					t.Error("first rule should have matched")
				}
				if gjson.GetBytes(e.RawLog, "b.key").Exists() {
					t.Error(
						"second rule should not have matched",
					)
				}
			},
		},
		{
			name: "custom kvSep",
			rules: []Rule{{
				Match: []Condition{{Path: "sourceType", Value: "app"}},
				KVSep: ":",
			}},
			event: types.Event{
				SourceType: "app",
				RawLog:     rawJSON(t, "host:localhost port:8080 status:ok"),
			},
			check: func(t *testing.T, e types.Event) {
				get := func(key string) string {
					return gjson.GetBytes(e.RawLog, key).String()
				}
				if get("host") != "localhost" {
					t.Errorf("host = %q", get("host"))
				}
				if get("port") != "8080" {
					t.Errorf("port = %q", get("port"))
				}
				if get("status") != "ok" {
					t.Errorf("status = %q", get("status"))
				}
			},
		},
		{
			name: "non-JSON rawLog passthrough",
			rules: []Rule{{
				Match: []Condition{
					{Path: "sourceType", Value: "syslog"},
				},
			}},
			event: types.Event{
				SourceType: "syslog",
				RawLog:     json.RawMessage(`not valid json`),
			},
			check: func(t *testing.T, e types.Event) {
				if string(e.RawLog) != "not valid json" {
					t.Errorf(
						"rawLog should be unchanged, got: %s",
						e.RawLog,
					)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kp, err := New(
				&fakeSource{events: []types.Event{tt.event}},
				tt.rules,
			)
			if err != nil {
				t.Fatal(err)
			}
			e := recv(t, kp)
			tt.check(t, e)
		})
	}
}

func TestParseKV(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		sep    string
		expect map[string]string
	}{
		{
			name:  "simple kv",
			input: "key=value foo=bar",
			sep:   "=",
			expect: map[string]string{
				"key": "value",
				"foo": "bar",
			},
		},
		{
			name:  "with prefix",
			input: "REJECT IN=eth0 OUT= SRC=1.2.3.4",
			sep:   "=",
			expect: map[string]string{
				"_prefix": "REJECT",
				"IN":      "eth0",
				"OUT":     "",
				"SRC":     "1.2.3.4",
			},
		},
		{
			name:  "quoted values",
			input: `level=info msg="hello world" dur=0.1`,
			sep:   "=",
			expect: map[string]string{
				"level": "info",
				"msg":   "hello world",
				"dur":   "0.1",
			},
		},
		{
			name:  "escaped quote in value",
			input: `key="value with \"quotes\""`,
			sep:   "=",
			expect: map[string]string{
				"key": `value with "quotes"`,
			},
		},
		{
			name:   "empty input",
			input:  "",
			sep:    "=",
			expect: nil,
		},
		{
			name:   "no separator",
			input:  "just plain text",
			sep:    "=",
			expect: nil,
		},
		{
			name:  "colon separator",
			input: "host:localhost port:8080",
			sep:   ":",
			expect: map[string]string{
				"host": "localhost",
				"port": "8080",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseKV(tt.input, tt.sep)
			if tt.expect == nil {
				if got != nil {
					t.Errorf("expected nil, got %v", got)
				}
				return
			}
			for k, want := range tt.expect {
				if got[k] != want {
					t.Errorf(
						"%s: got %q, want %q",
						k, got[k], want,
					)
				}
			}
			// Check no unexpected keys (except _raw which is added
			// by bare mode, not by parseKV directly)
			for k := range got {
				if _, ok := tt.expect[k]; !ok {
					t.Errorf("unexpected key %q = %q", k, got[k])
				}
			}
		})
	}
}

func TestNewValidation(t *testing.T) {
	_, err := New(nil, []Rule{{Match: nil}})
	if err == nil {
		t.Error("expected error for rule with no match conditions")
	}
}
