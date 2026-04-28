package refiner_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/runreveal/kawa"
	"github.com/runreveal/lib/loader"
	"github.com/runreveal/reveald/internal/sources/refiner"
	"github.com/runreveal/reveald/internal/types"
)

// testSource is a simple source that yields fixed events, registered as "test".
type testSource struct {
	events []types.Event
	idx    int
}

func (s *testSource) Run(ctx context.Context) error {
	<-ctx.Done()
	return ctx.Err()
}

func (s *testSource) Recv(ctx context.Context) (kawa.Message[types.Event], func(), error) {
	if s.idx >= len(s.events) {
		<-ctx.Done()
		return kawa.Message[types.Event]{}, nil, ctx.Err()
	}
	e := s.events[s.idx]
	s.idx++
	return kawa.Message[types.Event]{Value: e}, func() {}, nil
}

// testSourceConfig is a loader.Builder that creates a testSource.
type testSourceConfig struct {
	Events []json.RawMessage `json:"events"`
}

func (c *testSourceConfig) Configure() (kawa.Source[types.Event], error) {
	events := make([]types.Event, len(c.Events))
	for i, raw := range c.Events {
		events[i] = types.Event{
			SourceType: "test",
			RawLog:     raw,
		}
	}
	return &testSource{events: events}, nil
}

func init() {
	loader.Register("test", func() loader.Builder[kawa.Source[types.Event]] {
		return &testSourceConfig{}
	})
	loader.Register("refine", func() loader.Builder[kawa.Source[types.Event]] {
		return &refiner.Config{}
	})
}

func TestConfigUnmarshalAndPipeline(t *testing.T) {
	configJSON := `{
		"type": "refine",
		"source": {
			"type": "test",
			"events": [
				{"SYSLOG_IDENTIFIER": "coredns", "MESSAGE": "query from 10.0.0.1"},
				{"SYSLOG_IDENTIFIER": "sshd", "MESSAGE": "login attempt"},
				{"SYSLOG_IDENTIFIER": "coredns", "MESSAGE": "query from 10.0.0.2"}
			]
		},
		"rules": [
			{
				"match": [{"path": "rawLog.SYSLOG_IDENTIFIER", "value": "coredns"}],
				"extract": [
					{"to": "sourceType", "from": "rawLog.SYSLOG_IDENTIFIER"},
					{"to": "service.name", "from": "rawLog.SYSLOG_IDENTIFIER"},
					{"to": "eventName", "from": "rawLog.MESSAGE"}
				]
			}
		]
	}`

	var l loader.Loader[kawa.Source[types.Event]]
	if err := json.Unmarshal([]byte(configJSON), &l); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	src, err := l.Configure()
	if err != nil {
		t.Fatalf("configure: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Event 1: coredns — should be refined
	msg1, _, err := src.Recv(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if msg1.Value.SourceType != "coredns" {
		t.Errorf("event 1: sourceType = %q, want coredns", msg1.Value.SourceType)
	}
	if msg1.Value.Service.Name != "coredns" {
		t.Errorf("event 1: service.name = %q, want coredns", msg1.Value.Service.Name)
	}
	if msg1.Value.EventName != "query from 10.0.0.1" {
		t.Errorf("event 1: eventName = %q", msg1.Value.EventName)
	}

	// Event 2: sshd — no match, should pass through as "test"
	msg2, _, err := src.Recv(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if msg2.Value.SourceType != "test" {
		t.Errorf("event 2: sourceType = %q, want test", msg2.Value.SourceType)
	}
	if msg2.Value.Service.Name != "" {
		t.Errorf("event 2: service.name = %q, want empty", msg2.Value.Service.Name)
	}

	// Event 3: coredns again — should be refined
	msg3, _, err := src.Recv(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if msg3.Value.SourceType != "coredns" {
		t.Errorf("event 3: sourceType = %q, want coredns", msg3.Value.SourceType)
	}
}

func TestConfigMissingSource(t *testing.T) {
	configJSON := `{
		"type": "refine",
		"rules": [{"match": [{"path": "rawLog.x", "value": "y"}]}]
	}`

	var l loader.Loader[kawa.Source[types.Event]]
	// Unmarshal may fail since source is missing the "type" field,
	// or Configure should fail.
	err := json.Unmarshal([]byte(configJSON), &l)
	if err != nil {
		return // acceptable: loader rejects missing inner type at unmarshal
	}
	_, err = l.Configure()
	if err == nil {
		t.Error("expected error when source is missing")
	}
}

func TestConfigNestedSourceType(t *testing.T) {
	// Verify the inner source type is correctly resolved.
	configJSON := `{
		"type": "refine",
		"source": {
			"type": "test",
			"events": [{"app": "hello"}]
		},
		"rules": [
			{
				"match": [{"path": "rawLog.app", "op": "exists"}],
				"extract": [
					{"to": "tags.app", "from": "rawLog.app"}
				]
			}
		]
	}`

	var l loader.Loader[kawa.Source[types.Event]]
	if err := json.Unmarshal([]byte(configJSON), &l); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	src, err := l.Configure()
	if err != nil {
		t.Fatalf("configure: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	msg, _, err := src.Recv(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if msg.Value.Tags["app"] != "hello" {
		t.Errorf("tags.app = %q, want hello", msg.Value.Tags["app"])
	}
}
