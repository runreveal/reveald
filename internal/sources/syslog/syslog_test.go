package syslog

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"testing"
	"time"
)

func TestSyslogJSONContent(t *testing.T) {
	tests := []struct {
		name            string
		syslogMessage   string
		expectedContent string
	}{
		{
			name:            "simple JSON object",
			syslogMessage:   `<34>Oct 11 22:14:15 mymachine su: {"key":"value","number":123}`,
			expectedContent: `{"key":"value","number":123}`,
		},
		{
			name:            "JSON array",
			syslogMessage:   `<34>Oct 11 22:14:15 mymachine app: ["item1","item2","item3"]`,
			expectedContent: `["item1","item2","item3"]`,
		},
		{
			name:            "nested JSON object",
			syslogMessage:   `<34>Oct 11 22:14:15 mymachine app: {"outer":{"inner":"value"},"array":[1,2,3]}`,
			expectedContent: `{"outer":{"inner":"value"},"array":[1,2,3]}`,
		},
		{
			name:            "JSON with spaces",
			syslogMessage:   `<34>Oct 11 22:14:15 mymachine app: {"message": "hello world", "status": "ok"}`,
			expectedContent: `{"message": "hello world", "status": "ok"}`,
		},
		{
			name:            "JSON with special characters",
			syslogMessage:   `<34>Oct 11 22:14:15 mymachine app: {"unicode":"Hello\u0021","escaped":"quote\"here"}`,
			expectedContent: `{"unicode":"Hello\u0021","escaped":"quote\"here"}`,
		},
		{
			name:            "complex nested JSON",
			syslogMessage:   `<34>Oct 11 22:14:15 mymachine app: {"timestamp":"2024-01-01T00:00:00Z","level":"info","data":{"user":"test","action":"login"},"tags":["auth","security"]}`,
			expectedContent: `{"timestamp":"2024-01-01T00:00:00Z","level":"info","data":{"user":"test","action":"login"},"tags":["auth","security"]}`,
		},
		{
			name:            "plain text message",
			syslogMessage:   `<34>Oct 11 22:14:15 mymachine app: This is a plain text message`,
			expectedContent: `This is a plain text message`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Find an available port
			listener, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("failed to find available port: %v", err)
			}
			addr := listener.LocalAddr().String()
			listener.Close()

			// Create syslog source with the available address
			cfg := SyslogCfg{
				Addr:        addr,
				ContentType: "json",
			}
			source := NewSyslogSource(cfg)

			// Start the source in a goroutine
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			errC := make(chan error, 1)
			go func() {
				errC <- source.Run(ctx)
			}()

			// Give the server time to start
			time.Sleep(100 * time.Millisecond)

			// Send syslog message via UDP
			conn, err := net.Dial("udp", addr)
			if err != nil {
				t.Fatalf("failed to dial UDP: %v", err)
			}
			defer conn.Close()

			_, err = conn.Write([]byte(tt.syslogMessage + "\n"))
			if err != nil {
				t.Fatalf("failed to write to UDP: %v", err)
			}

			// Give time for message to be processed
			time.Sleep(50 * time.Millisecond)

			// Receive the message
			recvCtx, recvCancel := context.WithTimeout(context.Background(), 1*time.Second)
			defer recvCancel()

			msg, _, err := source.Recv(recvCtx)
			if err != nil {
				t.Fatalf("failed to receive message: %v", err)
			}

			// Verify the content
			gotContent := string(msg.Value.RawLog)
			if gotContent != tt.expectedContent {
				t.Errorf("content mismatch:\nexpected: %q\ngot:      %q", tt.expectedContent, gotContent)
			}

			// Verify source type
			if msg.Value.SourceType != "syslog" {
				t.Errorf("expected source type 'syslog', got %q", msg.Value.SourceType)
			}

			// Verify timestamp is set
			if msg.Value.EventTime.IsZero() {
				t.Error("event time should not be zero")
			}

			// For JSON content, verify it's valid JSON
			if tt.expectedContent[0] == '{' || tt.expectedContent[0] == '[' {
				var jsonData any
				if err := json.Unmarshal([]byte(gotContent), &jsonData); err != nil {
					t.Errorf("content is not valid JSON: %v", err)
				}
			}

			cancel()
		})
	}
}

func TestSyslogMultipleMessages(t *testing.T) {
	// Find an available port
	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to find available port: %v", err)
	}
	addr := listener.LocalAddr().String()
	listener.Close()

	cfg := SyslogCfg{
		Addr:        addr,
		ContentType: "json",
	}
	source := NewSyslogSource(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	errC := make(chan error, 1)
	go func() {
		errC <- source.Run(ctx)
	}()

	time.Sleep(100 * time.Millisecond)

	conn, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatalf("failed to dial UDP: %v", err)
	}
	defer conn.Close()

	// Send multiple JSON messages
	messages := []string{
		`<34>Oct 11 22:14:15 mymachine app1: {"id":1,"msg":"first"}`,
		`<34>Oct 11 22:14:16 mymachine app2: {"id":2,"msg":"second"}`,
		`<34>Oct 11 22:14:17 mymachine app3: {"id":3,"msg":"third"}`,
	}

	expectedContents := []string{
		`{"id":1,"msg":"first"}`,
		`{"id":2,"msg":"second"}`,
		`{"id":3,"msg":"third"}`,
	}

	for _, msg := range messages {
		_, err = conn.Write([]byte(msg + "\n"))
		if err != nil {
			t.Fatalf("failed to write message: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}

	// Receive and verify all messages
	for i, expected := range expectedContents {
		recvCtx, recvCancel := context.WithTimeout(context.Background(), 1*time.Second)
		msg, _, err := source.Recv(recvCtx)
		recvCancel()

		if err != nil {
			t.Fatalf("failed to receive message %d: %v", i+1, err)
		}

		got := string(msg.Value.RawLog)
		if got != expected {
			t.Errorf("message %d mismatch:\nexpected: %q\ngot:      %q", i+1, expected, got)
		}

		// Verify it's valid JSON
		var jsonData any
		if err := json.Unmarshal([]byte(got), &jsonData); err != nil {
			t.Errorf("message %d is not valid JSON: %v", i+1, err)
		}
	}
}

func TestSyslogContextCancellation(t *testing.T) {
	cfg := SyslogCfg{
		Addr:        "127.0.0.1:0",
		ContentType: "json",
	}
	source := NewSyslogSource(cfg)

	ctx, cancel := context.WithCancel(context.Background())

	errC := make(chan error, 1)
	go func() {
		errC <- source.Run(ctx)
	}()

	time.Sleep(100 * time.Millisecond)

	// Cancel context
	cancel()

	// Verify Run exits
	select {
	case err := <-errC:
		if err != nil && err != context.Canceled {
			t.Errorf("expected nil or context.Canceled error, got: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Error("Run did not exit after context cancellation")
	}

	// Verify Recv respects cancelled context
	cancelledCtx, cancelRecv := context.WithCancel(context.Background())
	cancelRecv()

	_, _, err := source.Recv(cancelledCtx)
	if err == nil {
		t.Error("expected error from Recv with cancelled context")
	}
	if err != context.Canceled {
		t.Errorf("expected context.Canceled, got: %v", err)
	}
}

func TestSyslogLargeJSONPayload(t *testing.T) {
	// Find an available port
	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to find available port: %v", err)
	}
	addr := listener.LocalAddr().String()
	listener.Close()

	cfg := SyslogCfg{
		Addr:        addr,
		ContentType: "json",
	}
	source := NewSyslogSource(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	errC := make(chan error, 1)
	go func() {
		errC <- source.Run(ctx)
	}()

	time.Sleep(100 * time.Millisecond)

	// Create a large JSON object
	largeJSON := map[string]any{
		"timestamp": "2024-01-01T00:00:00Z",
		"level":     "info",
		"data":      make(map[string]string),
	}
	dataMap := largeJSON["data"].(map[string]string)
	for i := 0; i < 100; i++ {
		dataMap[fmt.Sprintf("key%d", i)] = fmt.Sprintf("value%d", i)
	}

	jsonBytes, err := json.Marshal(largeJSON)
	if err != nil {
		t.Fatalf("failed to marshal JSON: %v", err)
	}

	syslogMsg := fmt.Sprintf("<34>Oct 11 22:14:15 mymachine app: %s", string(jsonBytes))

	conn, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatalf("failed to dial UDP: %v", err)
	}
	defer conn.Close()

	_, err = conn.Write([]byte(syslogMsg + "\n"))
	if err != nil {
		t.Fatalf("failed to write to UDP: %v", err)
	}

	time.Sleep(50 * time.Millisecond)

	recvCtx, recvCancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer recvCancel()

	msg, _, err := source.Recv(recvCtx)
	if err != nil {
		t.Fatalf("failed to receive message: %v", err)
	}

	// Verify it's valid JSON
	var receivedJSON map[string]any
	if err := json.Unmarshal(msg.Value.RawLog, &receivedJSON); err != nil {
		t.Fatalf("received content is not valid JSON: %v", err)
	}

	// Verify structure
	if receivedJSON["timestamp"] != "2024-01-01T00:00:00Z" {
		t.Errorf("unexpected timestamp in received JSON")
	}

	receivedData, ok := receivedJSON["data"].(map[string]any)
	if !ok {
		t.Fatal("data field is not a map")
	}

	if len(receivedData) != 100 {
		t.Errorf("expected 100 data entries, got %d", len(receivedData))
	}
}
