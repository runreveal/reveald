package journald

import (
	"encoding/json"
	"testing"
)

func TestUnescapeMessage(t *testing.T) {
	tests := []struct {
		name           string
		input          string
		unescapeJSON   bool
		expectModified bool
		checkMessage   func(t *testing.T, result map[string]any)
	}{
		{
			name: "simple escaped JSON object",
			input: `{
				"MESSAGE": "{\"key\":\"value\",\"number\":123}",
				"__REALTIME_TIMESTAMP": "1234567890",
				"__CURSOR": "cursor123"
			}`,
			unescapeJSON:   true,
			expectModified: true,
			checkMessage: func(t *testing.T, result map[string]any) {
				msg, ok := result["MESSAGE"].(map[string]any)
				if !ok {
					t.Fatalf("MESSAGE should be an object, got %T", result["MESSAGE"])
				}
				if msg["key"] != "value" {
					t.Errorf("expected key=value, got %v", msg["key"])
				}
				if msg["number"] != float64(123) {
					t.Errorf("expected number=123, got %v", msg["number"])
				}
			},
		},
		{
			name: "nested escaped JSON",
			input: `{
				"MESSAGE": "{\"outer\":\"{\\\"inner\\\":\\\"value\\\"}\"}",
				"__REALTIME_TIMESTAMP": "1234567890",
				"__CURSOR": "cursor123"
			}`,
			unescapeJSON:   true,
			expectModified: true,
			checkMessage: func(t *testing.T, result map[string]any) {
				msg, ok := result["MESSAGE"].(map[string]any)
				if !ok {
					t.Fatalf("MESSAGE should be an object, got %T", result["MESSAGE"])
				}
				// The outer level is unescaped, inner stays as escaped string
				if _, ok := msg["outer"].(string); !ok {
					t.Errorf("expected outer to be a string, got %T", msg["outer"])
				}
			},
		},
		{
			name: "escaped JSON array",
			input: `{
				"MESSAGE": "[\"item1\",\"item2\",123]",
				"__REALTIME_TIMESTAMP": "1234567890",
				"__CURSOR": "cursor123"
			}`,
			unescapeJSON:   true,
			expectModified: true,
			checkMessage: func(t *testing.T, result map[string]any) {
				msg, ok := result["MESSAGE"].([]any)
				if !ok {
					t.Fatalf("MESSAGE should be an array, got %T", result["MESSAGE"])
				}
				if len(msg) != 3 {
					t.Errorf("expected 3 items, got %d", len(msg))
				}
				if msg[0] != "item1" {
					t.Errorf("expected item1, got %v", msg[0])
				}
			},
		},
		{
			name: "plain text message",
			input: `{
				"MESSAGE": "This is just a plain text message",
				"__REALTIME_TIMESTAMP": "1234567890",
				"__CURSOR": "cursor123"
			}`,
			unescapeJSON:   true,
			expectModified: false,
			checkMessage: func(t *testing.T, result map[string]any) {
				msg, ok := result["MESSAGE"].(string)
				if !ok {
					t.Fatalf("MESSAGE should be a string, got %T", result["MESSAGE"])
				}
				if msg != "This is just a plain text message" {
					t.Errorf("message content changed unexpectedly")
				}
			},
		},
		{
			name: "invalid JSON in MESSAGE",
			input: `{
				"MESSAGE": "{invalid json",
				"__REALTIME_TIMESTAMP": "1234567890",
				"__CURSOR": "cursor123"
			}`,
			unescapeJSON:   true,
			expectModified: false,
			checkMessage: func(t *testing.T, result map[string]any) {
				msg, ok := result["MESSAGE"].(string)
				if !ok {
					t.Fatalf("MESSAGE should remain a string, got %T", result["MESSAGE"])
				}
				if msg != "{invalid json" {
					t.Errorf("message content changed unexpectedly")
				}
			},
		},
		{
			name: "already unescaped JSON object",
			input: `{
				"MESSAGE": {"already":"unescaped","works":true},
				"__REALTIME_TIMESTAMP": "1234567890",
				"__CURSOR": "cursor123"
			}`,
			unescapeJSON:   true,
			expectModified: false,
			checkMessage: func(t *testing.T, result map[string]any) {
				msg, ok := result["MESSAGE"].(map[string]any)
				if !ok {
					t.Fatalf("MESSAGE should be an object, got %T", result["MESSAGE"])
				}
				if msg["already"] != "unescaped" {
					t.Errorf("expected already=unescaped, got %v", msg["already"])
				}
			},
		},
		{
			name: "empty MESSAGE",
			input: `{
				"MESSAGE": "",
				"__REALTIME_TIMESTAMP": "1234567890",
				"__CURSOR": "cursor123"
			}`,
			unescapeJSON:   true,
			expectModified: false,
			checkMessage: func(t *testing.T, result map[string]any) {
				if msg, ok := result["MESSAGE"].(string); !ok || msg != "" {
					t.Errorf("MESSAGE should be empty string, got %v", result["MESSAGE"])
				}
			},
		},
		{
			name: "MESSAGE with special characters",
			input: `{
				"MESSAGE": "{\"unicode\":\"\\u0048\\u0065\\u006c\\u006c\\u006f\"}",
				"__REALTIME_TIMESTAMP": "1234567890",
				"__CURSOR": "cursor123"
			}`,
			unescapeJSON:   true,
			expectModified: true,
			checkMessage: func(t *testing.T, result map[string]any) {
				msg, ok := result["MESSAGE"].(map[string]any)
				if !ok {
					t.Fatalf("MESSAGE should be an object, got %T", result["MESSAGE"])
				}
				if msg["unicode"] != "Hello" {
					t.Errorf("expected unicode=Hello, got %v", msg["unicode"])
				}
			},
		},
		{
			name: "feature disabled",
			input: `{
				"MESSAGE": "{\"key\":\"value\"}",
				"__REALTIME_TIMESTAMP": "1234567890",
				"__CURSOR": "cursor123"
			}`,
			unescapeJSON:   false,
			expectModified: false,
			checkMessage: func(t *testing.T, result map[string]any) {
				msg, ok := result["MESSAGE"].(string)
				if !ok {
					t.Fatalf("MESSAGE should remain a string when feature is disabled, got %T", result["MESSAGE"])
				}
				if msg != `{"key":"value"}` {
					t.Errorf("message content changed when feature was disabled")
				}
			},
		},
		{
			name: "preserves other journald fields",
			input: `{
				"MESSAGE": "{\"key\":\"value\"}",
				"__REALTIME_TIMESTAMP": "1234567890",
				"__CURSOR": "cursor123",
				"_HOSTNAME": "testhost",
				"SYSLOG_IDENTIFIER": "test",
				"CUSTOM_FIELD": "should remain"
			}`,
			unescapeJSON:   true,
			expectModified: true,
			checkMessage: func(t *testing.T, result map[string]any) {
				if result["__REALTIME_TIMESTAMP"] != "1234567890" {
					t.Errorf("timestamp was modified")
				}
				if result["__CURSOR"] != "cursor123" {
					t.Errorf("cursor was modified")
				}
				if result["_HOSTNAME"] != "testhost" {
					t.Errorf("hostname was modified")
				}
				if result["SYSLOG_IDENTIFIER"] != "test" {
					t.Errorf("syslog identifier was modified")
				}
				if result["CUSTOM_FIELD"] != "should remain" {
					t.Errorf("custom field was modified")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create Journald instance with the test configuration
			j := New(WithUnescapeMessageJSON(tt.unescapeJSON))

			// Parse the input JSON
			var inputData map[string]any
			if err := json.Unmarshal([]byte(tt.input), &inputData); err != nil {
				t.Fatalf("failed to parse test input: %v", err)
			}

			// Extract MESSAGE field and convert to journalMsg
			var message journalMsg
			if msgStr, ok := inputData["MESSAGE"].(string); ok {
				message = journalMsg(msgStr)
			} else if msgObj, ok := inputData["MESSAGE"]; ok {
				// Already an object, marshal it back to bytes
				msgBytes, err := json.Marshal(msgObj)
				if err != nil {
					t.Fatalf("failed to marshal MESSAGE object: %v", err)
				}
				message = journalMsg(msgBytes)
			}

			// Test the unescapeMessage function
			inputBytes := []byte(tt.input)
			var resultBytes []byte
			if j.unescapeMessageJSON {
				resultBytes = j.unescapeMessage(inputBytes, message)
			} else {
				resultBytes = inputBytes
			}

			// Check if bytes were modified as expected
			wasModified := string(inputBytes) != string(resultBytes)
			if wasModified != tt.expectModified {
				t.Errorf("expected modified=%v, got modified=%v", tt.expectModified, wasModified)
			}

			// Parse result and run custom checks
			var result map[string]any
			if err := json.Unmarshal(resultBytes, &result); err != nil {
				t.Fatalf("failed to parse result: %v", err)
			}

			tt.checkMessage(t, result)
		})
	}
}

func TestJournalMsgUnmarshal(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "string MESSAGE",
			input:    `"hello world"`,
			expected: "hello world",
		},
		{
			name:     "byte array MESSAGE",
			input:    `[104, 101, 108, 108, 111]`,
			expected: "hello",
		},
		{
			name:     "escaped string MESSAGE",
			input:    `"hello\nworld"`,
			expected: "hello\nworld",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var msg journalMsg
			if err := json.Unmarshal([]byte(tt.input), &msg); err != nil {
				t.Fatalf("failed to unmarshal: %v", err)
			}
			if string(msg) != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, string(msg))
			}
		})
	}
}
