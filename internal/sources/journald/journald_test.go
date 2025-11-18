package journald

import (
	"encoding/json"
	"testing"
)

func TestUnescapeMessage(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		unescapeJSON bool
		expected     string
	}{
		{
			name: "simple escaped JSON object",
			input: `{
				"MESSAGE": "{\"key\":\"value\",\"number\":123}",
				"__REALTIME_TIMESTAMP": "1234567890",
				"__CURSOR": "cursor123"
			}`,
			unescapeJSON: true,
			expected: `{
				"MESSAGE": {"key":"value","number":123},
				"_MESSAGE_IS_JSON": true,
				"__REALTIME_TIMESTAMP": "1234567890",
				"__CURSOR": "cursor123"
			}`,
		},
		{
			name: "nested escaped JSON",
			input: `{
				"MESSAGE": "{\"outer\":\"{\\\"inner\\\":\\\"value\\\"}\"}",
				"__REALTIME_TIMESTAMP": "1234567890",
				"__CURSOR": "cursor123"
			}`,
			unescapeJSON: true,
			expected: `{
				"MESSAGE": {"outer":"{\"inner\":\"value\"}"},
				"_MESSAGE_IS_JSON": true,
				"__REALTIME_TIMESTAMP": "1234567890",
				"__CURSOR": "cursor123"
			}`,
		},
		{
			name: "escaped JSON array",
			input: `{
				"MESSAGE": "[\"item1\",\"item2\",123]",
				"__REALTIME_TIMESTAMP": "1234567890",
				"__CURSOR": "cursor123"
			}`,
			unescapeJSON: true,
			expected: `{
				"MESSAGE": ["item1","item2",123],
				"_MESSAGE_IS_JSON": true,
				"__REALTIME_TIMESTAMP": "1234567890",
				"__CURSOR": "cursor123"
			}`,
		},
		{
			name: "plain text message",
			input: `{
				"MESSAGE": "This is just a plain text message",
				"__REALTIME_TIMESTAMP": "1234567890",
				"__CURSOR": "cursor123"
			}`,
			unescapeJSON: true,
			expected: `{
				"MESSAGE": "This is just a plain text message",
				"__REALTIME_TIMESTAMP": "1234567890",
				"__CURSOR": "cursor123"
			}`,
		},
		{
			name: "invalid JSON in MESSAGE",
			input: `{
				"MESSAGE": "{invalid json",
				"__REALTIME_TIMESTAMP": "1234567890",
				"__CURSOR": "cursor123"
			}`,
			unescapeJSON: true,
			expected: `{
				"MESSAGE": "{invalid json",
				"__REALTIME_TIMESTAMP": "1234567890",
				"__CURSOR": "cursor123"
			}`,
		},
		{
			name: "already unescaped JSON object",
			input: `{
				"MESSAGE": {"already":"unescaped","works":true},
				"__REALTIME_TIMESTAMP": "1234567890",
				"__CURSOR": "cursor123"
			}`,
			unescapeJSON: true,
			expected: `{
				"MESSAGE": {"already":"unescaped","works":true},
				"__REALTIME_TIMESTAMP": "1234567890",
				"__CURSOR": "cursor123"
			}`,
		},
		{
			name: "empty MESSAGE",
			input: `{
				"MESSAGE": "",
				"__REALTIME_TIMESTAMP": "1234567890",
				"__CURSOR": "cursor123"
			}`,
			unescapeJSON: true,
			expected: `{
				"MESSAGE": "",
				"__REALTIME_TIMESTAMP": "1234567890",
				"__CURSOR": "cursor123"
			}`,
		},
		{
			name: "MESSAGE with special characters",
			input: `{
				"MESSAGE": "{\"unicode\":\"\\u0048\\u0065\\u006c\\u006c\\u006f\"}",
				"__REALTIME_TIMESTAMP": "1234567890",
				"__CURSOR": "cursor123"
			}`,
			unescapeJSON: true,
			expected: `{
				"MESSAGE": {"unicode":"Hello"},
				"_MESSAGE_IS_JSON": true,
				"__REALTIME_TIMESTAMP": "1234567890",
				"__CURSOR": "cursor123"
			}`,
		},
		{
			name: "feature disabled",
			input: `{
				"MESSAGE": "{\"key\":\"value\"}",
				"__REALTIME_TIMESTAMP": "1234567890",
				"__CURSOR": "cursor123"
			}`,
			unescapeJSON: false,
			expected: `{
				"MESSAGE": "{\"key\":\"value\"}",
				"__REALTIME_TIMESTAMP": "1234567890",
				"__CURSOR": "cursor123"
			}`,
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
			unescapeJSON: true,
			expected: `{
				"MESSAGE": {"key":"value"},
				"_MESSAGE_IS_JSON": true,
				"__REALTIME_TIMESTAMP": "1234567890",
				"__CURSOR": "cursor123",
				"_HOSTNAME": "testhost",
				"SYSLOG_IDENTIFIER": "test",
				"CUSTOM_FIELD": "should remain"
			}`,
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

			// Parse expected JSON
			var expected map[string]any
			if err := json.Unmarshal([]byte(tt.expected), &expected); err != nil {
				t.Fatalf("failed to parse expected JSON: %v", err)
			}

			// Parse result JSON
			var result map[string]any
			if err := json.Unmarshal(resultBytes, &result); err != nil {
				t.Fatalf("failed to parse result: %v", err)
			}

			// Compare as JSON (marshal both to canonical form)
			expectedBytes, err := json.Marshal(expected)
			if err != nil {
				t.Fatalf("failed to marshal expected: %v", err)
			}
			resultCanonical, err := json.Marshal(result)
			if err != nil {
				t.Fatalf("failed to marshal result: %v", err)
			}

			if string(expectedBytes) != string(resultCanonical) {
				t.Errorf("JSON mismatch:\nexpected: %s\ngot:      %s", string(expectedBytes), string(resultCanonical))
			}
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
