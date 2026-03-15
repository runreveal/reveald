package cri

import (
	"testing"
	"time"
)

func TestParseCRI(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantTS  bool // whether we expect a non-zero timestamp
		wantLog string
	}{
		{
			name:    "standard CRI JSON",
			input:   `2026-03-15T00:08:39.715Z stdout F {"key":"val"}`,
			wantTS:  true,
			wantLog: `{"key":"val"}`,
		},
		{
			name:    "CRI with text body",
			input:   `2026-03-15T00:08:39.715Z stderr F error: failed`,
			wantTS:  true,
			wantLog: `error: failed`,
		},
		{
			name:    "partial line no tag",
			input:   `2026-03-15T00:08:39.715Z stdout`,
			wantTS:  true,
			wantLog: `stdout`,
		},
		{
			name:    "non-CRI passthrough",
			input:   `just a log line`,
			wantTS:  false,
			wantLog: `just a log line`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ts, body := parseCRI([]byte(tc.input))
			if tc.wantTS && ts.IsZero() {
				t.Errorf("expected non-zero timestamp, got zero")
			}
			if !tc.wantTS && !ts.IsZero() {
				t.Errorf("expected zero timestamp, got %v", ts)
			}
			if string(body) != tc.wantLog {
				t.Errorf("body = %q, want %q", body, tc.wantLog)
			}
		})
	}

	// Ensure the timestamp is parsed correctly for a known input
	ts, _ := parseCRI([]byte(`2026-03-15T00:08:39.715Z stdout F msg`))
	expected, _ := time.Parse(time.RFC3339Nano, "2026-03-15T00:08:39.715Z")
	if !ts.Equal(expected) {
		t.Errorf("timestamp = %v, want %v", ts, expected)
	}
}

func TestExtractJSON(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "already JSON object",
			input: `{"key":"val"}`,
			want:  `{"key":"val"}`,
		},
		{
			name:  "CoreDNS wrapped",
			input: "[INFO] `{\"remote\":\"127.0.0.1\"}`",
			want:  `{"remote":"127.0.0.1"}`,
		},
		{
			name:  "plain text no JSON",
			input: `[INFO] plugin/ready: ready`,
			want:  `[INFO] plugin/ready: ready`,
		},
		{
			name:  "JSON array passthrough",
			input: `[{"a":1}]`,
			want:  `[{"a":1}]`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := extractJSON([]byte(tc.input))
			if string(got) != tc.want {
				t.Errorf("extractJSON(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestContainerFromPath(t *testing.T) {
	tests := []struct {
		name string
		path string
		want string
	}{
		{
			name: "dns-logger container",
			path: "/var/log/pods/forge_forge-forge-alive_db5f/dns-logger/0.log",
			want: "dns-logger",
		},
		{
			name: "export-stdout container",
			path: "/var/log/pods/kube-system_tetragon_uid/export-stdout/0.log",
			want: "export-stdout",
		},
		{
			name: "no container extractable",
			path: "/some/other/path.log",
			want: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := containerFromPath(tc.path)
			if got != tc.want {
				t.Errorf("containerFromPath(%q) = %q, want %q", tc.path, got, tc.want)
			}
		})
	}
}
