package cri

import (
	"bytes"
	"context"
	"strings"
	"time"

	"github.com/runreveal/kawa"
	"github.com/runreveal/reveald/internal/sources/file"
	"github.com/runreveal/reveald/internal/types"
)

// Source wraps a file.Watcher and parses the CRI log format, stripping the
// timestamp/stream/flags prefix from each line.
//
// CRI log format: <timestamp> <stream> <flags> <log>
// Example: 2026-03-15T00:08:39.715Z stdout F {"remote":"127.0.0.1"}
type Source struct {
	watcher *file.Watcher
}

func New(watcher *file.Watcher) *Source {
	return &Source{watcher: watcher}
}

func (s *Source) Run(ctx context.Context) error {
	return s.watcher.Run(ctx)
}

func (s *Source) Recv(ctx context.Context) (kawa.Message[types.Event], func(), error) {
	msg, ack, err := s.watcher.Recv(ctx)
	if err != nil {
		return msg, ack, err
	}

	raw := msg.Value.RawLog
	eventTime, logBody := parseCRI(raw)
	logBody = extractJSON(logBody)

	msg.Value.RawLog = types.RawLogJSON(logBody)
	msg.Value.SourceType = "cri"

	if !eventTime.IsZero() {
		msg.Value.EventTime = eventTime
	}

	if tags := tagsFromPath(msg.Key); tags != nil {
		msg.Value.Tags = tags
	}

	if container := containerFromPath(msg.Key); container != "" {
		msg.Value.Service.Name = container
	}

	return msg, ack, nil
}

// parseCRI extracts the timestamp and log body from a CRI-formatted line.
// Returns zero time if the timestamp can't be parsed.
func parseCRI(line []byte) (time.Time, []byte) {
	// Find first space (after timestamp)
	i := bytes.IndexByte(line, ' ')
	if i < 0 {
		return time.Time{}, line
	}

	ts, err := time.Parse(time.RFC3339Nano, string(line[:i]))
	if err != nil {
		return time.Time{}, line
	}

	rest := line[i+1:]

	// Skip stream (stdout/stderr)
	i = bytes.IndexByte(rest, ' ')
	if i < 0 {
		return ts, rest
	}
	rest = rest[i+1:]

	// Skip flags (F/P)
	i = bytes.IndexByte(rest, ' ')
	if i < 0 {
		return ts, rest
	}

	return ts, rest[i+1:]
}

// extractJSON extracts embedded JSON from a log line. If the line already
// starts with '{', or starts with '[' followed by a non-letter (i.e. looks
// like a JSON array rather than a log-level prefix like "[INFO]"), it is
// returned as-is. Otherwise, the substring from the first '{' to the last '}'
// is returned. If no '{' is found, the line is returned unchanged.
func extractJSON(b []byte) []byte {
	if len(b) == 0 {
		return b
	}
	if b[0] == '{' {
		return b
	}
	// Treat '[' as a JSON array start only when the next byte is not an ASCII
	// letter (e.g. '[{"a":1}]' yes, '[INFO] ...' no).
	if b[0] == '[' && (len(b) == 1 || !isASCIILetter(b[1])) {
		return b
	}
	start := bytes.IndexByte(b, '{')
	if start < 0 {
		return b
	}
	end := bytes.LastIndexByte(b, '}')
	if end < start {
		return b
	}
	return b[start : end+1]
}

func isASCIILetter(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// tagsFromPath extracts namespace and pod name from a K8s pod log path.
// Path format: /var/log/pods/<namespace>_<pod>_<uid>/<container>/<rotation>.log
func tagsFromPath(path string) map[string]string {
	if !strings.Contains(path, "/pods/") {
		return nil
	}
	parts := strings.Split(path, "/")
	if len(parts) < 7 {
		return nil
	}
	// The pods directory segment: <namespace>_<pod>_<uid>
	podSegment := parts[len(parts)-3]
	fields := strings.SplitN(podSegment, "_", 3)
	if len(fields) < 2 {
		return nil
	}
	return map[string]string{
		"namespace": fields[0],
		"pod":       fields[1],
	}
}

// containerFromPath extracts the container name from a K8s pod log path.
// Path format: /var/log/pods/<namespace>_<pod>_<uid>/<container>/<rotation>.log
// Returns the second-to-last path segment (the container directory).
// Returns "" if the path doesn't look like a K8s pod log path.
func containerFromPath(path string) string {
	if !strings.Contains(path, "/pods/") {
		return ""
	}
	parts := strings.Split(path, "/")
	// Need at least: ["", "var", "log", "pods", "<ns_pod_uid>", "<container>", "<file>"]
	if len(parts) < 7 {
		return ""
	}
	return parts[len(parts)-2]
}
