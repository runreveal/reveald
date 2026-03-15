package cri

import (
	"bytes"
	"context"
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

	msg.Value.RawLog = logBody
	msg.Value.SourceType = "cri"
	if !eventTime.IsZero() {
		msg.Value.EventTime = eventTime
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
