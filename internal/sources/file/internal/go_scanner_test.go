package internal

import (
	"io"
	"strings"
	"testing"
)

// slowReader wraps a list of read results, returning one per Read call.
// This simulates a file being appended to in chunks (e.g. 4096-byte flushes).
type slowReader struct {
	chunks []string
	idx    int
}

func (r *slowReader) Read(p []byte) (int, error) {
	if r.idx >= len(r.chunks) {
		return 0, io.EOF
	}
	chunk := r.chunks[r.idx]
	r.idx++
	n := copy(p, chunk)
	// If this is the last chunk, return EOF with the data
	if r.idx >= len(r.chunks) {
		return n, io.EOF
	}
	return n, nil
}

func TestScanLines_CompleteLines(t *testing.T) {
	r := strings.NewReader("line1\nline2\nline3\n")
	s := NewScanner(r)

	var lines []string
	for s.Scan() {
		lines = append(lines, s.Text())
	}
	if err := s.Err(); err != nil && err != io.EOF {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := []string{"line1", "line2", "line3"}
	if len(lines) != len(expected) {
		t.Fatalf("got %d lines, want %d", len(lines), len(expected))
	}
	for i, line := range lines {
		if line != expected[i] {
			t.Errorf("line %d: got %q, want %q", i, line, expected[i])
		}
	}
}

func TestScanLines_DoesNotReturnUnterminatedLineAtEOF(t *testing.T) {
	// Simulates a partial buffer flush: the file contains a complete line
	// followed by an incomplete line with no trailing newline.
	r := strings.NewReader("complete\npartial")
	s := NewScanner(r)

	var lines []string
	for s.Scan() {
		lines = append(lines, s.Text())
	}

	// Only the complete line should be returned; the unterminated "partial"
	// should be held in the buffer (not emitted).
	if len(lines) != 1 {
		t.Fatalf("got %d lines, want 1; lines: %v", len(lines), lines)
	}
	if lines[0] != "complete" {
		t.Errorf("got %q, want %q", lines[0], "complete")
	}
}

func TestScanLines_PartialLineCompletedBySubsequentWrite(t *testing.T) {
	// Simulates: first read returns "complete\npar", second returns "tial\n"
	// The scanner should emit "complete", then hold "par" until the second
	// read completes it, then emit "partial".
	r := &slowReader{
		chunks: []string{"complete\npar", "tial\n"},
	}
	s := NewScanner(r)

	var lines []string
	for s.Scan() {
		lines = append(lines, s.Text())
	}

	expected := []string{"complete", "partial"}
	if len(lines) != len(expected) {
		t.Fatalf("got %d lines %v, want %d", len(lines), lines, len(expected))
	}
	for i, line := range lines {
		if line != expected[i] {
			t.Errorf("line %d: got %q, want %q", i, line, expected[i])
		}
	}
}

func TestScanLines_EmptyInput(t *testing.T) {
	r := strings.NewReader("")
	s := NewScanner(r)

	if s.Scan() {
		t.Fatal("expected Scan to return false for empty input")
	}
	if err := s.Err(); err != nil && err != io.EOF {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestScanLines_OnlyNewlines(t *testing.T) {
	r := strings.NewReader("\n\n\n")
	s := NewScanner(r)

	var lines []string
	for s.Scan() {
		lines = append(lines, s.Text())
	}

	// Three newlines produce three empty-string tokens.
	if len(lines) != 3 {
		t.Fatalf("got %d lines, want 3", len(lines))
	}
	for i, line := range lines {
		if line != "" {
			t.Errorf("line %d: got %q, want empty", i, line)
		}
	}
}

func TestScanLines_CRLFHandling(t *testing.T) {
	r := strings.NewReader("line1\r\nline2\r\n")
	s := NewScanner(r)

	var lines []string
	for s.Scan() {
		lines = append(lines, s.Text())
	}

	expected := []string{"line1", "line2"}
	if len(lines) != len(expected) {
		t.Fatalf("got %d lines, want %d", len(lines), len(expected))
	}
	for i, line := range lines {
		if line != expected[i] {
			t.Errorf("line %d: got %q, want %q", i, line, expected[i])
		}
	}
}

func TestScan_PositionTracksCorrectly(t *testing.T) {
	r := strings.NewReader("aaa\nbbb\nccc\n")
	s := NewScanner(r)

	// Position should advance by the length of each line + newline
	expectedPositions := []int{4, 8, 12} // "aaa\n"=4, "bbb\n"=4, "ccc\n"=4

	i := 0
	for s.Scan() {
		if i >= len(expectedPositions) {
			t.Fatal("too many tokens")
		}
		if s.Position() != expectedPositions[i] {
			t.Errorf("after token %d (%q): position = %d, want %d",
				i, s.Text(), s.Position(), expectedPositions[i])
		}
		i++
	}
}

func TestScan_ReturnsFalseAtEOFWithPartialData(t *testing.T) {
	// When the file ends mid-line, Scan should return false (no complete token)
	// but the scanner should NOT be "done" — a subsequent Scan after more data
	// arrives should succeed.
	r := strings.NewReader("complete\npartial")
	s := NewScanner(r)

	// First Scan: returns "complete"
	if !s.Scan() {
		t.Fatal("expected first Scan to return true")
	}
	if s.Text() != "complete" {
		t.Fatalf("got %q, want %q", s.Text(), "complete")
	}

	// Second Scan: should return false (partial data, no newline at EOF)
	if s.Scan() {
		t.Fatalf("expected Scan to return false for partial data, got token %q", s.Text())
	}
}

func TestScanLines_MultipleChunkedWrites(t *testing.T) {
	// Simulates a logger writing in small buffer flushes that split lines
	// across multiple writes.
	r := &slowReader{
		chunks: []string{
			`{"event":"lo`,            // partial JSON
			`gin","user":"a"}` + "\n", // completes first line
			`{"event":"logo`,          // partial second line
			`ut","user":"b"}` + "\n",  // completes second line
		},
	}
	s := NewScanner(r)

	var lines []string
	for s.Scan() {
		lines = append(lines, s.Text())
	}

	expected := []string{
		`{"event":"login","user":"a"}`,
		`{"event":"logout","user":"b"}`,
	}
	if len(lines) != len(expected) {
		t.Fatalf("got %d lines %v, want %d", len(lines), lines, len(expected))
	}
	for i, line := range lines {
		if line != expected[i] {
			t.Errorf("line %d: got %q, want %q", i, line, expected[i])
		}
	}
}
