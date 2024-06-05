package filewatch

import (
	"context"
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestScanUntilCancel(t *testing.T) {
	// Create a temporary file
	tmpfile, err := ioutil.TempFile("", "testfile")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())

	// Write some content to the file
	content := []byte("line 1\nline 2\nline 3\n")
	_, err = tmpfile.Write(content)
	if err != nil {
		t.Fatal(err)
	}

	// Close the file
	err = tmpfile.Close()
	if err != nil {
		t.Fatal(err)
	}

	// Create a context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Define a callback function for testing
	var lines []string
	callback := func(ctx context.Context, line []byte, pos int) {
		lines = append(lines, string(line))
	}

	// Call the function under test
	err = scanUntilCancel(ctx, callback, tmpfile)
	assert.NoError(t, err)

	// Verify the lines read
	expectedLines := []string{"line 1", "line 2", "line 3"}
	assert.Equal(t, expectedLines, lines)

	// Append more content to the file
	additionalContent := []byte("line 4\nline 5\n")
	_, err = os.OpenFile(tmpfile.Name(), os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		t.Fatal(err)
	}
	_, err = tmpfile.Write(additionalContent)
	if err != nil {
		t.Fatal(err)
	}

	// Call the function again to check for log rotation
	err = scanUntilCancel(ctx, callback, tmpfile)
	assert.NoError(t, err)

	// Verify the additional lines read
	expectedLines = append(expectedLines, "line 4", "line 5")
	assert.Equal(t, expectedLines, lines)
}
