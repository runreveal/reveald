package filewatch

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"time"

	"github.com/runreveal/reveald/internal/sources/filewatch/internal"
)

// scanUntilClose reads from the io.ReadCloser until it is closed, calling the
// provided callback with each line read. The callback is called with the line
// read, excluding the newline character.  pos has the byte offset for the next line
// to be read.
// Upon reaching EOF, we check to see if a new file has been written to the
// location (for logrotation).
func scanUntilCancel(ctx context.Context, lf func(context.Context, []byte, string, int) error, f *os.File) error {
	go func() {
		// stop the scanner if we're canceled
		<-ctx.Done()
		f.Close()
	}()

	scanner := internal.NewScanner(f)
	more := scanner.Scan()
	for more {
		bts := scanner.Bytes()

		val := make([]byte, len(bts))
		copy(val, bts)

		// slog.Info("scanned line in file: %s", f.Name())
		err := lf(ctx, val, f.Name(), scanner.Position())
		if err != nil {
			return err
		}

		more = scanner.Scan()
		if !more && errors.Is(scanner.Err(), io.EOF) {
			slog.Info(fmt.Sprintf("EOF reached in file: %s", f.Name()))
			more = true
			time.Sleep(500 * time.Millisecond)
		}
	}

	return nil
}
