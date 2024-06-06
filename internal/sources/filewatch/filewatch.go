package filewatch

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/runreveal/kawa"
	"github.com/runreveal/lib/await"
	"github.com/runreveal/reveald/internal/types"
)

type Option func(*Watcher)

func WithExtension(ext string) Option {
	return func(w *Watcher) {
		w.extension = ext
	}
}

func WithPath(path string) Option {
	return func(w *Watcher) {
		w.path = path
	}
}

type msgErr[T any] struct {
	msg kawa.Message[T]
	ack func()
	err error
}

type filePos struct {
	file *os.File
	pos  int
}

type Watcher struct {
	path      string
	extension string
	msgC      chan msgErr[types.Event]

	mapLock sync.RWMutex
	fmap    map[string]filePos
}

func NewWatcher(opts ...Option) *Watcher {
	w := &Watcher{
		msgC: make(chan msgErr[types.Event]),
		fmap: make(map[string]filePos),
	}
	// first determine if the path is a single file or a directory
	// If it's a directory, monitor all files in the directory

	for _, opt := range opts {
		opt(w)
	}
	return w
}

func (s *Watcher) Run(ctx context.Context) error {
	if s.path == "" {
		return fmt.Errorf("watcher: path is required")
	}

	st, err := os.Stat(s.path)
	if err != nil {
		return fmt.Errorf("watcher: %w", err)
	}

	if !st.IsDir() {
		return errors.New("watcher: single file monitoring not implemented yet")
	}

	if !filepath.IsAbs(s.path) {
		s.path, err = filepath.Abs(s.path)
		if err != nil {
			return fmt.Errorf("watcher: %w", err)
		}
	}

	wg := await.New()
	wg.Add(await.RunFunc(s.recvLoop))
	return wg.Run(ctx)
}

func (s *Watcher) savePosition(fname string, pos int) {
	s.mapLock.Lock()
	defer s.mapLock.Unlock()
	// save the position of the files
	if fpos, ok := s.fmap[fname]; ok {
		s.fmap[fname] = filePos{file: fpos.file, pos: pos}
		slog.Info(fmt.Sprintf("file %s position saved: %d", fname, pos))
	} else {
		slog.Error(fmt.Sprintf("file %s not found in map.", fname))
	}
}

func (s *Watcher) recvLoop(ctx context.Context) error {

	var callback = func(ctx context.Context, b []byte, fname string, pos int) error {
		event := kawa.Message[types.Event]{
			Value: types.Event{
				// TODO: how do we parse eventTime from the file?
				EventTime:  time.Now(),
				SourceType: "scanner",
				RawLog:     b,
			},
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case s.msgC <- msgErr[types.Event]{
			msg: event,
			ack: func() {
				s.savePosition(fname, pos)
			},
			err: nil,
		}:
		}
		return nil
	}

	for {
		// list the files in the directory given by s.path
		files, err := os.ReadDir(s.path)
		if err != nil {
			return fmt.Errorf("watcher: %w", err)
		}
		slog.Info(fmt.Sprintf("files in directory: %v", files))

		for _, file := range files {
			if file.IsDir() {
				continue
			}

			fname := filepath.Join(s.path, file.Name())

			if s.extension != "" && !strings.HasSuffix(fname, s.extension) {
				continue
			}

			s.mapLock.Lock()
			shouldOpen := false
			// if the file is not in the map, add it
			if cur, ok := s.fmap[fname]; ok {
				newSt, err := os.Stat(fname)
				if err != nil {
					return fmt.Errorf("watcher: %w", err)
				}
				curSt, err := cur.file.Stat()
				if err != nil {
					return fmt.Errorf("watcher: %w", err)
				}
				if !os.SameFile(newSt, curSt) {
					cur.file.Close()
					shouldOpen = true
				}
			} else {
				shouldOpen = true
				slog.Info(fmt.Sprintf("file %s not found in map, adding it", fname))
			}

			if shouldOpen {
				f, err := os.Open(fname)
				if err != nil {
					return fmt.Errorf("watcher: %w", err)
				}

				// open the file for processing
				s.fmap[f.Name()] = filePos{file: f, pos: 0}

				go func() {
					// scan the file
					err := scanUntilCancel(ctx, callback, f)
					if err != nil {
						s.msgC <- msgErr[types.Event]{
							msg: kawa.Message[types.Event]{},
							ack: nil,
							err: err,
						}
					}
				}()
			}
			s.mapLock.Unlock()
		}
		time.Sleep(5 * time.Second)

	}

	// for {
	// 	msg, ack, err := s.wrapped.Recv(ctx)
	// }
}

func (s *Watcher) Recv(ctx context.Context) (kawa.Message[types.Event], func(), error) {

	select {
	case <-ctx.Done():
		return kawa.Message[types.Event]{}, nil, ctx.Err()
	case msg := <-s.msgC:
		return msg.msg, msg.ack, msg.err
	}

}
