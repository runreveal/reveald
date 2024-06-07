package file

import (
	"context"
	"encoding/json"
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

func WithCommitInterval(d time.Duration) Option {
	return func(w *Watcher) {
		w.commitInterval = d
	}
}

func WithHighWatermarkFile(fname string) Option {
	return func(w *Watcher) {
		w.highWatermarkFile = fname
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

	mapLock           sync.RWMutex
	fmap              map[string]filePos
	highWatermarkFile string
	commitInterval    time.Duration
	commitTicker      *time.Ticker

	loaded chan struct{}
}

func NewWatcher(opts ...Option) *Watcher {
	w := &Watcher{
		msgC:   make(chan msgErr[types.Event]),
		fmap:   make(map[string]filePos),
		loaded: make(chan struct{}),
	}
	for _, opt := range opts {
		opt(w)
	}
	if w.commitInterval == 0 {
		w.commitInterval = 5 * time.Second
	}
	w.commitTicker = time.NewTicker(w.commitInterval)
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
	wg.Add(await.RunFunc(s.commitLoop))
	return wg.Run(ctx)
}

func (s *Watcher) savePosition(fname string, pos int) {
	s.mapLock.Lock()
	// save the position of the files
	if fpos, ok := s.fmap[fname]; ok {
		// Only update the position if it is advancing in the file.
		// There's a chance that lines will be processed out of order and we don't
		// want to move our position in the file backwards in that case.
		// The position being saved should represent where to start reading the
		// next line in the given file as a byte offset.
		if pos > fpos.pos {
			s.fmap[fname] = filePos{file: fpos.file, pos: pos}
		}
	} else {
		slog.Error(fmt.Sprintf("file %s not found in map.", fname))
	}
	s.mapLock.Unlock()
}

func (s *Watcher) persistOffsets() {
	// open a temporary file
	f, err := os.OpenFile(s.highWatermarkFile+".tmp", os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		slog.Error(fmt.Sprintf("error opening high watermark file: %s", s.highWatermarkFile))
		return
	}
	defer f.Close()

	tracker := make(map[string]int, len(s.fmap))
	// write the offsets to the file
	s.mapLock.RLock()
	for fname, fpos := range s.fmap {
		tracker[fname] = fpos.pos
	}
	s.mapLock.RUnlock()

	bts, err := json.Marshal(tracker)
	if err != nil {
		slog.Error(fmt.Sprintf("error marshalling offsets: %s", err))
		return
	}
	bts = append(bts, '\n')
	_, err = f.Write(bts)
	if err != nil {
		slog.Error(fmt.Sprintf("error writing to high watermark file: %s", s.highWatermarkFile))
		return
	}

	slog.Debug(fmt.Sprintf("persisted offsets to high watermark file: %s", s.highWatermarkFile))

	// rename the temporary file to the high watermark file
	err = os.Rename(s.highWatermarkFile+".tmp", s.highWatermarkFile)
	if err != nil {
		slog.Error(fmt.Sprintf("error renaming high watermark file: %s", s.highWatermarkFile))
		return
	}
}

func (s *Watcher) loadOffsets() map[string]int {
	ret := make(map[string]int)

	// open the high watermark file
	f, err := os.Open(s.highWatermarkFile)
	if err != nil {
		// if the file doesn't exist, return an empty map
		slog.Info(fmt.Sprintf("cant open high watermark file: %s", err))
		return ret
	}
	defer f.Close()

	// read the offsets from the file
	dec := json.NewDecoder(f)
	err = dec.Decode(&ret)
	if err != nil {
		slog.Error(fmt.Sprintf("error decoding offsets: %s", err))
		return ret
	}
	return ret
}

func (s *Watcher) commitLoop(ctx context.Context) error {
	// Wait until we have loaded the initial offsets
	select {
	case <-s.loaded:
	case <-ctx.Done():
		return ctx.Err()
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-s.commitTicker.C:
			s.persistOffsets()
		}
	}
}

func (s *Watcher) recvLoop(ctx context.Context) error {

	var callback = func(startOffset int) func(ctx context.Context, b []byte, fname string, pos int) error {
		return func(ctx context.Context, b []byte, fname string, pos int) error {
			event := kawa.Message[types.Event]{
				Value: types.Event{
					// TODO: how do we parse eventTime from the file?
					EventTime:  time.Now(),
					SourceType: "watcher",
					RawLog:     b,
				},
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case s.msgC <- msgErr[types.Event]{
				msg: event,
				ack: func() {
					s.savePosition(fname, startOffset+pos)
				},
				err: nil,
			}:
			}
			return nil
		}
	}

	// load the offsets from the high watermark file
	offsets := s.loadOffsets()
	firstRun := true

	for {
		// list the files in the directory given by s.path
		files, err := os.ReadDir(s.path)
		if err != nil {
			return fmt.Errorf("watcher: %w", err)
		}

		for _, file := range files {
			if file.IsDir() {
				continue
			}
			fname := filepath.Join(s.path, file.Name())
			if s.extension != "" && !strings.HasSuffix(fname, s.extension) {
				slog.Debug(fmt.Sprintf("skipping file without given extension (%s): %s", s.extension, fname))
				continue
			}
			s.mapLock.Lock()
			shouldOpen := false

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
					slog.Debug(fmt.Sprintf("log rotation detected, opening new file: %s", fname))
					cur.file.Close()
					shouldOpen = true
				}
			} else {
				// if the file is not in the map, add it
				slog.Debug(fmt.Sprintf("new log file detected to read: %s", fname))
				shouldOpen = true
			}

			// New file or file was rotated
			if shouldOpen {
				f, err := os.Open(fname)
				if err != nil {
					return fmt.Errorf("watcher: %w", err)
				}
				startOffset := 0
				if firstRun {
					slog.Debug(fmt.Sprintf("first run, setting file position to high watermark: %s", fname))
					// if this is the first run, set the position to the high watermark
					if pos, ok := offsets[fname]; ok {
						slog.Debug(fmt.Sprintf("first run, setting file position to: %d", pos))
						startOffset = pos
						f.Seek(int64(pos), 0)
					}
				}
				fp := filePos{file: f, pos: startOffset}
				// open the file for processing
				s.fmap[fname] = fp
				go func(fpos filePos) {
					// scan the file
					err := scanUntilCancel(ctx, callback(fpos.pos), fpos.file)
					if err != nil {
						s.msgC <- msgErr[types.Event]{
							msg: kawa.Message[types.Event]{},
							ack: nil,
							err: err,
						}
					}
				}(fp)
			}
			s.mapLock.Unlock()
		}
		if firstRun {
			close(s.loaded)
		}
		firstRun = false
		time.Sleep(5 * time.Second)
	}
}

func (s *Watcher) Recv(ctx context.Context) (kawa.Message[types.Event], func(), error) {
	select {
	case <-ctx.Done():
		return kawa.Message[types.Event]{}, nil, ctx.Err()
	case msg := <-s.msgC:
		return msg.msg, msg.ack, msg.err
	}
}
