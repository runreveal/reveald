package filewatch

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/runreveal/kawa"
	"github.com/runreveal/kawa/x/scanner"
	"github.com/runreveal/reveald/internal/types"
)

type Watcher struct {
	file    string
	wrapped *scanner.Scanner
	started chan struct{}
}

func NewWatcher(f string) *Watcher {
	return &Watcher{
		file:    f,
		started: make(chan struct{}),
	}
}

func (s *Watcher) Run(ctx context.Context) error {
	// open the file and construct a scanner from the reader
	f, err := os.Open(s.file)
	if err != nil {
		return fmt.Errorf("watcher: %w", err)
	}
	s.wrapped = scanner.NewScanner(f, scanner.Tail)
	close(s.started)
	return s.wrapped.Run(ctx)
}

func (s *Watcher) Recv(ctx context.Context) (kawa.Message[types.Event], func(), error) {
	select {
	case <-s.started:
	case <-ctx.Done():
		return kawa.Message[types.Event]{}, nil, ctx.Err()
	}

	msg, ack, err := s.wrapped.Recv(ctx)
	if err != nil {
		return kawa.Message[types.Event]{}, nil, err
	}
	return kawa.Message[types.Event]{
		Value: types.Event{
			EventTime:  time.Now(),
			SourceType: "scanner",
			RawLog:     msg.Value,
		},
	}, ack, nil
}
