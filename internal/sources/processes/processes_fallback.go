//go:build !linux

package processes

import (
	"context"
	"fmt"
	"runtime"
)

var errNotSupported = fmt.Errorf("net source not supported on %s", runtime.GOOS)

type listener struct {
}

func newListener() (*listener, error) {
	return nil, errNotSupported
}

func (l *listener) next(ctx context.Context) (*Event, error) {
	return nil, errNotSupported
}

func (l *listener) Close() error {
	return nil
}
