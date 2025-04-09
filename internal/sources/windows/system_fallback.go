//go:build !windows

package windows

import (
	"fmt"
	"runtime"
)

type eventSubscription struct{}

func newEventSubscription(opts *Options, onEvent xmlEventFunc, onError errorFunc) (*eventSubscription, error) {
	return nil, fmt.Errorf("windows_events: unsupported on %s", runtime.GOOS)
}

func (evtSub *eventSubscription) Close() error { return nil }

func reportInfoEvent(sourceName string, category uint16, eventID uint32, messages []string) error {
	return fmt.Errorf("report event: unsupported on %s", runtime.GOOS)
}
