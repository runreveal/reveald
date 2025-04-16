package windows

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"sync"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/runreveal/kawa"
)

// Options is the set of parameters to [NewEventLogSource].
type Options struct {
	// Query specifies the types of events that you want the subscription service to return.
	// You can specify an XPath 1.0 query or structured XML query.
	// An empty Query is equivalent to "*".
	Query string
	// Channel is the name of the Admin or Operational channel
	// that contains the events that you want to subscribe to.
	// Channel is required if Query contains an XPath query;
	// Channel is ignored if Query contains a structured XML query.
	Channel string
	// Buffer is the maximum number of events to receive between calls to [*EventLogSource.Recv].
	// If less than 1, Buffer is treated as if 1 was given.
	Buffer int
}

// EventLogSource is a [kawa.Source] that reads the [Windows Event Log].
//
// [Windows Event Log]: https://learn.microsoft.com/en-us/windows/win32/wes/windows-event-log
type EventLogSource struct {
	channel      string
	subscription *eventSubscription
	events       chan []byte

	setError sync.Once
	err      error
}

// NewEventLogSource creates a new subscription to the Windows Event Log.
// The caller is responsible for calling [*EventLogSource.Close] on the returned source
// when the caller is no longer using the source.
func NewEventLogSource(opts *Options) (*EventLogSource, error) {
	var fullOptions Options
	if opts != nil {
		fullOptions = *opts
		if fullOptions.Query == "" {
			fullOptions.Query = "*"
		}
	}

	s := &EventLogSource{
		channel: fullOptions.Channel,
		events:  make(chan []byte, max(fullOptions.Buffer, 1)),
	}
	var err error
	s.subscription, err = newEventSubscription(&fullOptions, s.onEvent, s.onError)
	if err != nil {
		return nil, err
	}
	//Query=[EventData[Data[@Name='LogonType']='2'] and System[(EventID=4624)]]", // Successful interactive logon events
	return s, nil
}

func (s *EventLogSource) onEvent(b []byte) {
	select {
	case s.events <- b:
	default:
		// Drop events if our buffer is full.
	}
}

func (s *EventLogSource) onError(err error) {
	s.setError.Do(func() {
		close(s.events)
		s.err = err
	})
}

// Recv waits for the next matching event in the event log.
// The acknowledgement function is a no-op.
//
// If Recv is not called at a rate that matches incoming events,
// then the source will skip events.
// To address bursts of events, you can increase the Buffer in [Options] given to [NewEventLogSource].
func (s *EventLogSource) Recv(ctx context.Context) (kawa.Message[Event], func(), error) {
	var data []byte
	var ok bool
	select {
	case data, ok = <-s.events:
		if !ok {
			// Wait for onError to finish.
			s.setError.Do(func() {})

			return kawa.Message[Event]{}, nil, s.err
		}
	case <-ctx.Done():
		return kawa.Message[Event]{}, nil, ctx.Err()
	}

	x := new(xmlEvent)
	if err := xml.Unmarshal(data, x); err != nil {
		return kawa.Message[Event]{}, nil, fmt.Errorf("windows_event: failed to unmarshal event xml: %v", err)
	}
	return kawa.Message[Event]{
		Value: *x.ToJSONEvent(),
		Topic: s.channel,
	}, func() {}, nil
}

// Run waits until ctx.Done() is closed
// then stops the Windows Event Log subscription
// and releases any resources associated with the source.
func (s *EventLogSource) Run(ctx context.Context) error {
	<-ctx.Done()
	err := s.subscription.Close()
	s.setError.Do(func() {
		close(s.events)
		s.err = errors.New("windows_event: source closed")
	})
	return err
}

func utf16ToUTF8(src []uint16) []byte {
	// Compute size.
	n := 0
	for i := 0; i < len(src); i++ {
		r1 := rune(src[i])
		if r1 == 0 {
			src = src[:i]
			break
		}
		if utf16.IsSurrogate(r1) {
			i++
			if i < len(src) {
				r2 := rune(src[i])
				if r2 == 0 {
					src = src[:i]
					n += utf8.RuneLen(utf8.RuneError)
					break
				}
				n += utf8.RuneLen(utf16.DecodeRune(r1, r2))
			} else {
				n += utf8.RuneLen(utf8.RuneError)
			}
		} else {
			n += utf8.RuneLen(r1)
		}
	}

	// Allocate bytes.
	dst := make([]byte, 0, n)
	for i := 0; i < len(src); i++ {
		r1 := rune(src[i])
		if utf16.IsSurrogate(r1) {
			i++
			if i < len(src) {
				r2 := rune(src[i])
				dst = utf8.AppendRune(dst, utf16.DecodeRune(r1, r2))
			} else {
				dst = utf8.AppendRune(dst, utf8.RuneError)
			}
		} else {
			dst = utf8.AppendRune(dst, r1)
		}
	}
	return dst
}

type xmlEventFunc func([]byte)
type errorFunc func(error)
