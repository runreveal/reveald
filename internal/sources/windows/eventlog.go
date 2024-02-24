//go:build windows
// +build windows

package windowskawad

import (
	"context"
	"encoding/json"

	"github.com/runreveal/kawa"
	"github.com/runreveal/kawa/x/windows"
	"github.com/runreveal/reveald/internal/types"
)

type EventLog struct {
	wrapped *windows.EventLogSource
}

func NewEventLog(opts ...windows.Option) *EventLog {
	return &EventLog{
		wrapped: windows.NewEventLogSource(opts...),
	}
}

func (s *EventLog) Run(ctx context.Context) error {
	return s.wrapped.Run(ctx)
}

func (s *EventLog) Recv(ctx context.Context) (kawa.Message[types.Event], func(), error) {
	msg, ack, err := s.wrapped.Recv(ctx)
	if err != nil {
		return kawa.Message[types.Event]{}, nil, ctx.Err()
	}

	rawLog, err := json.Marshal(msg.Value)
	if err != nil {
		return kawa.Message[types.Event]{}, nil, ctx.Err()
	}

	eventMsg := kawa.Message[types.Event]{
		Key: msg.Key,
		Value: types.Event{
			Timestamp:  msg.Value.System.TimeCreated.SystemTime,
			SourceType: "eventlog",
			RawLog:     rawLog,
		},
		Topic:      msg.Topic,
		Attributes: msg.Attributes,
	}

	return eventMsg, ack, err
}
