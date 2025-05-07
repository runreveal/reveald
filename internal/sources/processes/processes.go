package processes

import (
	"context"
	"time"

	"github.com/runreveal/kawa"
	"github.com/runreveal/lib/await"
)

type EventType string

const (
	ForkEvent EventType = "fork"
	ExecEvent EventType = "exec"
)

type Event struct {
	Type       EventType `json:"type"`
	Time       time.Time `json:"time"`
	KernelTime uint64    `json:"bootTime"`
	PID        int       `json:"pid"`
	ParentPID  int       `json:"ppid"`

	Program string   `json:"program,omitempty"`
	Argv    []string `json:"argv,omitempty"`
}

var _ interface {
	kawa.Source[*Event]
	await.Runner
} = (*Source)(nil)

type Source struct {
	l *listener
}

func NewSource() (*Source, error) {
	l, err := newListener()
	if err != nil {
		return nil, err
	}
	return &Source{l}, nil
}

func (src *Source) Recv(ctx context.Context) (kawa.Message[*Event], func(), error) {
	e, err := src.l.next(ctx)
	if err != nil {
		return kawa.Message[*Event]{}, nil, err
	}
	return kawa.Message[*Event]{Value: e}, func() {}, nil
}

func (src *Source) Run(ctx context.Context) error {
	<-ctx.Done()
	return src.l.Close()
}
