package processes

import (
	"context"
	"net/netip"
	"time"

	"github.com/runreveal/kawa"
	"github.com/runreveal/lib/await"
)

type Event struct {
	Time       time.Time `json:"time"`
	KernelTime uint64    `json:"bootTime"`
	PID        int       `json:"pid"`
	ParentPID  int       `json:"ppid"`
	Program    string    `json:"program,omitempty"`
	Argv       []string  `json:"argv,omitempty"`

	ForkEvent    *ForkEvent    `json:"fork,omitempty"`
	ExecEvent    *ExecEvent    `json:"exec,omitempty"`
	ExitEvent    *ExitEvent    `json:"exit,omitempty"`
	ConnectEvent *ConnectEvent `json:"connect,omitempty"`
}

type ForkEvent struct {
}

type ExecEvent struct {
}

type ExitEvent struct {
	Code int `json:"code"`
}

type ConnectEvent struct {
	Address netip.AddrPort `json:"address"`
}

var _ interface {
	kawa.Source[*Event]
	await.Runner
} = (*Source)(nil)

type Source struct {
	l *listener
}

func NewSource(network bool) (*Source, error) {
	l, err := newListener(network)
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
