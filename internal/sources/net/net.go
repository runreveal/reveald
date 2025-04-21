//go:generate go tool bpf2go -tags linux net linuxnet.c

package net

import (
	"context"
	"net/netip"
	"time"

	"github.com/runreveal/kawa"
	"github.com/runreveal/lib/await"
)

type Event struct {
	Time    time.Time      `json:"time"`
	PID     int            `json:"pid"`
	Address netip.AddrPort `json:"address"`
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
