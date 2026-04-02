package printer

import (
	"context"
	"io"

	"github.com/runreveal/kawa"
	"github.com/runreveal/kawa/x/printer"
	"github.com/runreveal/reveald/internal/types"
)

type Printer struct {
	wrapped *printer.Printer
}

func NewPrinter(writer io.Writer) *Printer {
	return &Printer{wrapped: printer.NewPrinter(writer)}
}

func (p *Printer) Send(ctx context.Context, ack func(), msg kawa.Message[types.Event]) error {
	return p.wrapped.Send(ctx, ack, kawa.Message[[]byte]{Value: msg.Value.RawLog})
}
