package s3kawad

import (
	"context"

	"github.com/runreveal/kawa"
	"github.com/runreveal/kawa/x/s3"
	"github.com/runreveal/reveald/internal/types"
)

type S3 struct {
	wrapped *s3.S3
}

func NewS3(opts ...s3.Option) *S3 {
	return &S3{wrapped: s3.New(opts...)}
}

func (p *S3) Run(ctx context.Context) error {
	return p.wrapped.Run(ctx)
}

func (p *S3) Send(ctx context.Context, ack func(), msg kawa.Message[types.Event]) error {
	return p.wrapped.Send(ctx, ack, kawa.Message[[]byte]{Value: msg.Value.RawLog})
}
