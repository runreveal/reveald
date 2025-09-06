package objbatch

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/runreveal/kawa"
	batch "github.com/runreveal/kawa/x/batcher"
	"github.com/runreveal/reveald/internal/destinations/objstore"
	"github.com/runreveal/reveald/internal/types"
	"github.com/segmentio/ksuid"
)

type Option func(*ObjectStorage)

func WithBatchSize(batchSize int) Option {
	return func(s *ObjectStorage) {
		s.batchSize = batchSize
	}
}

func WithFlushFrequency(flushFrequency time.Duration) Option {
	return func(s *ObjectStorage) {
		s.flushFrequency = flushFrequency
	}
}

func WithBlobLike(blobLike objstore.BlobLike) Option {
	return func(s *ObjectStorage) {
		s.blobLike = blobLike
	}
}

type ObjectStorage struct {
	batcher *batch.Destination[types.Event]

	pathPrefix string
	bucketName string

	batchSize      int
	flushFrequency time.Duration
	blobLike       objstore.BlobLike
	objStore       *objstore.ObjStorageManager
}

func New(opts ...Option) *ObjectStorage {
	ret := &ObjectStorage{}
	for _, o := range opts {
		o(ret)
	}
	if ret.batchSize == 0 {
		ret.batchSize = 100
	}
	if ret.flushFrequency == 0 {
		ret.flushFrequency = 30 * time.Second
	}

	ret.batcher = batch.NewDestination(ret,
		batch.Raise[types.Event](),
		batch.FlushLength(ret.batchSize),
		batch.FlushFrequency(ret.flushFrequency),
	)
	return ret
}

func (s *ObjectStorage) Run(ctx context.Context) error {
	if s.blobLike == nil {
		return errors.New("no blob destination initialized")
	}
	var err error
	s.objStore, err = objstore.New(s.blobLike)
	if err != nil {
		return errors.New("objstore failed to initialize")
	}

	return s.batcher.Run(ctx)
}

func (s *ObjectStorage) Send(ctx context.Context, ack func(), msgs ...kawa.Message[types.Event]) error {
	return s.batcher.Send(ctx, ack, msgs...)
}

func (s *ObjectStorage) Flush(ctx context.Context, msgs []kawa.Message[types.Event]) error {
	var buf bytes.Buffer
	gzipBuffer := gzip.NewWriter(&buf)

	for _, msg := range msgs {
		_, err := gzipBuffer.Write(msg.Value.RawLog)
		if err != nil {
			return err
		}
		_, err = gzipBuffer.Write([]byte("\n"))
		if err != nil {
			return err
		}
	}

	if err := gzipBuffer.Close(); err != nil {
		return err
	}

	key := fmt.Sprintf("%s/%s/%s_%d.gz",
		s.pathPrefix,
		time.Now().UTC().Format("2006/01/02/15"),
		ksuid.New().String(),
		time.Now().Unix(),
	)

	return s.objStore.Store(ctx, s.bucketName, key, bytes.NewReader(buf.Bytes()))
}
