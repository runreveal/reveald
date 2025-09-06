package objbatch

import (
	"errors"
	"time"

	"github.com/runreveal/kawa"
	"github.com/runreveal/lib/loader"
	"github.com/runreveal/reveald/internal/destinations/objstore"
	"github.com/runreveal/reveald/internal/types"
)

type BlobConfig struct {
	BatchSize      int           `json:"batchSize"`
	FlushFrequency time.Duration `json:"flushFrequency"`

	ObjStore loader.Builder[objstore.BlobLike] `json:"s3"`
}

func (bc BlobConfig) Configure() (kawa.Destination[types.Event], error) {
	if bc.ObjStore == nil {
		return nil, errors.New("objstore is required")
	}
	bl, err := bc.ObjStore.Configure()
	if err != nil {
		return nil, err
	}

	opts := []Option{WithBlobLike(bl)}
	if bc.BatchSize > 0 {
		opts = append(opts, WithBatchSize(bc.BatchSize))
	}
	if bc.FlushFrequency > 5*time.Second {
		opts = append(opts, WithFlushFrequency(bc.FlushFrequency))
	}

	s3 := New(opts...)

	return s3, nil
}
