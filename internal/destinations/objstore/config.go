package objstore

import (
	"github.com/runreveal/lib/loader"
)

func init() {
	loader.Register("r2", func() loader.Builder[BlobLike] {
		return &R2Config{}
	})
	loader.Register("s3", func() loader.Builder[BlobLike] {
		return &S3Config{}
	})

}

func (r R2Config) Configure() (BlobLike, error) {
	return NewR2(r)
}

func (s S3Config) Configure() (BlobLike, error) {
	return NewS3(s)
}
