package objstore

import (
	"os"
	"slices"

	"github.com/runreveal/lib/loader"
)

func init() {
	loader.Register("r2", func() loader.Builder[BlobLike] {
		return &R2Config{}
	})
	loader.Register("s3", func() loader.Builder[BlobLike] {
		return &S3Config{}
	})

	// only load if not in stage/prod
	if slices.Contains([]string{"development", "testing", ""}, os.Getenv("RUNREVEAL_ENV")) {
		loader.Register("fs", func() loader.Builder[BlobLike] {
			return &FilesystemConfig{}
		})
	}
}

func (r R2Config) Configure() (BlobLike, error) {
	return NewR2(r)
}

func (s S3Config) Configure() (BlobLike, error) {
	return NewS3(s)
}

func (f FilesystemConfig) Configure() (BlobLike, error) {
	return NewFilesystem(f)
}
