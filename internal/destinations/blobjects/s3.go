package blobjects

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

type Option func(*S3)

func WithBucketName(bucketName string) Option {
	return func(s *S3) {
		s.bucketName = bucketName
	}
}

func WithWorkspaceID(workspaceID string) Option {
	return func(s *S3) {
		s.workspaceID = workspaceID
	}
}

func WithPathPrefix(pathPrefix string) Option {
	return func(s *S3) {
		s.pathPrefix = pathPrefix
	}
}

func WithBucketRegion(bucketRegion string) Option {
	return func(s *S3) {
		s.bucketRegion = bucketRegion
	}
}

func WithAccessKeyID(accessKeyID string) Option {
	return func(s *S3) {
		s.accessKeyID = accessKeyID
	}
}

func WithSecretAccessKey(secretAccessKey string) Option {
	return func(s *S3) {
		s.secretAccessKey = secretAccessKey
	}
}

func WithCustomEndpoint(customEndpoint string) Option {
	return func(s *S3) {
		s.customEndpoint = customEndpoint
	}
}

func WithBatchSize(batchSize int) Option {
	return func(s *S3) {
		s.batchSize = batchSize
	}
}

func WithFlushFrequency(flushFrequency time.Duration) Option {
	return func(s *S3) {
		s.flushFrequency = flushFrequency
	}
}

type S3 struct {
	batcher *batch.Destination[types.Event]

	bucketName      string
	workspaceID     string
	pathPrefix      string
	bucketRegion    string
	accessKeyID     string
	secretAccessKey string
	customEndpoint  string
	batchSize       int
	flushFrequency  time.Duration

	objStore *objstore.ObjStorageManager
}

func New(opts ...Option) *S3 {
	ret := &S3{}
	for _, o := range opts {
		o(ret)
	}
	if ret.batchSize == 0 {
		ret.batchSize = 100
	}
	if ret.bucketRegion == "" {
		ret.bucketRegion = "us-east-2"
	}
	if ret.flushFrequency == 0 {
		ret.flushFrequency = 30 * time.Second
	}

	ret.batcher = batch.NewDestination[types.Event](ret,
		batch.Raise[types.Event](),
		batch.FlushLength(ret.batchSize),
		batch.FlushFrequency(ret.flushFrequency),
	)
	return ret
}

func (s *S3) Run(ctx context.Context) error {
	if s.bucketName == "" {
		return errors.New("missing bucket name")
	}
	if s.workspaceID == "" {
		return errors.New("missing workspace ID")
	}

	// Initialize objstore using the existing S3 implementation
	if err := s.initObjStore(); err != nil {
		return fmt.Errorf("failed to initialize object store: %w", err)
	}

	return s.batcher.Run(ctx)
}

func (s *S3) initObjStore() error {
	s3Config := objstore.S3Config{
		Region:          s.bucketRegion,
		Type:            "s3",
		Bucket:          s.bucketName,
		AccessKeyID:     s.accessKeyID,
		SecretAccessKey: s.secretAccessKey,
		CustomEndpoint:  s.customEndpoint,
	}

	s3Client, err := objstore.NewS3(s3Config)
	if err != nil {
		return fmt.Errorf("failed to create S3 client: %w", err)
	}

	s.objStore, err = objstore.New(s3Client)
	if err != nil {
		return fmt.Errorf("failed to create object store manager: %w", err)
	}

	return nil
}

func (s *S3) Send(ctx context.Context, ack func(), msgs ...kawa.Message[types.Event]) error {
	return s.batcher.Send(ctx, ack, msgs...)
}

func (s *S3) Flush(ctx context.Context, msgs []kawa.Message[types.Event]) error {
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

	return s.objStore.Store(ctx, s.workspaceID, s.bucketName, key, bytes.NewReader(buf.Bytes()))
}
