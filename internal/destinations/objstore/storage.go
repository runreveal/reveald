package objstore

import (
	"bytes"
	"context"
	"fmt"
	"io"
)

type GetObjectInput struct {
	Bucket string
	Key    string
}

type PutObjectInput struct {
	Bucket string
	Key    string
	Data   io.Reader
}

type SignedURLInput struct {
	Bucket string
	Key    string
}

type BlobLike interface {
	GetObject(ctx context.Context, in GetObjectInput) (io.ReadCloser, error)
	PutObject(ctx context.Context, in PutObjectInput) error
	GetSignedURL(ctx context.Context, in SignedURLInput) (string, error)
}

// ObjectStorageManager is a high level wrapper around S3 Clients which implements basic
// workspace-based storage separation (via workspaceID prefixing).
type ObjStorageManager struct {
	svc BlobLike
}

func New(objstr BlobLike) (*ObjStorageManager, error) {
	return &ObjStorageManager{svc: objstr}, nil
}

func (m *ObjStorageManager) ReadAll(ctx context.Context, wkspID, bucket, key string) ([]byte, error) {
	readCloser, err := m.Read(ctx, wkspID, bucket, key)
	if err != nil {
		return nil, fmt.Errorf("S3 data read error: %w", err)
	}

	buf := new(bytes.Buffer)
	_, err = buf.ReadFrom(readCloser)
	if err != nil {
		return nil, fmt.Errorf("S3 data read error: %w", err)
	}
	err = readCloser.Close()
	if err != nil {
		return nil, fmt.Errorf("S3 data close error: %w", err)
	}
	return buf.Bytes(), nil
}

// Read reads the data from the s3 bucket for the given key.
// The given key will be prefixed with the workspaceID.
// Read returns an io.ReadCloser that must be closed by the caller.
func (m *ObjStorageManager) Read(ctx context.Context, wkspID, bucket, key string) (io.ReadCloser, error) {
	// Create a new S3 session and create the request
	input := GetObjectInput{
		Bucket: bucket,
		Key:    wkspID + "/" + key,
	}

	// Return the object and check for error
	result, err := m.svc.GetObject(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("S3 GetObject error (%s): %w", key, err)
	}

	return result, nil
}

// Store stores the data in the s3 bucket for the given key.
// data will be read until io.EOF is returned from Read()
// The given key will be prefixed with the workspaceID.
// Store blocks until data has been fully read, so must be run in a separate
// goroutine from what is writing to the other side of the io.Reader, if
// necessary.
func (m *ObjStorageManager) Store(ctx context.Context, wkspID, bucket, key string, data io.Reader) error {
	if key == "" || wkspID == "" || bucket == "" {
		return fmt.Errorf("wkspID, bucket and key are required")
	}

	return m.svc.PutObject(ctx, PutObjectInput{
		Bucket: bucket,
		Key:    wkspID + "/" + key,
		Data:   data,
	})
}

func (m *ObjStorageManager) GetSignedURL(ctx context.Context, wkspID, bucket, key string) (string, error) {
	r, err := m.svc.GetSignedURL(ctx, SignedURLInput{
		Bucket: bucket,
		Key:    wkspID + "/" + key,
	})
	if err != nil {
		return "", fmt.Errorf("S3 GetSignedURL error (%s): %w", key, err)
	}
	return r, nil
}
