package objstore

import (
	"bytes"
	"context"
	"fmt"
	"io"
)

type GetObjectInput struct {
	Key string
}

type PutObjectInput struct {
	Key  string
	Data io.Reader
}

type SignedURLInput struct {
	Key string
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

func (m *ObjStorageManager) ReadAll(ctx context.Context, key string) ([]byte, error) {
	readCloser, err := m.Read(ctx, key)
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
// Read returns an io.ReadCloser that must be closed by the caller.
func (m *ObjStorageManager) Read(ctx context.Context, key string) (io.ReadCloser, error) {
	// Create a new S3 session and create the request
	input := GetObjectInput{
		Key: key,
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
// Store blocks until data has been fully read, so must be run in a separate
// goroutine from what is writing to the other side of the io.Reader, if
// necessary.
func (m *ObjStorageManager) Store(ctx context.Context, key string, data io.Reader) error {
	if key == "" {
		return fmt.Errorf("key is required")
	}

	return m.svc.PutObject(ctx, PutObjectInput{
		Key:  key,
		Data: data,
	})
}

func (m *ObjStorageManager) GetSignedURL(ctx context.Context, key string) (string, error) {
	r, err := m.svc.GetSignedURL(ctx, SignedURLInput{
		Key: key,
	})
	if err != nil {
		return "", fmt.Errorf("S3 GetSignedURL error (%s): %w", key, err)
	}
	return r, nil
}
