package objstore

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

type R2 struct {
	s3svc *s3.Client
}

type R2Config struct {
	Account         string `json:"account"`
	Jurisdiction    string `json:"jurisdiction"`
	AccessKeyID     string `json:"accessKeyID"`
	SecretAccessKey string `json:"secretAccessKey"`
	Type            string `json:"type"`
}

func NewR2(cfg R2Config) (*R2, error) {
	r2Cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(cfg.AccessKeyID, cfg.SecretAccessKey, ""),
		),
		config.WithRegion("auto"),
	)
	if err != nil {
		return nil, err
	}

	r2AccessURL := fmt.Sprintf("https://%s.r2.cloudflarestorage.com", cfg.Account)
	if cfg.Jurisdiction != "" {
		r2AccessURL = fmt.Sprintf("https://%s.%s.r2.cloudflarestorage.com", cfg.Account, cfg.Jurisdiction)
	}

	client := s3.NewFromConfig(r2Cfg, func(o *s3.Options) {
		o.BaseEndpoint = aws.String(r2AccessURL)
	})

	return &R2{s3svc: client}, nil
}

func (s *R2) GetObject(ctx context.Context, in GetObjectInput) (io.ReadCloser, error) {
	obj, err := s.s3svc.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(in.Bucket),
		Key:    aws.String(in.Key),
	})

	return obj.Body, err
}

func (s *R2) PutObject(ctx context.Context, in PutObjectInput) error {
	uploader := manager.NewUploader(s.s3svc, func(u *manager.Uploader) {
		// PartSize (upload buffer size) is minimum 5MB
		// u.PartSize = 5 * 1024 * 1024
		u.Concurrency = 5
		u.LeavePartsOnError = false
	})

	_, err := uploader.Upload(ctx, &s3.PutObjectInput{
		Bucket: aws.String(in.Bucket),
		Key:    aws.String(in.Key),
		Body:   in.Data,
	})
	return err
}

func (s *R2) GetSignedURL(ctx context.Context, in SignedURLInput) (string, error) {
	// Create presign client
	presignClient := s3.NewPresignClient(s.s3svc)

	// Create the presigned request
	resp, err := presignClient.PresignGetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(in.Bucket),
		Key:    aws.String(in.Key),
	}, s3.WithPresignExpires(15*time.Minute))
	if err != nil {
		return "", fmt.Errorf("failed to presign URL: %w", err)
	}

	return resp.URL, nil
}
