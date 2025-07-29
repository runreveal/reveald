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

type S3 struct {
	s3svc *s3.Client
}

type S3Config struct {
	Region          string `json:"region"`
	Type            string `json:"type"`
	Bucket          string `json:"bucket,omitempty"`
	AccessKeyID     string `json:"accessKeyID,omitempty"`
	SecretAccessKey string `json:"secretAccessKey,omitempty"`
	CustomEndpoint  string `json:"customEndpoint,omitempty"`
}

func NewS3(cfg S3Config) (*S3, error) {
	var configOpts []func(*config.LoadOptions) error
	
	if cfg.Region != "" {
		configOpts = append(configOpts, config.WithRegion(cfg.Region))
	}
	
	if cfg.AccessKeyID != "" && cfg.SecretAccessKey != "" {
		staticCreds := credentials.NewStaticCredentialsProvider(
			cfg.AccessKeyID,
			cfg.SecretAccessKey,
			"",
		)
		configOpts = append(configOpts, config.WithCredentialsProvider(staticCreds))
	}

	awsConfig, err := config.LoadDefaultConfig(context.TODO(), configOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	var client *s3.Client
	if cfg.CustomEndpoint != "" {
		client = s3.NewFromConfig(awsConfig, func(o *s3.Options) {
			o.BaseEndpoint = aws.String(cfg.CustomEndpoint)
		})
	} else {
		client = s3.NewFromConfig(awsConfig)
	}

	return &S3{
		s3svc: client,
	}, nil
}

func (s *S3) GetObject(ctx context.Context, in GetObjectInput) (io.ReadCloser, error) {
	obj, err := s.s3svc.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(in.Bucket),
		Key:    aws.String(in.Key),
	})

	return obj.Body, err
}

func (s *S3) PutObject(ctx context.Context, in PutObjectInput) error {
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

func (s *S3) GetSignedURL(ctx context.Context, in SignedURLInput) (string, error) {
	// Create presign client
	presignClient := s3.NewPresignClient(s.s3svc)

	// Create the presigned request
	req, err := presignClient.PresignGetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(in.Bucket),
		Key:    aws.String(in.Key),
	}, s3.WithPresignExpires(15*time.Minute))
	if err != nil {
		return "", fmt.Errorf("failed to presign URL: %w", err)
	}

	return req.URL, nil
}
