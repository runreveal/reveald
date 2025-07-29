package objstore

import (
	"fmt"
	"testing"

	"github.com/runreveal/lib/loader"
	"github.com/stretchr/testify/assert"
)

func TestBlobStoreLoading(t *testing.T) {
	tests := []struct {
		name       string
		input      []byte
		expectType string
	}{
		{
			name: "r2_config",
			input: []byte(`{
				"type": "r2",
				"account": "test-account",
				"jurisdiction": "test-jurisdiction",
				"accessKeyID": "test-access-key",
				"secretAccessKey": "test-secret-key"
			}`),
			expectType: "*objstore.R2",
		},
		{
			name: "s3_config",
			input: []byte(`{
				"type": "s3",
				"sessionName": "test-session",
				"roleArn": "test-role",
				"externalID": "test-external-id",
				"region": "us-east-1",
				"accessKeyID": "test-access-key",
				// comments and trailing commas are allowed with loader
				"secretAccessKey": "test-secret-key",
			}`),
			expectType: "*objstore.S3",
		},
		{
			name: "s3_config_empty_is_valid",
			input: []byte(`{
				"type": "s3",
			}`),
			expectType: "*objstore.S3",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var blobLoader loader.Loader[BlobLike]
			err := loader.LoadConfig(test.input, &blobLoader)
			assert.NoError(t, err)

			blob, err := blobLoader.Configure()
			assert.NoError(t, err)
			assert.NotNil(t, blob)
			assert.Equal(t, test.expectType, fmt.Sprintf("%T", blob))
		})
	}
}

func TestInvalidConfigs(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
	}{
		{
			name:  "unregistered_type",
			input: []byte(`{"type": "unknown"}`),
		},
		{
			name:  "missing_type",
			input: []byte(`{"account": "test-account"}`),
		},
		{
			name:  "invalid_json",
			input: []byte(`{"type": "r2", "account": `),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var blobLoader loader.Loader[BlobLike]
			err := loader.LoadConfig(test.input, &blobLoader)
			assert.Error(t, err)
		})
	}
}
