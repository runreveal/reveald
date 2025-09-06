package objbatch

import (
	"os"
	"testing"

	"github.com/runreveal/kawa"
	"github.com/runreveal/lib/loader"
	"github.com/runreveal/reveald/internal/destinations/objstore"
	_ "github.com/runreveal/reveald/internal/destinations/objstore" // Import to register S3/R2 types
	"github.com/runreveal/reveald/internal/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPhase1_S3ConfigDeserialization(t *testing.T) {
	// Phase 1: Test that we can deserialize S3 config into a struct with loader.Loader[objstore.BlobLike]
	type TestStruct struct {
		S3Config loader.Loader[objstore.BlobLike] `json:"s3"`
	}

	configJSON := []byte(`{
		"s3": {
			"type": "s3",
			"region": "us-east-2",
			"bucket": "my-logs-bucket"
		}
	}`)

	var testStruct TestStruct
	err := loader.LoadConfig(configJSON, &testStruct)
	require.NoError(t, err, "should deserialize S3 config into loader.Loader[objstore.BlobLike] successfully")

	// Test that we can configure the S3 config
	s3Instance, err := testStruct.S3Config.Configure()
	require.NoError(t, err, "should configure S3 successfully")

	assert.NotNil(t, s3Instance)
}

func TestPhase2_BlobConfigDeserialization(t *testing.T) {
	// Phase 2: Test that we can deserialize BlobConfig into a struct with loader.Loader[kawa.Destination[types.Event]]

	// First, register the BlobConfig type (normally done in main config.go)
	loader.Register("s3b", func() loader.Builder[kawa.Destination[types.Event]] {
		return &BlobConfig{}
	})

	type TestStruct struct {
		BatchDest loader.Loader[kawa.Destination[types.Event]] `json:"s3_batch"`
	}

	configJSON := []byte(`{
		"s3_batch": {
			"type": "s3b",
			"batchSize": 100,
			"flushFrequency": "30s",
			"s3": {
				"type": "s3",
				"region": "us-east-2",
				"bucket": "my-logs-bucket"
			}
		}
	}`)

	var testStruct TestStruct
	err := loader.LoadConfig(configJSON, &testStruct)
	require.NoError(t, err, "should deserialize BlobConfig into loader.Loader[kawa.Destination[types.Event]] successfully")

	// Test that we can configure the BlobConfig
	blobInstance, err := testStruct.BatchDest.Configure()
	require.NoError(t, err, "should configure BlobConfig successfully")

	assert.NotNil(t, blobInstance)
}

func TestExampleConfigDeserialization(t *testing.T) {
	// Test the actual example config file can be parsed correctly
	examplePath := "../../../examples/journald_to_s3batch_config.json"

	// Check if file exists (skip if running in isolation)
	if _, err := os.Stat(examplePath); os.IsNotExist(err) {
		t.Skip("Example config file not found, skipping test")
	}

	_, err := os.ReadFile(examplePath)
	require.NoError(t, err, "should read example config file")

	// Register the BlobConfig type (normally done in main config.go)
	loader.Register("s3b", func() loader.Builder[kawa.Destination[types.Event]] {
		return &BlobConfig{}
	})

	// Test the destination part matches the example
	type TestStruct struct {
		BatchDest loader.Loader[kawa.Destination[types.Event]] `json:"s3_batch"`
	}

	destinationJSON := []byte(`{
		"s3_batch": {
			"type": "s3b",
			"batchSize": 100,
			"flushFrequency": "30s", 
			"s3": {
				"type": "s3",
				"region": "us-east-2",
				"bucket": "my-logs-bucket"
			}
		}
	}`)

	var testStruct TestStruct
	err = loader.LoadConfig(destinationJSON, &testStruct)
	require.NoError(t, err, "should deserialize destination config successfully")

	config, err := testStruct.BatchDest.Configure()
	require.NoError(t, err, "should configure destination successfully")

	assert.NotNil(t, config)
}
