package objstore

import (
	"bytes"
	"context"
	"io"
	"math/rand"
	"strconv"
	"testing"

	"github.com/segmentio/ksuid"
	"github.com/stretchr/testify/assert"
)

func TestS3DataStoreStream(t *testing.T) {
	t.Skip("local test only, requires aws credentials")
	ctx := context.Background()

	s3, err := NewS3(S3Config{})
	assert.NoError(t, err, "should not error on s3 init")

	objmgr, err := New(s3)
	assert.NoError(t, err, "should not error on s3 init")

	wkspID := "12345-go_test"
	key := ksuid.New().String()

	// Create a pipe to connect the writer and the S3 uploader
	pr, pw := io.Pipe()

	// Generate >10M of random data to write
	data := bytes.NewBuffer(nil)
	for i := 0; i < 10_000_000; i++ {
		_, _ = data.WriteString(strconv.Itoa(rand.Intn(10000)))
	}
	bts := make([]byte, data.Len())
	copy(bts, data.Bytes())

	// Start a goroutine that sends data to S3
	go func() {
		for i := 0; i < 25_000_000; i += 1_000_000 {
			_, err := pw.Write(bts[i : i+1_000_000])
			assert.NoError(t, err, "should not error on write")
			// fmt.Println("wrote 1M data")
		}
		err := pw.Close()
		assert.NoError(t, err, "should not error on close")
	}()

	err = objmgr.Store(ctx, wkspID, "pfpwfpwwpfwp", key, pr)
	assert.NoError(t, err, "should not error on store")

	t.Log("finished uploading.")

	actualData, err := objmgr.ReadAll(ctx, wkspID, "pfpwfpwwpfwp", key)

	assert.NoError(t, err, "should not error on fetch")
	assert.Equal(t, 25_000_000, len(actualData), "s3 data should match expected")
}
