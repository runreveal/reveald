package internal

import (
	"os"
	"path/filepath"
)

func ConfigDir() string {
	cfg := filepath.Join(os.TempDir(), "reveald")
	// check if the directory exists
	_, err := os.Stat(cfg)
	if os.IsNotExist(err) {
		// create the directory, let the error bubble up
		// where this directory is used if it fails.
		_ = os.MkdirAll(cfg, 0744)
	}
	return cfg
}
