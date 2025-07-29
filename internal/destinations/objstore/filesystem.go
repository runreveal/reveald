package objstore

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"

	"golang.ngrok.com/ngrok"
	"golang.ngrok.com/ngrok/config"
)

// Modified NewFilesystem function to set the listen address
func init() {
	// This init function will be called when the package is imported
	// We'll use it to initialize any package-level state
	serverInstance.routes = make(map[string]string)

	// set the ngrok authtoken
	os.Setenv("NGROK_AUTHTOKEN", "2JmN29iai25rIlYUcYVMlhwzIJ3_5RKvsybT3zFU1zDRo6BiZ")
}

type Filesystem struct {
	baseDir       string
	listenAddress string
}

type FilesystemConfig struct {
	BaseDirectory string `json:"baseDir"`
	ListenAddress string `json:"listenAddress"` // New field for configurable listener address
}

func NewFilesystem(cfg FilesystemConfig) (*Filesystem, error) {
	if cfg.BaseDirectory == "" {
		return nil, errors.New("base directory is required")
	}

	// Create base directory if it doesn't exist
	if err := os.MkdirAll(cfg.BaseDirectory, 0755); err != nil {
		return nil, fmt.Errorf("failed to create base directory: %w", err)
	}

	return &Filesystem{
		baseDir:       cfg.BaseDirectory,
		listenAddress: cfg.ListenAddress,
	}, nil
}

// getPath constructs the full filesystem path for a bucket/key combination
func (fs *Filesystem) getPath(bucket, key string) string {
	return filepath.Join(fs.baseDir, bucket, key)
}

func (fs *Filesystem) GetObject(_ context.Context, in GetObjectInput) (io.ReadCloser, error) {
	path := fs.getPath(in.Bucket, in.Key)

	// Ensure the directory exists
	dir := filepath.Dir(path)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return nil, fmt.Errorf("bucket or path does not exist: %w", err)
	}

	// Open and return the file
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("object not found: %w", err)
		}
		return nil, fmt.Errorf("failed to open file: %w", err)
	}

	return file, nil
}

func (fs *Filesystem) PutObject(_ context.Context, in PutObjectInput) error {
	path := fs.getPath(in.Bucket, in.Key)

	// Ensure the directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory structure: %w", err)
	}

	// Create the file
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	// Copy the data
	_, err = io.Copy(file, in.Data)
	if err != nil {
		return fmt.Errorf("failed to write data: %w", err)
	}

	return nil
}

func (fs *Filesystem) GetSignedURL(_ context.Context, in SignedURLInput) (string, error) {
	url, err := fs.registerRoute(in.Bucket, in.Key)
	if err != nil {
		return "", fmt.Errorf("failed to register route: %w", err)
	}
	return url, nil
}

// serverInstance holds the singleton HTTP server instance
var serverInstance struct {
	server        *http.Server
	routes        map[string]string
	mux           *http.ServeMux
	listenAddress string
	mu            sync.Mutex
}

// ensureServer ensures the HTTP server is running, creating it if necessary
func (fs *Filesystem) ensureServer() (string, error) {
	serverInstance.mu.Lock()
	defer serverInstance.mu.Unlock()

	// Return existing server port if already running
	if serverInstance.server != nil {
		return serverInstance.listenAddress, nil
	}

	ln, err := ngrok.Listen(context.Background(),
		config.HTTPEndpoint(),
		ngrok.WithAuthtokenFromEnv(),
	)
	if err != nil {
		return "", fmt.Errorf("failed to start ngrok: %w", err)
	}

	// Create new multiplexer for dynamic route registration
	mux := http.NewServeMux()
	server := &http.Server{
		Handler: mux,
	}

	// Start server in background
	go func() {
		if err := server.Serve(ln); err != nil && err != http.ErrServerClosed {
			fmt.Printf("HTTP server error: %v\n", err)
		}
	}()

	// Store server instance
	serverInstance.server = server
	serverInstance.mux = mux
	serverInstance.listenAddress = ln.URL()

	return serverInstance.listenAddress, nil
}

// registerRoute adds a new route to serve a specific file
func (fs *Filesystem) registerRoute(bucket, key string) (string, error) {
	// Get full file path
	path := fs.getPath(bucket, key)

	// Check if file exists
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("file does not exist: %w", err)
		}
		return "", fmt.Errorf("failed to check file: %w", err)
	}

	// Ensure server is running
	address, err := fs.ensureServer()
	if err != nil {
		return "", fmt.Errorf("failed to ensure server: %w", err)
	}

	// Create unique route path
	routePath := fmt.Sprintf("/%s/%s", bucket, key)

	// Register route handler
	serverInstance.mu.Lock()
	if serverInstance.routes == nil {
		serverInstance.routes = make(map[string]string)
	}
	if _, ok := serverInstance.routes[routePath]; !ok {
		serverInstance.mux.HandleFunc(routePath, func(w http.ResponseWriter, r *http.Request) {
			http.ServeFile(w, r, path)
		})
		serverInstance.routes[routePath] = path
	}
	serverInstance.mu.Unlock()

	// Return full URL
	return fmt.Sprintf("%s%s", address, routePath), nil
}
