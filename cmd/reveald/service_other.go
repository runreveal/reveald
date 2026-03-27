//go:build !windows

package main

import "context"

// runService on non-Windows platforms just calls fn directly.
func runService(_ string, fn func(ctx context.Context) error) error {
	return fn(context.Background())
}
