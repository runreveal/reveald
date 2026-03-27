//go:build windows

package main

import (
	"context"
	"fmt"
	"log/slog"

	"golang.org/x/sys/windows/svc"
)

// runService detects whether the process is running as a Windows service.
// If so, it runs fn under the Service Control Manager. Otherwise it calls
// fn directly with a background context (normal interactive mode).
func runService(serviceName string, fn func(ctx context.Context) error) error {
	isService, err := svc.IsWindowsService()
	if err != nil {
		return fmt.Errorf("detecting service mode: %w", err)
	}
	if !isService {
		return fn(context.Background())
	}

	slog.Info("running as Windows service", "service", serviceName)
	return svc.Run(serviceName, &serviceHandler{fn: fn})
}

type serviceHandler struct {
	fn func(ctx context.Context) error
}

func (h *serviceHandler) Execute(
	args []string,
	r <-chan svc.ChangeRequest,
	s chan<- svc.Status,
) (svcSpecificEC bool, exitCode uint32) {
	s <- svc.Status{State: svc.StartPending}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- h.fn(ctx)
	}()

	s <- svc.Status{
		State:   svc.Running,
		Accepts: svc.AcceptStop | svc.AcceptShutdown,
	}

	for {
		select {
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				s <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				s <- svc.Status{State: svc.StopPending}
				cancel()
				<-done
				return false, 0
			}
		case err := <-done:
			if err != nil {
				slog.Error("service exited with error", "err", err)
				return true, 1
			}
			return false, 0
		}
	}
}
