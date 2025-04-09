package windows

import (
	"context"
	"runtime"
	"slices"
	"testing"
)

func TestEventLogSource(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skipf("cannot run test on %s", runtime.GOOS)
	}

	source, err := NewEventLogSource(&Options{
		Channel: "Application",
		Query:   "*[System[(EventID=3001)]]",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := source.Close(); err != nil {
			t.Error("Close:", err)
		}
	}()

	const message = "Hello, World!"
	ch := make(chan error, 1)
	go func() {
		ch <- reportInfoEvent("RevealdEventLogTest", 1, 3001, []string{message})
	}()

	got, ack, err := source.Recv(context.Background())
	if err != nil {
		t.Fatal("Recv:", err)
	}
	defer ack()

	if got, want := got.Value.System.EventID, "3001"; got != want {
		t.Errorf("System.EventID = %q; want %q", got, want)
	}
	if got, want := got.Value.EventData, []string{message}; !slices.Equal(got, want) {
		t.Errorf("EventData = %q; want %q", got, want)
	}
}
