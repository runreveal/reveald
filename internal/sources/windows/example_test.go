package windows_test

import (
	"context"
	"log"

	"github.com/runreveal/reveald/internal/sources/windows"
)

func ExampleEventLogSource() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Open an event log source that matches successful interactive logon events.
	source, err := windows.NewEventLogSource(&windows.Options{
		Channel: "Security",
		Query:   "*[EventData[Data[@Name='LogonType']='2'] and System[(EventID=4624)]]",
	})
	if err != nil {
		log.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := source.Run(ctx); err != nil {
			log.Print(err)
		}
	}()
	defer func() {
		cancel()
		<-done
	}()

	for {
		// Wait for next message.
		msg, ack, err := source.Recv(ctx)
		if err != nil {
			log.Print(err)
			break
		}

		// Do something with msg.
		_ = msg
		ack()
	}
}
