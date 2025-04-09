//go:build windows
// +build windows

package windows

import (
	"fmt"
	"runtime/cgo"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	// EvtSubscribeToFutureEvents instructs the
	// subscription to only receive events that occur
	// after the subscription has been made
	evtSubscribeToFutureEvents = 1

	// EvtSubscribeStartAtOldestRecord instructs the
	// subscription to receive all events (past and future)
	// that match the query
	evtSubscribeStartAtOldestRecord = 2

	// evtSubscribeActionError defines a action
	// code that may be received by the winAPICallback.
	// ActionError defines that an internal error occurred
	// while obtaining an event for the callback
	evtSubscribeActionError = 0

	// evtSubscribeActionDeliver defines a action
	// code that may be received by the winAPICallback.
	// ActionDeliver defines that the internal API was
	// successful in obtaining an event that matched
	// the subscription query
	evtSubscribeActionDeliver = 1

	// evtRenderEventXML instructs procEvtRender
	// to render the event details as a XML string
	evtRenderEventXML = 1
)

var (
	modwevtapi  = windows.NewLazySystemDLL("wevtapi.dll")
	modadvapi32 = windows.NewLazySystemDLL("advapi32.dll")

	// https://learn.microsoft.com/en-us/windows/win32/api/winevt/nf-winevt-evtsubscribe
	procEvtSubscribe = modwevtapi.NewProc("EvtSubscribe")
	// https://learn.microsoft.com/en-us/windows/win32/api/winevt/nf-winevt-evtrender
	procEvtRender = modwevtapi.NewProc("EvtRender")
	// https://learn.microsoft.com/en-us/windows/win32/api/winevt/nf-winevt-evtclose
	procEvtClose = modwevtapi.NewProc("EvtClose")

	// https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-registereventsourcew
	procRegisterEventSource = modadvapi32.NewProc("RegisterEventSourceW")
	// https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-deregistereventsource
	procDeregisterEventSource = modadvapi32.NewProc("DeregisterEventSource")
	// https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-reporteventw
	procReportEvent = modadvapi32.NewProc("ReportEventW")

	cbSubscribe = windows.NewCallback(subscribeCallback)
)

// eventSubscription is a subscription to
// Windows Events, it defines details about the
// subscription including the channel and query
type eventSubscription struct {
	handle  windows.Handle
	onEvent xmlEventFunc
	onError errorFunc
}

func newEventSubscription(opts *Options, onEvent xmlEventFunc, onError errorFunc) (*eventSubscription, error) {
	winChannel, err := windows.UTF16PtrFromString(opts.Channel)
	if err != nil {
		return nil, fmt.Errorf("windows_events: bad channel name: %s", err)
	}

	winQuery, err := windows.UTF16PtrFromString(opts.Query)
	if err != nil {
		return nil, fmt.Errorf("windows_events: bad query string: %s", err)
	}

	evtSub := &eventSubscription{
		onEvent: onEvent,
		onError: onError,
	}

	handle, _, err := procEvtSubscribe.Call(
		0,
		0,
		uintptr(unsafe.Pointer(winChannel)),
		uintptr(unsafe.Pointer(winQuery)),
		0,
		uintptr(cgo.NewHandle(evtSub)),
		cbSubscribe,
		uintptr(evtSubscribeToFutureEvents),
	)
	if handle == 0 {
		return nil, fmt.Errorf("windows_events: failed to subscribe to events: %v", err)
	}

	evtSub.handle = windows.Handle(handle)
	return evtSub, nil
}

// Close releases resources associated with the subscription.
func (evtSub *eventSubscription) Close() error {
	if returnCode, _, err := procEvtClose.Call(uintptr(evtSub.handle)); returnCode == 0 {
		return fmt.Errorf("windows_events: encountered error while closing event handle: %s", err)
	}
	return nil
}

// subscribeCallback receives the callback from the windows
// kernel when an event matching the query and channel is
// received. It will query the kernel to get the event rendered
// as a XML string, the XML string is then unmarshaled to an
// `Event` and the custom callback invoked
func subscribeCallback(action, userContext, event uintptr) uintptr {
	evtSub := cgo.Handle(userContext).Value().(*eventSubscription)

	switch action {
	case evtSubscribeActionError:
		evtSub.onError(fmt.Errorf("windows_events: encountered error during callback: Win32 Error %x", uint16(event)))
	case evtSubscribeActionDeliver:
		renderSpace := make([]uint16, 4096)
		bufferUsed := uint32(0)
		propertyCount := uint32(0)

		returnCode, _, err := procEvtRender.Call(
			0,
			event,
			evtRenderEventXML,
			uintptr(len(renderSpace)*2),
			uintptr(unsafe.Pointer(&renderSpace[0])),
			uintptr(unsafe.Pointer(&bufferUsed)),
			uintptr(unsafe.Pointer(&propertyCount)),
		)
		if returnCode == 0 {
			evtSub.onError(fmt.Errorf("windows_event: failed to render event data: %v", err))
			return 0
		}

		evtSub.onEvent(utf16ToUTF8(renderSpace[:bufferUsed/2]))
	default:
		evtSub.onError(fmt.Errorf("windows_events: unknown callback action code %#x", action))
	}

	return 0
}

func reportInfoEvent(sourceName string, category uint16, eventID uint32, messages []string) error {
	lpSourceName, err := windows.UTF16PtrFromString(sourceName)
	if err != nil {
		return fmt.Errorf("report event: source name: %v", err)
	}
	eventLogHandle, _, err := procRegisterEventSource.Call(0, uintptr(unsafe.Pointer(lpSourceName)))
	if eventLogHandle == 0 {
		return fmt.Errorf("report event: %v", err)
	}
	defer procDeregisterEventSource.Call(eventLogHandle)

	if len(messages) == 0 {
		ok, _, err := procReportEvent.Call(
			eventLogHandle,
			0x0004, // information event
			uintptr(category),
			uintptr(eventID),
			0, // lpUserSid
			0, // wNumStrings
			0, // dwDataSize
			0, // lpStrings,
			0, // lpRawData,
		)
		if ok == 0 {
			return fmt.Errorf("report event: %v", err)
		}
		return nil
	}

	wcharMessages := make([]*uint16, len(messages))
	for i, msg := range messages {
		var err error
		wcharMessages[i], err = windows.UTF16PtrFromString(msg)
		if err != nil {
			return fmt.Errorf("report event: message: %v", err)
		}
	}

	ok, _, err := procReportEvent.Call(
		eventLogHandle,
		0x0004, // information event
		uintptr(category),
		uintptr(eventID),
		0, // lpUserSid
		uintptr(len(messages)),
		0, // dwDataSize
		uintptr(unsafe.Pointer(&wcharMessages[0])),
		0, // lpRawData
	)
	if ok == 0 {
		return fmt.Errorf("report event: %v", err)
	}
	return nil
}
