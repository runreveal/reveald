//go:generate go tool bpf2go -tags linux -cflags=-fno-builtin processes processes.c

package processes

import (
	"context"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

func init() {
	rlimit.RemoveMemlock()
}

type listener struct {
	objs  processesObjects
	links [2]link.Link
	r     *ringbuf.Reader
	buf   ringbuf.Record
}

func newListener() (*listener, error) {
	l := new(listener)
	if err := loadProcessesObjects(&l.objs, nil); err != nil {
		return nil, fmt.Errorf("load bpf program: %v", err)
	}
	var err error
	l.links[0], err = link.Tracepoint("syscalls", "sys_exit_fork", l.objs.SyscallExitFork, nil)
	if err != nil {
		l.objs.Close()
		return nil, err
	}
	l.links[1], err = link.Tracepoint("syscalls", "sys_enter_execve", l.objs.SyscallEnterExecve, nil)
	if err != nil {
		l.links[0].Close()
		l.objs.Close()
		return nil, err
	}
	l.r, err = ringbuf.NewReader(l.objs.Events)
	if err != nil {
		l.links[1].Close()
		l.links[0].Close()
		l.objs.Close()
		return nil, err
	}
	return l, nil
}

func (l *listener) next(ctx context.Context) (*Event, error) {
	if err := l.r.ReadInto(&l.buf); err != nil {
		return nil, err
	}
	now := time.Now() // Approximate, but eBPF only gives us time since boot.
	if len(l.buf.RawSample) < 17 {
		return nil, fmt.Errorf("result too short (%d bytes)", len(l.buf.RawSample))
	}

	event := &Event{
		Time:       now,
		KernelTime: binary.NativeEndian.Uint64(l.buf.RawSample[:8]),
		PID:        int(binary.NativeEndian.Uint32(l.buf.RawSample[8:12])),
		ParentPID:  int(binary.NativeEndian.Uint32(l.buf.RawSample[12:16])),
	}
	const maxArgLen = 255
	var err error
	event.Program, err = parseCString(l.buf.RawSample[16:])
	if err != nil {
		return nil, fmt.Errorf("program: %v", err)
	}
	for argv := l.buf.RawSample[16+maxArgLen+1:]; len(argv) >= maxArgLen+1; argv = argv[maxArgLen+1:] {
		if argv[0] == 0 && argv[1] == 0xff {
			break
		}
		arg, err := parseCString(argv[:maxArgLen+1])
		if err != nil {
			return nil, fmt.Errorf("argv: %v", err)
		}
		event.Argv = append(event.Argv, arg)
	}
	if event.Program != "" {
		event.Type = ExecEvent
	} else {
		event.Type = ForkEvent
	}
	return event, nil
}

func (l *listener) Close() error {
	var closeErrors [4]error
	closeErrors[0] = l.r.Close()
	closeErrors[1] = l.links[1].Close()
	closeErrors[2] = l.links[0].Close()
	closeErrors[3] = l.objs.Close()
	for _, err := range closeErrors {
		if err != nil {
			return err
		}
	}
	return nil
}

func parseCString(mem []byte) (s string, err error) {
	for n, b := range mem {
		if b == 0 {
			return string(mem[:n]), nil
		}
	}
	return "", fmt.Errorf("missing trailing nul byte")
}
