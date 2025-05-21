//go:generate go tool bpf2go -tags linux -cflags=-fno-builtin processes processes.c

package processes

import (
	"context"
	"encoding/binary"
	"fmt"
	"net/netip"
	"path/filepath"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

func init() {
	rlimit.RemoveMemlock()
}

type listener struct {
	objs  processesObjects
	links [3]link.Link
	r     *ringbuf.Reader
	buf   ringbuf.Record
}

func newListener(network bool) (_ *listener, err error) {
	l := new(listener)
	if err := loadProcessesObjects(&l.objs, nil); err != nil {
		return nil, fmt.Errorf("load bpf program: %v", err)
	}
	defer func() {
		if err != nil {
			for i := len(l.links) - 1; i >= 0; i-- {
				if ll := l.links[i]; ll != nil {
					l.links[i].Close()
				}
			}
			l.objs.Close()
		}
	}()

	l.links[0], err = link.Tracepoint("syscalls", "sys_exit_fork", l.objs.SyscallExitFork, nil)
	if err != nil {
		return nil, err
	}
	l.links[1], err = link.Tracepoint("syscalls", "sys_enter_execve", l.objs.SyscallEnterExecve, nil)
	if err != nil {
		return nil, err
	}
	l.links[2], err = link.AttachCgroup(link.CgroupOptions{
		Program: l.objs.SockConnect4,
		Attach:  ebpf.AttachCGroupInet4Connect,
		// TODO(soon): Detect from mountpoints?
		// See https://github.com/cilium/ebpf/blob/49a06b1fe26190a4c2a702932f611c6eff908d3a/examples/cgroup_skb/main.go
		Path: "/sys/fs/cgroup/unified",
	})
	if err != nil {
		return nil, err
	}

	l.r, err = ringbuf.NewReader(l.objs.Events)
	if err != nil {
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
		return nil, fmt.Errorf("tagged data too short (%d bytes)", len(l.buf.RawSample))
	}

	event := &Event{
		Time:       now,
		KernelTime: binary.NativeEndian.Uint64(l.buf.RawSample[:8]),
		PID:        int(binary.NativeEndian.Uint32(l.buf.RawSample[8:12])),
		ParentPID:  int(binary.NativeEndian.Uint32(l.buf.RawSample[12:16])),
	}

	switch tag := l.buf.RawSample[16]; tag {
	case 0: // fork
	case 1: // exec
		if len(l.buf.RawSample) < 18 {
			return nil, fmt.Errorf("exec data too short (%d bytes)", len(l.buf.RawSample))
		}
		event.ExecEvent = new(ExecEvent)
		var err error
		event.ExecEvent.Program, err = parseCString(l.buf.RawSample[18:])
		if err != nil {
			return nil, fmt.Errorf("program: %v", err)
		}

		argc := l.buf.RawSample[17]
		event.ExecEvent.Argv = make([]string, argc)
		var argValue []byte
		for i := range event.ExecEvent.Argv {
			err := l.objs.ExecArgs.LookupAndDelete(execArgKey{
				time: event.KernelTime,
				pid:  uint32(event.PID),
				i:    uint8(i),
			}, &argValue)
			if err != nil {
				return nil, fmt.Errorf("%s: argv[%d]: %v", filepath.Base(event.ExecEvent.Program), i, err)
			}
			event.ExecEvent.Argv[i], err = parseCString(argValue)
			if err != nil {
				return nil, fmt.Errorf("%s: argv[%d]: %v", filepath.Base(event.ExecEvent.Program), i, err)
			}
		}
	case 2: // connect
		if len(l.buf.RawSample) < 35 {
			return nil, fmt.Errorf("connect data too short (%d bytes)", len(l.buf.RawSample))
		}
		addr, _ := netip.AddrFromSlice(l.buf.RawSample[17:33])
		if addr.Is4In6() {
			addr = netip.AddrFrom4(addr.As4())
		}
		port := binary.NativeEndian.Uint16(l.buf.RawSample[33:])
		event.ConnectEvent = &ConnectEvent{
			Address: netip.AddrPortFrom(addr, port),
		}
	default:
		return nil, fmt.Errorf("unknown data tag %#02x", tag)
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

type execArgKey struct {
	time uint64
	pid  uint32
	i    uint8
}

func (key execArgKey) MarshalBinary() ([]byte, error) {
	data := make([]byte, 0, 13)
	data = binary.NativeEndian.AppendUint64(data, key.time)
	data = binary.NativeEndian.AppendUint32(data, key.pid)
	data = append(data, key.i)
	return data, nil
}

func parseCString(mem []byte) (s string, err error) {
	for n, b := range mem {
		if b == 0 {
			return string(mem[:n]), nil
		}
	}
	return "", fmt.Errorf("missing trailing nul byte")
}
