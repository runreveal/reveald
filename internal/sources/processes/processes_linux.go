//go:generate go tool bpf2go -tags linux -cflags=-fno-builtin processes processes.c

package processes

import (
	"context"
	"encoding/binary"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
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
	links [4]link.Link
	r     *ringbuf.Reader
	buf   ringbuf.Record

	processes map[int]processInfo
}

func newListener(network bool) (_ *listener, err error) {
	l := &listener{
		processes: make(map[int]processInfo),
	}
	if err := loadProcessesObjects(&l.objs, nil); err != nil {
		return nil, fmt.Errorf("load bpf program: %v", err)
	}
	defer func() {
		if err != nil {
			l.Close()
		}
	}()

	l.links[0], err = link.Tracepoint("sched", "sched_process_fork", l.objs.SchedProcessFork, nil)
	if err != nil {
		return nil, err
	}
	l.links[1], err = link.Tracepoint("syscalls", "sys_enter_execve", l.objs.SyscallEnterExecve, nil)
	if err != nil {
		return nil, err
	}
	l.links[2], err = link.Tracepoint("sched", "sched_process_exit", l.objs.SchedProcessExit, nil)
	if err != nil {
		return nil, err
	}
	if network {
		l.links[3], err = link.AttachCgroup(link.CgroupOptions{
			Program: l.objs.SockConnect4,
			Attach:  ebpf.AttachCGroupInet4Connect,
			// TODO(soon): Detect from mountpoints?
			// See https://github.com/cilium/ebpf/blob/49a06b1fe26190a4c2a702932f611c6eff908d3a/examples/cgroup_skb/main.go
			Path: "/sys/fs/cgroup/unified",
		})
		if err != nil {
			return nil, err
		}
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
		event.ForkEvent = new(ForkEvent)
		parentInfo, ok := l.processes[event.ParentPID]
		if !ok {
			// If the parent process isn't found, it's likely from before the trace started.
			// Make an attempt to read the process info from /proc,
			// but if it fails, don't block the event.
			var err error
			parentInfo, err = readProcessInfoFromProc(event.ParentPID)
			if err == nil {
				l.processes[event.ParentPID] = parentInfo
			}
		}
		event.Program = parentInfo.program
		event.Argv = slices.Clone(parentInfo.argv)
		l.processes[event.PID] = parentInfo
	case 1: // exec
		if len(l.buf.RawSample) < 18 {
			return nil, fmt.Errorf("exec data too short (%d bytes)", len(l.buf.RawSample))
		}
		event.ExecEvent = new(ExecEvent)
		var err error
		event.Program, err = parseCString(l.buf.RawSample[18:])
		if err != nil {
			return nil, fmt.Errorf("program: %v", err)
		}

		argc := l.buf.RawSample[17]
		event.Argv = make([]string, argc)
		var argValue []byte
		for i := range event.Argv {
			err := l.objs.ExecArgs.LookupAndDelete(execArgKey{
				time: event.KernelTime,
				pid:  uint32(event.PID),
				i:    uint8(i),
			}, &argValue)
			if err != nil {
				return nil, fmt.Errorf("%s: argv[%d]: %v", filepath.Base(event.Program), i, err)
			}
			event.Argv[i], err = parseCString(argValue)
			if err != nil {
				return nil, fmt.Errorf("%s: argv[%d]: %v", filepath.Base(event.Program), i, err)
			}
		}
		l.processes[event.PID] = processInfo{
			program: event.Program,
			argv:    slices.Clone(event.Argv),
		}
	case 2: // exit
		if len(l.buf.RawSample) < 22 {
			return nil, fmt.Errorf("exec data too short (%d bytes)", len(l.buf.RawSample))
		}
		info := l.processes[event.PID]
		delete(l.processes, event.PID)
		event.Program = info.program
		event.Argv = info.argv
		event.ExitEvent = &ExitEvent{
			Code: int(binary.NativeEndian.Uint32(l.buf.RawSample[17:])),
		}
	case 3: // connect
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
	var closeErrors [len(l.links) + 1]error
	for i := range l.links {
		if ll := l.links[len(l.links)-i-1]; ll != nil {
			closeErrors[i] = ll.Close()
			l.links[len(l.links)-i-1] = nil
		}
	}
	closeErrors[len(closeErrors)-1] = l.objs.Close()
	for _, err := range closeErrors {
		if err != nil {
			return err
		}
	}
	l.processes = nil
	return nil
}

type processInfo struct {
	program string
	argv    []string
}

func readProcessInfoFromProc(pid int) (processInfo, error) {
	var info processInfo
	var err error
	info.program, err = os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return processInfo{}, fmt.Errorf("query process %d info: %v", pid, err)
	}
	argv, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return processInfo{}, fmt.Errorf("query process %d info: %v", pid, err)
	}
	info.argv = strings.Split(string(argv), "\x00")
	// Strip trailing NUL split.
	if info.argv[len(info.argv)-1] == "" {
		info.argv = info.argv[:len(info.argv)-1]
	}
	return info, nil
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
