package net

import (
	"context"
	"encoding/binary"
	"fmt"
	"net/netip"
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
	objs netObjects
	link link.Link
	r    *ringbuf.Reader
	buf  ringbuf.Record
}

func newListener() (*listener, error) {
	l := new(listener)
	if err := loadNetObjects(&l.objs, nil); err != nil {
		return nil, fmt.Errorf("load bpf program: %v", err)
	}
	var err error
	l.link, err = link.AttachCgroup(link.CgroupOptions{
		// Program: l.objs.SockBind4,
		// Attach:  ebpf.AttachCGroupInet4PostBind,
		Program: l.objs.SockConnect4,
		Attach:  ebpf.AttachCGroupInet4Connect,
		// TODO(soon): Detect from mountpoints?
		// See https://github.com/cilium/ebpf/blob/49a06b1fe26190a4c2a702932f611c6eff908d3a/examples/cgroup_skb/main.go
		Path: "/sys/fs/cgroup/unified",
	})
	if err != nil {
		l.objs.Close()
		return nil, err
	}
	l.r, err = ringbuf.NewReader(l.objs.Connections)
	if err != nil {
		l.link.Close()
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
	if len(l.buf.RawSample) < 22 {
		return nil, fmt.Errorf("result too short (%d bytes)", len(l.buf.RawSample))
	}
	pid := binary.NativeEndian.Uint32(l.buf.RawSample[:4])
	addr, _ := netip.AddrFromSlice(l.buf.RawSample[4:20])
	if addr.Is4In6() {
		addr = netip.AddrFrom4(addr.As4())
	}
	port := binary.NativeEndian.Uint16(l.buf.RawSample[20:22])
	return &Event{
		Time:    now,
		PID:     int(pid),
		Address: netip.AddrPortFrom(addr, port),
	}, nil
}

func (l *listener) Close() error {
	var closeErrors [3]error
	closeErrors[0] = l.r.Close()
	closeErrors[1] = l.link.Close()
	closeErrors[2] = l.objs.Close()
	for _, err := range closeErrors {
		if err != nil {
			return err
		}
	}
	return nil
}
