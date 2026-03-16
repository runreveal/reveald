package tetragon

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"time"

	"github.com/runreveal/kawa"
	"github.com/runreveal/reveald/internal/sources/file"
	"github.com/runreveal/reveald/internal/types"
)

type Source struct {
	watcher *file.Watcher
}

func New(watcher *file.Watcher) *Source {
	return &Source{watcher: watcher}
}

func (s *Source) Run(ctx context.Context) error {
	return s.watcher.Run(ctx)
}

func (s *Source) Recv(ctx context.Context) (kawa.Message[types.Event], func(), error) {
	for {
		msg, ack, err := s.watcher.Recv(ctx)
		if err != nil {
			return msg, ack, err
		}

		event, ok := parseEvent(msg.Value)
		if !ok {
			kawa.Ack(ack)
			continue
		}

		msg.Value = event
		return msg, ack, nil
	}
}

func parseEvent(ev types.Event) (types.Event, bool) {
	content, ts, ok := stripK8sWrapper(ev.RawLog)
	if !ok {
		content = string(ev.RawLog)
	}
	if !ts.IsZero() {
		ev.EventTime = ts
	}

	// Must be JSON starting with process_kprobe
	if len(content) == 0 || content[0] != '{' {
		return ev, false
	}

	var raw kprobeEvent
	if err := json.Unmarshal([]byte(content), &raw); err != nil {
		slog.Debug(fmt.Sprintf("tetragon: json parse error: %s", err))
		return ev, false
	}

	kp := raw.ProcessKprobe
	if kp == nil {
		return ev, false
	}

	// Use the event timestamp if available
	if raw.Time != "" {
		if t, err := time.Parse(time.RFC3339Nano, raw.Time); err == nil {
			ev.EventTime = t
		}
	}

	ev.SourceType = "tetragon"
	ev.EventName = kp.FunctionName
	ev.Service = types.Service{Name: processName(kp.Process)}

	// Extract network info from sock_arg
	if sa := firstSockArg(kp.Args); sa != nil {
		if ip, err := netip.ParseAddr(sa.Saddr); err == nil {
			ev.Src = types.Network{IP: ip, Port: uint(sa.Sport)}
		}
		if ip, err := netip.ParseAddr(sa.Daddr); err == nil {
			ev.Dst = types.Network{IP: ip, Port: uint(sa.Dport)}
		}
	}

	// Build tags from pod metadata
	tags := make(map[string]string)
	if kp.PolicyName != "" {
		tags["policyName"] = kp.PolicyName
	}
	if p := kp.Process; p != nil {
		tags["binary"] = p.Binary
		if p.Pod != nil {
			tags["podNamespace"] = p.Pod.Namespace
			tags["podName"] = p.Pod.Name
			if p.Pod.Container != nil {
				tags["container"] = p.Pod.Container.Name
			}
			if p.Pod.Workload != "" {
				tags["workload"] = p.Pod.Workload
			}
		}
	}
	if sa := firstSockArg(kp.Args); sa != nil {
		tags["protocol"] = sa.Protocol
		tags["family"] = sa.Family
	}
	ev.Tags = tags

	// Keep the original Tetragon JSON as rawLog (already clean JSON)
	ev.RawLog = []byte(content)

	return ev, true
}

func processName(p *process) string {
	if p == nil {
		return ""
	}
	// Return just the binary name, not the full path
	parts := strings.Split(p.Binary, "/")
	return parts[len(parts)-1]
}

func firstSockArg(args []arg) *sockArg {
	for _, a := range args {
		if a.SockArg != nil {
			return a.SockArg
		}
	}
	return nil
}

// stripK8sWrapper parses the Kubernetes container log format:
// <timestamp> <stream> <flag> <content>
func stripK8sWrapper(raw []byte) (content string, ts time.Time, ok bool) {
	line := string(raw)
	if len(line) < 32 {
		return "", time.Time{}, false
	}

	i := strings.IndexByte(line, ' ')
	if i < 0 {
		return "", time.Time{}, false
	}
	ts, err := time.Parse(time.RFC3339Nano, line[:i])
	if err != nil {
		return "", time.Time{}, false
	}

	rest := line[i+1:]
	j := strings.Index(rest, " F ")
	if j < 0 {
		j = strings.Index(rest, " P ")
	}
	if j < 0 {
		return "", time.Time{}, false
	}

	return rest[j+3:], ts, true
}

// Tetragon JSON types — only the fields we need.

type kprobeEvent struct {
	ProcessKprobe *processKprobe `json:"process_kprobe"`
	NodeName      string         `json:"node_name"`
	Time          string         `json:"time"`
}

type processKprobe struct {
	Process      *process `json:"process"`
	FunctionName string   `json:"function_name"`
	Args         []arg    `json:"args"`
	Action       string   `json:"action"`
	PolicyName   string   `json:"policy_name"`
}

type process struct {
	ExecID    string `json:"exec_id"`
	PID       int    `json:"pid"`
	Binary    string `json:"binary"`
	Arguments string `json:"arguments"`
	Pod       *pod   `json:"pod"`
}

type pod struct {
	Namespace string     `json:"namespace"`
	Name      string     `json:"name"`
	Container *container `json:"container"`
	Workload  string     `json:"workload"`
}

type container struct {
	Name string `json:"name"`
}

type arg struct {
	SockArg *sockArg `json:"sock_arg,omitempty"`
	IntArg  *int     `json:"int_arg,omitempty"`
}

type sockArg struct {
	Family   string `json:"family"`
	Type     string `json:"type"`
	Protocol string `json:"protocol"`
	Saddr    string `json:"saddr"`
	Daddr    string `json:"daddr"`
	Sport    int    `json:"sport"`
	Dport    int    `json:"dport"`
}
