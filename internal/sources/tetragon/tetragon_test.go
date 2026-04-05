package tetragon

import (
	"testing"
	"time"

	"github.com/runreveal/reveald/internal/types"
	"github.com/stretchr/testify/require"
)

const sampleUDPSendmsg = `2026-03-15T00:06:32.475152409Z stdout F {"process_kprobe":{"process":{"exec_id":"abc123","pid":50884,"uid":65532,"cwd":"/","binary":"/coredns","arguments":"-conf /etc/coredns/Corefile","flags":"execve","start_time":"2026-03-14T23:59:53Z","pod":{"namespace":"forge","name":"forge-dns","container":{"id":"containerd://abc","name":"dns-logger"},"workload":"forge-dns"}},"parent":{},"function_name":"udp_sendmsg","args":[{"sock_arg":{"family":"AF_INET","type":"SOCK_DGRAM","protocol":"IPPROTO_UDP","saddr":"10.244.0.30","daddr":"10.96.0.10","sport":45729,"dport":53}},{"int_arg":69}],"action":"KPROBE_ACTION_POST","policy_name":"network-monitor"},"node_name":"kubez-control-plane","time":"2026-03-15T00:06:31.621475905Z"}`

const sampleTCPConnect = `2026-03-15T00:06:32.475522327Z stdout F {"process_kprobe":{"process":{"exec_id":"def456","pid":56384,"uid":1000,"cwd":"/home/forge/workspace","binary":"/usr/local/bin/go","arguments":"build -o /tmp/forge-test ./cmd/forge/","flags":"execve","start_time":"2026-03-15T00:06:31Z","pod":{"namespace":"forge","name":"forge-build","container":{"id":"containerd://xyz","name":"forge"},"workload":"forge-build"}},"function_name":"tcp_connect","args":[{"sock_arg":{"family":"AF_INET","type":"SOCK_STREAM","protocol":"IPPROTO_TCP","saddr":"10.244.0.30","daddr":"142.250.80.46","sport":54321,"dport":443}}],"action":"KPROBE_ACTION_POST","policy_name":"network-monitor"},"node_name":"kubez-control-plane","time":"2026-03-15T00:06:31.800000000Z"}`

func TestParseEvent_UDPSendmsg(t *testing.T) {
	ev := types.Event{
		EventTime:  time.Now(),
		SourceType: "file",
		RawLog:     []byte(sampleUDPSendmsg),
	}

	got, ok := parseEvent(ev)
	require.True(t, ok)
	require.Equal(t, "tetragon", got.SourceType)
	require.Equal(t, "udp_sendmsg", got.EventName)
	require.Equal(t, "coredns", got.Service.Name)

	require.Equal(t, "10.244.0.30", got.Src.IP.String())
	require.Equal(t, uint(45729), got.Src.Port)
	require.Equal(t, "10.96.0.10", got.Dst.IP.String())
	require.Equal(t, uint(53), got.Dst.Port)

	require.Equal(t, "network-monitor", got.Tags["policyName"])
	require.Equal(t, "/coredns", got.Tags["binary"])
	require.Equal(t, "forge", got.Tags["podNamespace"])
	require.Equal(t, "forge-dns", got.Tags["podName"])
	require.Equal(t, "dns-logger", got.Tags["container"])
	require.Equal(t, "IPPROTO_UDP", got.Tags["protocol"])

	// EventTime should be from the Tetragon event time
	expected, _ := time.Parse(time.RFC3339Nano, "2026-03-15T00:06:31.621475905Z")
	require.Equal(t, expected, got.EventTime)
}

func TestParseEvent_TCPConnect(t *testing.T) {
	ev := types.Event{
		EventTime:  time.Now(),
		SourceType: "file",
		RawLog:     []byte(sampleTCPConnect),
	}

	got, ok := parseEvent(ev)
	require.True(t, ok)
	require.Equal(t, "tetragon", got.SourceType)
	require.Equal(t, "tcp_connect", got.EventName)
	require.Equal(t, "go", got.Service.Name)

	require.Equal(t, "10.244.0.30", got.Src.IP.String())
	require.Equal(t, uint(54321), got.Src.Port)
	require.Equal(t, "142.250.80.46", got.Dst.IP.String())
	require.Equal(t, uint(443), got.Dst.Port)
}

func TestParseEvent_SkipsNonKprobe(t *testing.T) {
	tests := []struct {
		name string
		raw  string
	}{
		{
			name: "plain text log",
			raw:  `2026-03-15T22:07:38.691246Z stdout F I0315 22:07:38.691246       1 main.go:297] Handling node`,
		},
		{
			name: "non-json",
			raw:  `2026-03-15T22:07:38.691246Z stdout F not json at all`,
		},
		{
			name: "json without process_kprobe",
			raw:  `2026-03-15T00:00:00Z stdout F {"process_exec":{"process":{"binary":"/bin/bash"}}}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev := types.Event{RawLog: []byte(tt.raw)}
			_, ok := parseEvent(ev)
			require.False(t, ok)
		})
	}
}

func TestStripK8sWrapper(t *testing.T) {
	raw := `2026-03-15T00:06:32.475152409Z stdout F {"some":"json"}`
	content, ts, ok := stripK8sWrapper([]byte(raw))
	require.True(t, ok)
	require.Equal(t, `{"some":"json"}`, content)
	require.False(t, ts.IsZero())
}

func TestProcessName(t *testing.T) {
	tests := []struct {
		binary string
		want   string
	}{
		{"/usr/local/bin/go", "go"},
		{"/coredns", "coredns"},
		{"binary", "binary"},
	}
	for _, tt := range tests {
		got := processName(&process{Binary: tt.binary})
		require.Equal(t, tt.want, got)
	}
	require.Equal(t, "", processName(nil))
}
