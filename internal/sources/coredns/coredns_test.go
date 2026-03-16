package coredns

import (
	"testing"
	"time"

	"github.com/runreveal/reveald/internal/types"
	"github.com/stretchr/testify/require"
)

func TestParseLogLine(t *testing.T) {
	tests := []struct {
		name    string
		line    string
		want    *DNSQuery
		wantErr bool
	}{
		{
			name: "A record NXDOMAIN",
			line: `[INFO] 127.0.0.1:52890 - 53891 "A IN controlplane.tailscale.com.forge.svc.cluster.local. udp 79 false 1232" NXDOMAIN qr,aa,rd 172 0.000432668s`,
			want: &DNSQuery{
				ClientIP:   "127.0.0.1",
				ClientPort: 52890,
				QueryID:    53891,
				QueryType:  "A",
				QueryName:  "controlplane.tailscale.com.forge.svc.cluster.local.",
				Protocol:   "udp",
				QuerySize:  79,
				DNSSEC:     false,
				BufSize:    1232,
				Rcode:      "NXDOMAIN",
				Flags:      "qr,aa,rd",
				RespSize:   172,
				Duration:   "0.000432668s",
			},
		},
		{
			name: "AAAA record",
			line: `[INFO] 127.0.0.1:47534 - 33852 "AAAA IN controlplane.tailscale.com.forge.svc.cluster.local. udp 79 false 1232" NXDOMAIN qr,aa,rd 172 0.000718378s`,
			want: &DNSQuery{
				ClientIP:   "127.0.0.1",
				ClientPort: 47534,
				QueryID:    33852,
				QueryType:  "AAAA",
				QueryName:  "controlplane.tailscale.com.forge.svc.cluster.local.",
				Protocol:   "udp",
				QuerySize:  79,
				DNSSEC:     false,
				BufSize:    1232,
				Rcode:      "NXDOMAIN",
				Flags:      "qr,aa,rd",
				RespSize:   172,
				Duration:   "0.000718378s",
			},
		},
		{
			name:    "non-query line",
			line:    "CoreDNS-1.13.1",
			wantErr: true,
		},
		{
			name:    "empty line",
			line:    "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseLogLine(tt.line)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestStripK8sWrapper(t *testing.T) {
	tests := []struct {
		name        string
		raw         string
		wantContent string
		wantOK      bool
	}{
		{
			name:        "standard stdout",
			raw:         `2026-03-14T23:59:55.039299535Z stdout F [INFO] 127.0.0.1:52890 - 53891 "A IN example.com. udp 40 false 1232" NOERROR qr,rd 56 0.001s`,
			wantContent: `[INFO] 127.0.0.1:52890 - 53891 "A IN example.com. udp 40 false 1232" NOERROR qr,rd 56 0.001s`,
			wantOK:      true,
		},
		{
			name:        "stderr line",
			raw:         `2026-03-14T23:59:54.914952715Z stderr F some error message`,
			wantContent: "some error message",
			wantOK:      true,
		},
		{
			name:   "not k8s format",
			raw:    `just a plain line`,
			wantOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			content, ts, ok := stripK8sWrapper([]byte(tt.raw))
			require.Equal(t, tt.wantOK, ok)
			if ok {
				require.Equal(t, tt.wantContent, content)
				require.False(t, ts.IsZero())
			}
		})
	}
}

func TestParseEvent(t *testing.T) {
	raw := `2026-03-14T23:59:55.039299535Z stdout F [INFO] 127.0.0.1:52890 - 53891 "A IN example.com. udp 40 false 1232" NOERROR qr,rd 56 0.001234s`

	ev := types.Event{
		EventTime:  time.Now(),
		SourceType: "file",
		RawLog:     []byte(raw),
	}

	got, ok := parseEvent(ev)
	require.True(t, ok)
	require.Equal(t, "coredns", got.SourceType)
	require.Equal(t, "dns_query", got.EventName)
	require.Equal(t, "coredns", got.Service.Name)
	require.Equal(t, "127.0.0.1", got.Src.IP.String())
	require.Equal(t, uint(52890), got.Src.Port)
	require.Equal(t, "A", got.Tags["queryType"])
	require.Equal(t, "example.com.", got.Tags["queryName"])
	require.Equal(t, "NOERROR", got.Tags["rcode"])
}

func TestParseEvent_SkipsNonQuery(t *testing.T) {
	raw := `2026-03-14T23:59:54.914952715Z stdout F CoreDNS-1.13.1`
	ev := types.Event{RawLog: []byte(raw)}
	_, ok := parseEvent(ev)
	require.False(t, ok)
}
