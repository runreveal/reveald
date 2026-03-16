package coredns

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/runreveal/kawa"
	"github.com/runreveal/reveald/internal/sources/file"
	"github.com/runreveal/reveald/internal/types"
)

// CoreDNS log format (from the log plugin):
// [INFO] <client_ip>:<client_port> - <query_id> "<qtype> IN <qname> <proto> <query_size> <do_bit> <bufsize>" <rcode> <flags> <rsize> <duration>
var logRe = regexp.MustCompile(
	`^\[INFO\] (\S+):(\d+) - (\d+) "(\S+) IN (\S+) (\S+) (\d+) (\S+) (\d+)" (\S+) (\S+) (\d+) ([\d.]+\S+)$`,
)

// DNSQuery is the structured representation of a CoreDNS log line.
type DNSQuery struct {
	ClientIP   string `json:"clientIP"`
	ClientPort int    `json:"clientPort"`
	QueryID    int    `json:"queryID"`
	QueryType  string `json:"queryType"`
	QueryName  string `json:"queryName"`
	Protocol   string `json:"protocol"`
	QuerySize  int    `json:"querySize"`
	DNSSEC     bool   `json:"dnssec"`
	BufSize    int    `json:"bufSize"`
	Rcode      string `json:"rcode"`
	Flags      string `json:"flags"`
	RespSize   int    `json:"respSize"`
	Duration   string `json:"duration"`
}

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

	q, err := parseLogLine(content)
	if err != nil {
		slog.Debug(fmt.Sprintf("coredns: skipping non-query line: %s", content))
		return ev, false
	}

	raw, err := json.Marshal(q)
	if err != nil {
		slog.Error(fmt.Sprintf("coredns: marshal error: %s", err))
		return ev, false
	}

	ev.SourceType = "coredns"
	ev.EventName = "dns_query"
	ev.Service = types.Service{Name: "coredns"}
	ev.RawLog = raw

	if ip, err := netip.ParseAddr(q.ClientIP); err == nil {
		ev.Src = types.Network{IP: ip, Port: uint(q.ClientPort)}
	}

	ev.Tags = map[string]string{
		"queryType": q.QueryType,
		"queryName": q.QueryName,
		"rcode":     q.Rcode,
		"protocol":  q.Protocol,
	}

	return ev, true
}

func parseLogLine(line string) (*DNSQuery, error) {
	m := logRe.FindStringSubmatch(line)
	if m == nil {
		return nil, fmt.Errorf("no match")
	}

	clientPort, _ := strconv.Atoi(m[2])
	queryID, _ := strconv.Atoi(m[3])
	querySize, _ := strconv.Atoi(m[7])
	bufSize, _ := strconv.Atoi(m[9])
	respSize, _ := strconv.Atoi(m[12])

	return &DNSQuery{
		ClientIP:   m[1],
		ClientPort: clientPort,
		QueryID:     queryID,
		QueryType:   m[4],
		QueryName:   m[5],
		Protocol:    m[6],
		QuerySize:   querySize,
		DNSSEC:      m[8] == "true",
		BufSize:     bufSize,
		Rcode:       m[10],
		Flags:       m[11],
		RespSize:    respSize,
		Duration:    m[13],
	}, nil
}

// stripK8sWrapper parses the Kubernetes container log format:
// <timestamp> <stream> <flag> <content>
func stripK8sWrapper(raw []byte) (content string, ts time.Time, ok bool) {
	line := string(raw)
	// Minimum: "2006-01-02T15:04:05Z stdout F x"
	if len(line) < 32 {
		return "", time.Time{}, false
	}

	// Find first space (end of timestamp)
	i := strings.IndexByte(line, ' ')
	if i < 0 {
		return "", time.Time{}, false
	}
	ts, err := time.Parse(time.RFC3339Nano, line[:i])
	if err != nil {
		return "", time.Time{}, false
	}

	// Skip "<stream> <flag> "
	rest := line[i+1:]
	// Find "F " or "P " flag
	j := strings.Index(rest, " F ")
	if j < 0 {
		j = strings.Index(rest, " P ")
	}
	if j < 0 {
		return "", time.Time{}, false
	}

	return rest[j+3:], ts, true
}
