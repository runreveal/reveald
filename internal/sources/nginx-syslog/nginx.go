package nginx_syslog

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"time"

	"log/slog"

	"github.com/runreveal/kawa"
	"github.com/runreveal/lib/await"
	"github.com/runreveal/reveald/internal/types"
	"gopkg.in/mcuadros/go-syslog.v2"
)

type NginxSyslogCfg struct {
	Addr string `json:"addr"`
}

type NginxSyslogSource struct {
	cfg          NginxSyslogCfg
	server       *syslog.Server
	syslogPartsC syslog.LogPartsChannel
	eventC       chan kawa.Message[types.Event]
}

func NewNginxSyslogSource(cfg NginxSyslogCfg) *NginxSyslogSource {
	server := syslog.NewServer()
	channel := make(syslog.LogPartsChannel)
	handler := syslog.NewChannelHandler(channel)
	server.SetFormat(syslog.RFC3164)
	server.SetHandler(handler)
	return &NginxSyslogSource{
		cfg:          cfg,
		server:       server,
		syslogPartsC: channel,
		eventC:       make(chan kawa.Message[types.Event]),
	}
}

func (s *NginxSyslogSource) Run(ctx context.Context) error {
	slog.Info(fmt.Sprintf("starting syslog server on socket %s", s.cfg.Addr))
	err := s.server.ListenUDP(s.cfg.Addr)
	if err != nil {
		return err
	}
	err = s.server.Boot()
	if err != nil {
		return err
	}

	done := make(chan struct{})
	go func() {
		s.server.Wait()
		close(done)
	}()

	run := await.New()
	run.AddNamed(await.RunFunc(s.recvLoop), "recvLoop")
	run.AddNamed(await.RunFunc(func(ctx context.Context) error {
		select {
		case <-ctx.Done():
			slog.Info("stopping syslog server")
			return s.server.Kill()
		case <-done:
			return errors.New("syslog server stopped unexpectedly")
		}
	}), "syslog")
	return run.Run(ctx)
}

func (s *NginxSyslogSource) recvLoop(ctx context.Context) error {
	for {
		select {
		case logParts := <-s.syslogPartsC:
			if content, ok := logParts["content"]; ok {
				rawLog := content.(string)

				ts := time.Now().UTC()
				if timestamp, ok := logParts["timestamp"]; ok {
					if ts, ok = timestamp.(time.Time); !ok {
						ts = time.Now().UTC()
					}
				}

				// Parse the nginx log
				entry, err := parseNginxLog(rawLog)
				if err != nil {
					fmt.Println("warn: failed to parse nginx log entry")
					continue
				}

				entryTime, err := time.Parse("02/Jan/2006:15:04:05 -0700", entry.TimeLocal)
				if err != nil {
					fmt.Printf("warn: failed to parse nginx log timestamp: %s\n", entry.TimeLocal)
				}
				if !entryTime.IsZero() {
					ts = entryTime
				}

				ip, err := netip.ParseAddr(entry.RemoteAddr)
				if err != nil {
					fmt.Printf("warn: failed to parse remote address: %s\n", entry.RemoteAddr)
				}
				if entry.RemoteUser == "-" {
					entry.RemoteUser = ""
				}
				if entry.HttpReferer == "-" {
					entry.HttpReferer = ""
				}
				if entry.HttpUserAgent == "-" {
					entry.HttpUserAgent = ""
				}
				if entry.BodyBytesSent == "-" {
					entry.BodyBytesSent = "0"
				}
				if entry.Status == "-" {
					entry.Status = "0"
				}
				if entry.Request == "-" {
					entry.Request = ""
				}

				log, err := json.Marshal(rawLog)
				if err != nil {
					fmt.Println("warn: failed to marshal raw log")
				}

				msg := kawa.Message[types.Event]{
					Value: types.Event{
						SourceType: "nginx-syslog",
						EventTime:  ts,
						Src: types.Network{
							IP: ip,
						},
						Actor: types.Actor{
							Username: entry.RemoteUser,
						},
						RawLog: log,
						Tags: map[string]string{
							"request":         entry.Request,
							"status":          entry.Status,
							"body_bytes":      entry.BodyBytesSent,
							"http_referer":    entry.HttpReferer,
							"http_user_agent": entry.HttpUserAgent,
						},
					},
				}

				select {
				case s.eventC <- msg:
				case <-ctx.Done():
					return ctx.Err()
				}
			} else {
				fmt.Println("warn: found syslog without 'content' key")
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (s *NginxSyslogSource) Recv(ctx context.Context) (kawa.Message[types.Event], func(), error) {
	for {
		select {
		case msg := <-s.eventC:
			return msg, func() {}, nil
		case <-ctx.Done():
			return kawa.Message[types.Event]{}, func() {}, ctx.Err()
		}
	}

}

// nginxLogEntry represents a parsed nginx log entry in the default combined
// log format.
type nginxLogEntry struct {
	RemoteAddr    string
	RemoteUser    string
	TimeLocal     string
	Request       string
	Status        string
	BodyBytesSent string
	HttpReferer   string
	HttpUserAgent string
}

// log_format combined '$remote_addr - $remote_user [$time_local] '
//                     '"$request" $status $body_bytes_sent '
//                     '"$http_referer" "$http_user_agent"';

// parseNginxLog takes a string in nginx combined log format and returns an nginxLogEntry.
func parseNginxLog(logLine string) (*nginxLogEntry, error) {
	var nginxLogRegex = regexp.MustCompile(`^(\S+) - (\S+) \[([\w:\/\-\s\+]+)\] "([^"]+)" (\S+) (\S+) "([^"]*)" "([^"]*)"$`)
	matches := nginxLogRegex.FindStringSubmatch(logLine)

	if matches == nil || len(matches) < 9 {
		return nil, fmt.Errorf("log line does not match the nginx combined log format")
	}

	entry := nginxLogEntry{
		RemoteAddr:    matches[1],
		RemoteUser:    matches[2],
		TimeLocal:     matches[3],
		Request:       matches[4],
		Status:        matches[5],
		BodyBytesSent: matches[6],
		HttpReferer:   matches[7],
		HttpUserAgent: matches[8],
	}

	return &entry, nil
}
