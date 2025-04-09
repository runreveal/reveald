package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"log/slog"

	"github.com/runreveal/kawa"
	"github.com/runreveal/kawa/x/mqtt"
	"github.com/runreveal/kawa/x/s3"
	"github.com/runreveal/lib/loader"
	"github.com/runreveal/reveald/internal"
	mqttDstkawad "github.com/runreveal/reveald/internal/destinations/mqtt"
	"github.com/runreveal/reveald/internal/destinations/printer"
	"github.com/runreveal/reveald/internal/destinations/runreveal"
	s3kawad "github.com/runreveal/reveald/internal/destinations/s3"
	"github.com/runreveal/reveald/internal/sources/command"
	"github.com/runreveal/reveald/internal/sources/file"
	"github.com/runreveal/reveald/internal/sources/journald"
	mqttSrckawad "github.com/runreveal/reveald/internal/sources/mqtt"
	nginx_syslog "github.com/runreveal/reveald/internal/sources/nginx-syslog"
	"github.com/runreveal/reveald/internal/sources/scanner"
	"github.com/runreveal/reveald/internal/sources/syslog"
	"github.com/runreveal/reveald/internal/sources/windows"
	"github.com/runreveal/reveald/internal/types"
	// We could register and configure these in their own package
	// using the init() function.
	// That would make it easy to "dynamically" enable and disable them at
	// compile time since it would simply be updating the import list.
)

func init() {
	// ---------------Sources-------------------------
	loader.Register("scanner", func() loader.Builder[kawa.Source[types.Event]] {
		return &ScannerConfig{}
	})
	loader.Register("file", func() loader.Builder[kawa.Source[types.Event]] {
		return &FileConfig{}
	})
	loader.Register("command", func() loader.Builder[kawa.Source[types.Event]] {
		return &CmdConfig{}
	})
	loader.Register("syslog", func() loader.Builder[kawa.Source[types.Event]] {
		return &SyslogConfig{}
	})
	loader.Register("nginx_syslog", func() loader.Builder[kawa.Source[types.Event]] {
		return &NginxSyslogConfig{}
	})
	loader.Register("journald", func() loader.Builder[kawa.Source[types.Event]] {
		return &JournaldConfig{}
	})
	loader.Register("mqtt", func() loader.Builder[kawa.Source[types.Event]] {
		return &MQTTSrcConfig{}
	})
	loader.Register("eventlog", func() loader.Builder[kawa.Source[types.Event]] {
		return &EventLogConfig{}
	})

	// ---------------Destinations-------------------------
	loader.Register("printer", func() loader.Builder[kawa.Destination[types.Event]] {
		return &PrinterConfig{}
	})
	loader.Register("s3", func() loader.Builder[kawa.Destination[types.Event]] {
		return &S3Config{}
	})
	loader.Register("runreveal", func() loader.Builder[kawa.Destination[types.Event]] {
		return &RunRevealConfig{}
	})
	loader.Register("mqtt", func() loader.Builder[kawa.Destination[types.Event]] {
		return &MQTTDestConfig{}
	})

}

type ScannerConfig struct {
}

func (c *ScannerConfig) Configure() (kawa.Source[types.Event], error) {
	slog.Info("configuring scanner")
	return scanner.NewScanner(os.Stdin), nil
}

type FileConfig struct {
	// Path is the directory to watch
	Path string `json:"path"`
	// Extension indicates which files to consume
	Extension string `json:"extension"`
}

func (c *FileConfig) Configure() (kawa.Source[types.Event], error) {
	slog.Info(fmt.Sprintf("configuring file source for path: %s", c.Path))
	return file.NewWatcher(
		file.WithExtension(c.Extension),
		file.WithPath(c.Path),
		file.WithHighWatermarkFile(filepath.Join(internal.ConfigDir(), "watcher-hwm.json")),
		file.WithCommitInterval(5*time.Second),
	), nil
}

type CmdConfig struct {
	// Cmd is the shell command to run
	Cmd  string   `json:"cmd"`
	Args []string `json:"args"`
	// Environment is a map of environment variables to set
	InheritEnv  bool              `json:"inheritEnv"`
	Environment map[string]string `json:"env"`
	Interval    time.Duration     `json:"interval"`
}

func (c *CmdConfig) Configure() (kawa.Source[types.Event], error) {
	return command.NewCommand(
		command.WithCmd(c.Cmd),
		command.WithArgs(c.Args),
		command.WithEnvironment(c.Environment),
		command.WithInheritEnv(c.InheritEnv),
		command.WithInterval(c.Interval),
	), nil
}

type SyslogConfig struct {
	Addr        string `json:"addr"`
	ContentType string `json:"contentType"`
}

func (c *SyslogConfig) Configure() (kawa.Source[types.Event], error) {
	slog.Info("configuring syslog")
	return syslog.NewSyslogSource(syslog.SyslogCfg{
		Addr:        c.Addr,
		ContentType: c.ContentType,
	}), nil
}

type NginxSyslogConfig struct {
	Addr string `json:"addr"`
}

func (c *NginxSyslogConfig) Configure() (kawa.Source[types.Event], error) {
	slog.Info("configuring nginx syslog")
	return nginx_syslog.NewNginxSyslogSource(nginx_syslog.NginxSyslogCfg{
		Addr: c.Addr,
	}), nil
}

type EventLogConfig struct {
	Channel string `json:"channel"`
	Query   string `json:"query"`
	Buffer  int    `json:"buffer"`
}

func (c *EventLogConfig) Configure() (kawa.Source[types.Event], error) {
	slog.Info("configuring windows event log")
	buffer := 128
	if c.Buffer != 0 {
		buffer = c.Buffer
	}
	source, err := windows.NewEventLogSource(&windows.Options{
		Channel: c.Channel,
		Query:   c.Query,
		Buffer:  buffer,
	})
	if err != nil {
		return nil, err
	}
	return eventLogSource{source}, nil
}

// eventLogSource wraps [windows.EventLogSource] and normalizes the events.
type eventLogSource struct {
	source *windows.EventLogSource
}

func (s eventLogSource) Recv(ctx context.Context) (kawa.Message[types.Event], func(), error) {
	msg, ack, err := s.source.Recv(ctx)
	if err != nil {
		return kawa.Message[types.Event]{}, nil, err
	}
	event, err := msg.Value.ToGeneric()
	if err != nil {
		return kawa.Message[types.Event]{}, nil, err
	}
	return kawa.Message[types.Event]{
		Key:        msg.Key,
		Value:      *event,
		Topic:      msg.Topic,
		Attributes: msg.Attributes,
	}, ack, nil
}

func (s eventLogSource) Close() error {
	return s.source.Close()
}

type PrinterConfig struct {
}

func (c *PrinterConfig) Configure() (kawa.Destination[types.Event], error) {
	slog.Info("configuring printer")
	return printer.NewPrinter(os.Stdout), nil
}

type RunRevealConfig struct {
	WebhookURL string        `json:"webhookURL"`
	BatchSize  int           `json:"batchSize"`
	FlushFreq  time.Duration `json:"flushFreq"`
}

func (c *RunRevealConfig) Configure() (kawa.Destination[types.Event], error) {
	slog.Info("configuring runreveal")
	return runreveal.New(
		runreveal.WithWebhookURL(c.WebhookURL),
		runreveal.WithBatchSize(c.BatchSize),
		runreveal.WithFlushFrequency(c.FlushFreq),
	), nil
}

type S3Config struct {
	BucketName   string `json:"bucketName"`
	PathPrefix   string `json:"pathPrefix"`
	BucketRegion string `json:"bucketRegion"`

	CustomEndpoint  string `json:"customEndpoint"`
	AccessKeyID     string `json:"accessKeyID"`
	SecretAccessKey string `json:"secretAccessKey"`

	BatchSize int `json:"batchSize"`
}

func (c *S3Config) Configure() (kawa.Destination[types.Event], error) {
	slog.Info("configuring s3")
	return s3kawad.NewS3(
		s3.WithBucketName(c.BucketName),
		s3.WithBucketRegion(c.BucketRegion),
		s3.WithPathPrefix(c.PathPrefix),
		s3.WithCustomEndpoint(c.CustomEndpoint),
		s3.WithAccessKeyID(c.AccessKeyID),
		s3.WithSecretAccessKey(c.SecretAccessKey),
		s3.WithBatchSize(c.BatchSize),
	), nil
}

type JournaldConfig struct {
}

func (c *JournaldConfig) Configure() (kawa.Source[types.Event], error) {
	slog.Info("configuring journald")
	return journald.New(), nil
}

type MQTTDestConfig struct {
	Broker   string `json:"broker"`
	ClientID string `json:"clientID"`
	Topic    string `json:"topic"`

	UserName string `json:"userName"`
	Password string `json:"password"`

	QOS      byte `json:"qos"`
	Retained bool `json:"retained"`
}

func (c *MQTTDestConfig) Configure() (kawa.Destination[types.Event], error) {
	slog.Info("configuring mqtt dest")
	return mqttDstkawad.NewMQTT(
		mqtt.WithBroker(c.Broker),
		mqtt.WithClientID(c.ClientID),
		mqtt.WithQOS(c.QOS),
		mqtt.WithTopic(c.Topic),
		mqtt.WithRetained(c.Retained),
		mqtt.WithUserName(c.UserName),
		mqtt.WithPassword(c.Password),
	)
}

type MQTTSrcConfig struct {
	Broker   string `json:"broker"`
	ClientID string `json:"clientID"`
	Topic    string `json:"topic"`

	UserName string `json:"userName"`
	Password string `json:"password"`

	QOS      byte `json:"qos"`
	Retained bool `json:"retained"`
}

func (c *MQTTSrcConfig) Configure() (kawa.Source[types.Event], error) {
	slog.Info("configuring mqtt src")
	return mqttSrckawad.NewMQTT(
		mqtt.WithBroker(c.Broker),
		mqtt.WithClientID(c.ClientID),
		mqtt.WithQOS(c.QOS),
		mqtt.WithTopic(c.Topic),
		mqtt.WithRetained(c.Retained),
		mqtt.WithUserName(c.UserName),
		mqtt.WithPassword(c.Password),
	)
}
