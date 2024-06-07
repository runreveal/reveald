package main

import (
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
	"github.com/runreveal/reveald/internal/sources/filewatch"
	"github.com/runreveal/reveald/internal/sources/journald"
	mqttSrckawad "github.com/runreveal/reveald/internal/sources/mqtt"
	nginx_syslog "github.com/runreveal/reveald/internal/sources/nginx-syslog"
	"github.com/runreveal/reveald/internal/sources/scanner"
	"github.com/runreveal/reveald/internal/sources/syslog"
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
	loader.Register("watcher", func() loader.Builder[kawa.Source[types.Event]] {
		return &WatcherConfig{}
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

type WatcherConfig struct {
	// Path is the directory to watch
	Path string `json:"path"`
	// Extension indicates which files to consume
	Extension string `json:"extension"`
}

func (c *WatcherConfig) Configure() (kawa.Source[types.Event], error) {
	slog.Info(fmt.Sprintf("configuring filewatcher for directory: %s", c.Path))
	return filewatch.NewWatcher(
		filewatch.WithExtension(c.Extension),
		filewatch.WithPath(c.Path),
		filewatch.WithHighWatermarkFile(filepath.Join(internal.ConfigDir(), "watcher-hwm.json")),
		filewatch.WithCommitInterval(5*time.Second),
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
	AccessSecretKey string `json:"accessSecretKey"`

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
		s3.WithAccessSecretKey(c.AccessSecretKey),
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
