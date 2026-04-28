package runreveal

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"log/slog"

	"github.com/carlmjohnson/requests"
	"github.com/runreveal/kawa"
	batch "github.com/runreveal/kawa/x/batcher"
	"github.com/runreveal/reveald/internal/types"
)

type Option func(*RunReveal)

func WithWebhookURL(url string) Option {
	return func(r *RunReveal) {
		r.webhookURL = url
	}
}

func WithHTTPClient(httpc *http.Client) Option {
	return func(r *RunReveal) {
		r.httpc = httpc
	}
}

func WithBatchSize(size int) Option {
	return func(r *RunReveal) {
		r.batchSize = size
	}
}

func WithFlushFrequency(t time.Duration) Option {
	return func(r *RunReveal) {
		r.flushFreq = t
	}
}

func WithFormatVersion(v int) Option {
	return func(r *RunReveal) {
		r.formatVersion = v
	}
}

type RunReveal struct {
	httpc   *http.Client
	batcher *batch.Destination[types.Event]

	batchSize     int
	flushFreq     time.Duration
	webhookURL    string
	formatVersion int // 0 = legacy, 1 = native
	reqConf       requests.Config
}

func New(opts ...Option) *RunReveal {
	ret := &RunReveal{
		httpc: http.DefaultClient,
	}
	for _, o := range opts {
		o(ret)
	}

	if ret.batchSize <= 0 {
		ret.batchSize = 100
	}
	if ret.flushFreq <= 0 {
		ret.flushFreq = 15 * time.Second
	}

	ret.batcher = batch.NewDestination[types.Event](ret,
		batch.Raise[types.Event](),
		batch.FlushLength(ret.batchSize),
		batch.FlushFrequency(ret.flushFreq),
		batch.FlushParallelism(2),
	)
	return ret
}

func (r *RunReveal) Run(ctx context.Context) error {
	if r.webhookURL == "" {
		return errors.New("missing webhook url")
	}

	r.reqConf = func(rb *requests.Builder) {
		rb.
			UserAgent("kawa").
			Accept("application/json").
			BaseURL(r.webhookURL).
			Header("Content-Type", "application/json")
	}

	return r.batcher.Run(ctx)
}

func (r *RunReveal) Send(
	ctx context.Context,
	ack func(),
	msg kawa.Message[types.Event],
) error {
	return r.batcher.Send(ctx, ack, msg)
}

func (r *RunReveal) newReq() *requests.Builder {
	return requests.New(r.reqConf)
}

// Flush sends a batch of events to the RunReveal API.
func (r *RunReveal) Flush(
	ctx context.Context,
	msgs []kawa.Message[types.Event],
) error {
	batch := make([]json.RawMessage, 0, len(msgs))
	for _, msg := range msgs {
		var raw []byte
		var err error
		if r.formatVersion >= 1 {
			raw, err = json.Marshal(msg.Value)
		} else {
			raw, err = json.Marshal(toLegacy(msg.Value))
		}
		if err != nil {
			slog.Error("error marshalling event", "err", err)
			continue
		}
		batch = append(batch, raw)
	}

	if len(batch) == 0 {
		return nil
	}

	err := r.newReq().BodyJSON(batch).Fetch(ctx)
	if err != nil {
		slog.Error("error sending batch to runreveal", "err", err)
		return err
	}
	return nil
}

// legacyEvent is the v0 wire format expected by older backends.
type legacyEvent struct {
	Timestamp   time.Time         `json:"ts"`
	SourceType  string            `json:"sourceType"`
	ContentType string            `json:"contentType"`
	EventTime   time.Time         `json:"eventTime,omitempty"`
	EventName   string            `json:"eventName,omitempty"`
	RawLog      []byte            `json:"rawLog"`
	Src         legacyNetwork     `json:"src"`
	Dst         legacyNetwork     `json:"dst"`
	Service     types.Service     `json:"service"`
	Tags        map[string]string `json:"tags,omitempty"`
}

type legacyNetwork struct {
	IP   string `json:"ip"`
	Port uint   `json:"port,omitempty"`
}

func toLegacy(e types.Event) legacyEvent {
	now := time.Now().UTC()
	srcIP := ""
	if e.Src.IP.IsValid() {
		srcIP = e.Src.IP.String()
	}
	dstIP := ""
	if e.Dst.IP.IsValid() {
		dstIP = e.Dst.IP.String()
	}
	return legacyEvent{
		Timestamp:   now,
		SourceType:  e.SourceType,
		ContentType: "application/json",
		EventTime:   e.EventTime,
		EventName:   e.EventName,
		RawLog:      []byte(e.RawLog),
		Src:         legacyNetwork{IP: srcIP, Port: e.Src.Port},
		Dst:         legacyNetwork{IP: dstIP, Port: e.Dst.Port},
		Service:     e.Service,
		Tags:        e.Tags,
	}
}
