package types

import (
	"encoding/json"
	"net/netip"
	"time"
)

type Event struct {
	SourceType string    `json:"sourceType"`
	EventTime  time.Time `json:"eventTime,omitempty"`
	EventName  string    `json:"eventName,omitempty"`

	Actor     Actor             `json:"actor,omitempty"`
	Src       Network           `json:"src,omitempty"`
	Dst       Network           `json:"dst,omitempty"`
	Service   Service           `json:"service,omitempty"`
	Tags      map[string]string `json:"tags,omitempty"`
	ReadOnly  bool              `json:"readOnly,omitempty"`
	Resources []json.RawMessage `json:"resources,omitempty"`

	// LogFormat describes the format of the log and indicates to the sourceType
	// how to parse the raw log.  e.g. "jsonl/normalized"
	LogFormat string `json:"logFormat"`
	RawLog    []byte `json:"rawLog"`
}

type Actor struct {
	ID       string `json:"id,omitempty"`
	Email    string `json:"email,omitempty"`
	Username string `json:"username,omitempty"`
}

type Network struct {
	IP   netip.Addr `json:"ip,omitempty"`
	Port uint       `json:"port,omitempty"`
}

type Service struct {
	Name string `json:"name,omitempty"`
}
