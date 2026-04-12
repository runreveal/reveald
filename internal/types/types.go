package types

import (
	"encoding/json"
	"net/netip"
	"time"
)

type Event struct {
	SourceType string          `json:"sourceType"`
	RawLog     json.RawMessage `json:"rawLog"`
	Normalized Normalized      `json:"normalized"`
}

type Normalized struct {
	EventTime time.Time         `json:"eventTime,omitempty"`
	EventName string            `json:"eventName,omitempty"`
	Src       Network           `json:"src,omitempty"`
	Dst       Network           `json:"dst,omitempty"`
	Actor     Actor             `json:"actor,omitempty"`
	Service   Service           `json:"service,omitempty"`
	Tags      map[string]string `json:"tags,omitempty"`
	ReadOnly  bool              `json:"readOnly,omitempty"`
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

// RawLogJSON ensures data is valid JSON for the rawLog field.
// If data is already valid JSON, it is returned as-is.
// Otherwise, it is marshaled as a JSON string.
func RawLogJSON(data []byte) json.RawMessage {
	if json.Valid(data) {
		return json.RawMessage(data)
	}
	b, _ := json.Marshal(string(data))
	return json.RawMessage(b)
}
