package kvparser

import (
	"fmt"

	"github.com/runreveal/kawa"
	"github.com/runreveal/lib/loader"
	"github.com/runreveal/reveald/internal/types"
)

// Config is a loader.Builder that wraps another source with a KVParser.
// Registered as source type "kv" in the loader registry.
//
// Example config:
//
//	{
//	  "type": "kv",
//	  "source": { "type": "syslog", "addr": ":514" },
//	  "rules": [
//	    {
//	      "match": [{"path": "sourceType", "value": "syslog"}],
//	      "kvSep": "="
//	    }
//	  ]
//	}
type Config struct {
	Source loader.Loader[kawa.Source[types.Event]] `json:"source"`
	Rules  []Rule                                  `json:"rules"`
}

func (c *Config) Configure() (kawa.Source[types.Event], error) {
	if c.Source.Builder == nil {
		return nil, fmt.Errorf("kv: source is required")
	}
	inner, err := c.Source.Configure()
	if err != nil {
		return nil, fmt.Errorf("kv: configuring inner source: %w", err)
	}
	return New(inner, c.Rules)
}
