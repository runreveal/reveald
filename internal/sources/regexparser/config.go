package regexparser

import (
	"fmt"

	"github.com/runreveal/kawa"
	"github.com/runreveal/lib/loader"
	"github.com/runreveal/reveald/internal/types"
)

// Config is a loader.Builder that wraps another source with a RegexParser.
// Registered as source type "regex" in the loader registry.
//
// Example config:
//
//	{
//	  "type": "regex",
//	  "source": { "type": "journald" },
//	  "rules": [
//	    {
//	      "match": [{"path": "rawLog.SYSLOG_IDENTIFIER", "value": "unbound"}],
//	      "field": "MESSAGE.text",
//	      "pattern": "\\[\\d+:\\d+\\] (?P<action>\\w+): (?P<client_ip>[\\d.]+) (?P<qname>\\S+)",
//	      "target": "parsed"
//	    }
//	  ]
//	}
type Config struct {
	Source loader.Loader[kawa.Source[types.Event]] `json:"source"`
	Rules  []Rule                                  `json:"rules"`
}

func (c *Config) Configure() (kawa.Source[types.Event], error) {
	if c.Source.Builder == nil {
		return nil, fmt.Errorf("regex: source is required")
	}
	inner, err := c.Source.Configure()
	if err != nil {
		return nil, fmt.Errorf("regex: configuring inner source: %w", err)
	}
	return New(inner, c.Rules)
}
