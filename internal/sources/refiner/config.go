package refiner

import (
	"fmt"

	"github.com/runreveal/kawa"
	"github.com/runreveal/lib/loader"
	"github.com/runreveal/reveald/internal/types"
)

// Config is a loader.Builder that wraps another source with a Refiner.
// It is registered as source type "refine" in the loader registry.
//
// Example config:
//
//	{
//	  "type": "refine",
//	  "source": {
//	    "type": "journald",
//	    "maxLineLenKB": 200
//	  },
//	  "rules": [
//	    {
//	      "match": [{"path": "rawLog.SYSLOG_IDENTIFIER", "value": "coredns"}],
//	      "extract": [
//	        {"to": "sourceType", "from": "rawLog.SYSLOG_IDENTIFIER"},
//	        {"to": "service.name", "from": "rawLog.SYSLOG_IDENTIFIER"}
//	      ]
//	    }
//	  ]
//	}
type Config struct {
	Source loader.Loader[kawa.Source[types.Event]] `json:"source"`
	Rules  []Rule                                  `json:"rules"`
}

func (c *Config) Configure() (kawa.Source[types.Event], error) {
	if c.Source.Builder == nil {
		return nil, fmt.Errorf("refine: source is required")
	}
	inner, err := c.Source.Configure()
	if err != nil {
		return nil, fmt.Errorf("refine: configuring inner source: %w", err)
	}
	return New(inner, c.Rules)
}
