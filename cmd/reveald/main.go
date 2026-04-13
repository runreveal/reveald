package main

import (
	"context"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"time"

	"log/slog"

	"github.com/runreveal/kawa"
	"github.com/runreveal/lib/await"
	"github.com/runreveal/lib/cli"
	"github.com/runreveal/lib/loader"
	"github.com/runreveal/reveald/internal/queue"
	"github.com/runreveal/reveald/internal/types"
)

var (
	version = "dev"
)

func init() {
	replace := func(groups []string, a slog.Attr) slog.Attr {
		// Remove the directory from the source's filename.
		if a.Key == slog.SourceKey {
			source := a.Value.Any().(*slog.Source)
			source.File = filepath.Base(source.File)
		}
		return a
	}
	level := slog.LevelInfo
	if _, ok := os.LookupEnv("KAWA_DEBUG"); ok {
		level = slog.LevelDebug
	}

	h := slog.NewTextHandler(
		os.Stderr,
		&slog.HandlerOptions{
			Level:       level,
			AddSource:   true,
			ReplaceAttr: replace,
		},
	)

	slogger := slog.New(h)
	slog.SetDefault(slogger)
}

// Globals holds flags and config sections shared across all commands.
type Globals struct {
	Config string `cli:"config,c" usage:"path to config file" default:"/etc/reveald/config.json"`

	Sources      map[string]loader.Loader[kawa.Source[types.Event]]      `config:"sources"`
	Destinations map[string]loader.Loader[kawa.Destination[types.Event]] `config:"destinations"`

	sources      map[string]queue.Source
	destinations map[string]queue.Destination
}

func (g *Globals) Configure() error {
	g.sources = make(map[string]queue.Source, len(g.Sources))
	for name, src := range g.Sources {
		s, err := src.Configure()
		if err != nil {
			return fmt.Errorf("source %q: %w", name, err)
		}
		g.sources[name] = queue.Source{Name: name, Source: s}
	}

	g.destinations = make(map[string]queue.Destination, len(g.Destinations))
	for name, dst := range g.Destinations {
		d, err := dst.Configure()
		if err != nil {
			return fmt.Errorf("destination %q: %w", name, err)
		}
		g.destinations[name] = queue.Destination{Name: name, Destination: d}
	}

	return nil
}

func (g *Globals) Validate() error {
	if len(g.sources) == 0 {
		return fmt.Errorf("at least one source is required")
	}
	if len(g.destinations) == 0 {
		return fmt.Errorf("at least one destination is required")
	}
	return nil
}

func (g *Globals) ExtraHelp() string {
	return "\nAvailable source types:\n" +
		"  scanner, file, cri, command, syslog, nginx_syslog, journald, mqtt, eventlog, refine\n" +
		"\nAvailable destination types:\n" +
		"  printer, s3, s3b, runreveal, mqtt\n"
}

type RunCmd struct{}

func (r *RunCmd) Run(ctx context.Context, args []string) error {
	g := cli.GlobalsFromContext[Globals](ctx)

	return runService("reveald", func(ctx context.Context) error {
		w := await.New(await.WithSignals, await.WithStopTimeout(30*time.Second))
		q := queue.New(queue.WithSources(g.sources), queue.WithDestinations(g.destinations))
		w.AddNamed(q, "queue")
		return w.Run(ctx)
	})
}

func main() {
	slog.Info("starting", "program", path.Base(os.Args[0]), "version", version)

	globals := &Globals{}
	app := cli.New("reveald", "Log collection and forwarding daemon",
		cli.WithVersion(version),
		cli.WithGlobals(globals),
		cli.WithConfigFlag("config"),
	)
	app.AddCommand(
		cli.Command("run", "Start the reveald daemon", &RunCmd{},
			cli.WithLong(`Start the reveald daemon with the given configuration.
Sources collect events (syslog, file, journald, etc.) and destinations
ship them (S3, RunReveal, MQTT, etc.). All sources and destinations
run concurrently with graceful shutdown on SIGINT/SIGTERM.`),
		),
	)
	os.Exit(app.Run(context.Background(), os.Args[1:]))
}
