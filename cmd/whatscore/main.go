// Command whatscore runs the WhatsCore REST API server.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/angga0x3/whatscore/buildinfo"
	"github.com/angga0x3/whatscore/config"
)

// Overridden at build time via -ldflags (see Makefile / Dockerfile).
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	showVersion := flag.Bool("version", false, "print version information and exit")
	flag.Parse()

	build := buildinfo.Info{Version: version, Commit: commit, Date: date}
	if *showVersion {
		fmt.Println("WhatsCore", build.String())
		return
	}

	if err := run(build); err != nil {
		fmt.Fprintln(os.Stderr, "fatal:", err)
		os.Exit(1)
	}
}

func run(build buildinfo.Info) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	initCtx, cancelInit := context.WithCancel(context.Background())
	defer cancelInit()

	core, err := newApp(initCtx, cfg, build)
	if err != nil {
		return fmt.Errorf("initialize app: %w", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	return core.Run(ctx)
}
