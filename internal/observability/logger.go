// Package observability centralizes logging and (future) metrics setup.
package observability

import (
	"log/slog"
	"os"

	"github.com/angga0x3/whatscore/internal/config"
)

// NewLogger builds the application logger from configuration.
//
// Development uses a human friendly text handler; production emits JSON so
// log aggregators can parse it without regex. Credential values must never
// be passed to this logger (see docs/architecture.md, "Log hygiene").
func NewLogger(cfg *config.Config) *slog.Logger {
	var level slog.Level
	switch cfg.App.LogLevel {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{Level: level}

	if cfg.IsProduction() {
		return slog.New(slog.NewJSONHandler(os.Stdout, opts))
	}
	return slog.New(slog.NewTextHandler(os.Stdout, opts))
}
