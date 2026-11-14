// app.go wires all WhatsCore components together and owns the process
// lifecycle: startup, dependency initialization, and graceful shutdown.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/angga0x3/whatscore/buildinfo"
	"github.com/angga0x3/whatscore/config"
	"github.com/angga0x3/whatscore/observability"
	httpapi "github.com/angga0x3/whatscore/server/http"
	"github.com/angga0x3/whatscore/server/http/handlers"
	"github.com/angga0x3/whatscore/storage/postgres"
	"github.com/angga0x3/whatscore/storage/postgres/migrations"
)

const (
	// initTimeout bounds the whole startup sequence (connect + migrate).
	initTimeout = 30 * time.Second
	// readHeaderTimeout protects against slowloris-style clients. Read and
	// write deadlines stay unset on purpose so streaming endpoints (SSE)
	// can hold long-lived responses.
	readHeaderTimeout = 10 * time.Second
	idleTimeout       = 120 * time.Second
)

// App is the fully assembled WhatsCore server.
type App struct {
	cfg      *config.Config
	logger   *slog.Logger
	pool     *pgxpool.Pool
	server   *http.Server
	build    buildinfo.Info
	draining atomic.Bool
}

// New initializes every dependency (logger, PostgreSQL pool, schema
// migrations, HTTP server) and returns an app ready to Run.
func newApp(ctx context.Context, cfg *config.Config, build buildinfo.Info) (*App, error) {
	logger := observability.NewLogger(cfg)
	if cfg.Security.EncryptionKey == "" && !cfg.IsProduction() {
		logger.Warn("ENCRYPTION_KEY is not set; set a real secret before going to production")
	}

	initCtx, cancel := context.WithTimeout(ctx, initTimeout)
	defer cancel()

	pool, err := postgres.NewPool(initCtx, cfg.Database.URL)
	if err != nil {
		return nil, fmt.Errorf("connect to PostgreSQL: %w", err)
	}
	logger.Info("connected to PostgreSQL", "host", safeHost(cfg.Database.URL))

	if cfg.Database.MigrateOnStartup {
		if err := postgres.MigrateUp(cfg.Database.URL, migrations.FS(), logger); err != nil {
			pool.Close()
			return nil, fmt.Errorf("run database migrations: %w", err)
		}
	}

	a := &App{
		cfg:    cfg,
		logger: logger,
		pool:   pool,
		build:  build,
	}

	router := httpapi.NewRouter(httpapi.Deps{
		Logger:         logger,
		AppName:        cfg.App.Name,
		Build:          build,
		Readiness:      []handlers.Checker{postgres.PingChecker{Pool: pool}},
		IsShuttingDown: a.draining.Load,
	})

	a.server = &http.Server{
		Addr:              cfg.Addr(),
		Handler:           router,
		ReadHeaderTimeout: readHeaderTimeout,
		IdleTimeout:       idleTimeout,
	}

	return a, nil
}

// Run serves HTTP until ctx is cancelled (SIGINT/SIGTERM), then drains.
func (a *App) Run(ctx context.Context) error {
	serverErrors := make(chan error, 1)
	go func() {
		a.logger.Info("HTTP server listening",
			"addr", a.server.Addr,
			"env", a.cfg.App.Env,
			"version", a.build.Version,
		)
		serverErrors <- a.server.ListenAndServe()
	}()

	select {
	case err := <-serverErrors:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("http server: %w", err)
	case <-ctx.Done():
		a.logger.Info("shutdown signal received")
		a.shutdown()
		return nil
	}
}

// safeHost extracts the host part of the database URL for logging without
// ever logging credentials.
func safeHost(databaseURL string) string {
	u, err := url.Parse(databaseURL)
	if err != nil || u.Host == "" {
		return "[redacted]"
	}
	return u.Host
}
