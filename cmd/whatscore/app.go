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
	"github.com/angga0x3/whatscore/core/events"
	"github.com/angga0x3/whatscore/observability"
	"github.com/angga0x3/whatscore/protocol/binary"
	"github.com/angga0x3/whatscore/server/api"
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
	sessions *api.Manager
	bus      *events.Bus
	server   *http.Server
	build    buildinfo.Info
	draining atomic.Bool
}

// New initializes every dependency (logger, PostgreSQL pool, schema
// migrations, HTTP server) and returns an app ready to Run.
func newApp(ctx context.Context, cfg *config.Config, build buildinfo.Info) (*App, error) {
	logger := observability.NewLogger(cfg)

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

	// Session secrets are sealed by storage/credentials.Vault before they
	// reach any backend. In development without ENCRYPTION_KEY, newCredentialVault
	// falls back to an ephemeral in-memory key and warns loudly; production
	// config already rejects that combination.
	backend, err := postgres.NewCredentialBackend(pool)
	if err != nil {
		pool.Close()
		return nil, fmt.Errorf("build credential backend: %w", err)
	}
	vault, err := newCredentialVault(cfg, backend, logger)
	if err != nil {
		pool.Close()
		return nil, fmt.Errorf("build credential vault: %w", err)
	}

	bus := events.NewBus()
	dictionary, err := loadTokenDictionary(cfg, logger)
	if err != nil {
		pool.Close()
		return nil, fmt.Errorf("load token dictionary: %w", err)
	}

	factory, err := newSessionFactory(sessionFactoryOptions{
		vault:  vault,
		bus:    bus,
		logger: logger,
		codec:  binary.NewCodec(dictionary),
	})
	if err != nil {
		pool.Close()
		return nil, fmt.Errorf("build session factory: %w", err)
	}

	sessions, err := api.NewManager(api.WithSessionFactory(factory.newSession))
	if err != nil {
		pool.Close()
		return nil, fmt.Errorf("build session service: %w", err)
	}
	apiHandler, err := api.NewHandler(sessions)
	if err != nil {
		pool.Close()
		return nil, fmt.Errorf("build API handler: %w", err)
	}
	// Sessions publish lifecycle events to the bus; mounting it lets the SSE
	// routes stream them instead of answering 501.
	apiHandler.SetBus(bus)

	// Inbound and outbound traffic lands in the message store, and text
	// delivers over the session connection: the REST surface is a client,
	// not a ledger of intents.
	messages := api.NewMemoryMessageStore()
	apiHandler.SetMessages(messages)
	apiHandler.SetTextDeliverer(textDelivererFunc(func(ctx context.Context, sessionID, to, text string) (string, error) {
		return factory.deliverText(ctx, sessionID, to, text)
	}))
	go appendInboundMessages(ctx, bus, messages, logger)

	a := &App{
		cfg:      cfg,
		logger:   logger,
		pool:     pool,
		sessions: sessions,
		bus:      bus,
		build:    build,
	}

	router := httpapi.NewRouter(httpapi.Deps{
		Logger:         logger,
		AppName:        cfg.App.Name,
		Build:          build,
		Readiness:      []handlers.Checker{postgres.PingChecker{Pool: pool}},
		IsShuttingDown: a.draining.Load,
		API:            apiHandler,
	})

	a.server = &http.Server{
		Addr:              cfg.Addr(),
		Handler:           router,
		ReadHeaderTimeout: readHeaderTimeout,
		IdleTimeout:       idleTimeout,
	}

	return a, nil
}

// textDelivererFunc adapts the factory's delivery to the API boundary.
type textDelivererFunc func(ctx context.Context, sessionID, to, text string) (string, error)

func (f textDelivererFunc) DeliverText(ctx context.Context, sessionID, to, text string) (string, error) {
	return f(ctx, sessionID, to, text)
}

// appendInboundMessages stores every decrypted inbound message, so
// GET /sessions/{id}/messages reflects what the session actually received.
func appendInboundMessages(ctx context.Context, bus *events.Bus, store api.MessageAppender, logger *slog.Logger) {
	sub := bus.Subscribe()
	defer sub.Close()
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-sub.C:
			if !ok {
				return
			}
			if ev.Type != events.TypeMessage || ev.Message == nil {
				continue
			}
			if _, err := store.Append(ctx, api.MessageView{
				ID:        ev.Message.ID,
				SessionID: ev.SessionID,
				Chat:      ev.Message.Chat,
				Sender:    ev.Message.Sender,
				Direction: api.DirectionInbound,
				Type:      api.MessageTypeText,
				Text:      ev.Message.Text,
			}); err != nil {
				logger.Warn("could not store inbound message", "session", ev.SessionID, "message", ev.Message.ID, "error", err)
			}
		}
	}
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
