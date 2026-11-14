package main

import (
	"context"
	"time"
)

// shutdownTimeout bounds the drain window. WhatsApp session state is only
// flushed at the engine layer, so closing HTTP first and PostgreSQL last
// keeps restarts safe (spec §9: graceful shutdown so sessions survive
// container restarts).
const shutdownTimeout = 15 * time.Second

// shutdown drains traffic in dependency order:
//  1. flip readiness so load balancers stop routing to this instance,
//  2. stop accepting new HTTP requests and let in-flight ones finish,
//  3. close the PostgreSQL pool.
func (a *App) shutdown() {
	a.draining.Store(true)

	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()

	if err := a.server.Shutdown(ctx); err != nil {
		a.logger.Error("graceful HTTP shutdown failed", "error", err)
	}

	a.pool.Close()
	a.logger.Info("shutdown complete")
}
