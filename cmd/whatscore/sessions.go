package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/angga0x3/whatscore/core/session"
)

// stopSessions stops every live session actor. It runs during shutdown after
// HTTP has drained, so no request can race a stop.
func (a *App) stopSessions(ctx context.Context) error {
	if a.sessions == nil {
		return nil
	}
	sessions, err := a.sessions.ListSessions(ctx, "")
	if err != nil {
		return fmt.Errorf("list sessions: %w", err)
	}
	var errs []error
	for _, view := range sessions {
		if err := a.sessions.DeleteSession(ctx, view.ID); err != nil && !errors.Is(err, session.ErrSessionClosed) {
			errs = append(errs, fmt.Errorf("session %s: %w", view.ID, err))
		}
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	a.logger.Info("sessions stopped", "count", len(sessions))
	return nil
}
