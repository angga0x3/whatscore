package main

// Server-side Signal session persistence.
//
// The server's session runtime keeps ratchets in memory while it runs, and the
// vault is where they have to outlive it: a bootstrapped ratchet is a one-way
// door, and a process that cannot restore the state loses every msg-carrier
// message the peer sends afterwards (the probe learned this as PF-087's
// redelivery). The probe persists to a file because it owns that file; the
// server persists through core/signalsession into the encrypted vault, which
// also keeps the peer index a restore needs.
//
// Without persistence the server's REST send path had a second failure mode:
// every restart re-initiated a prekey session, spending a one-time prekey and
// orphaning the chain the peer was already answering on.

import (
	"context"
	"errors"
	"fmt"

	coremessaging "github.com/angga0x3/whatscore/core/messaging"
	"github.com/angga0x3/whatscore/core/signalsession"
	storagecredentials "github.com/angga0x3/whatscore/storage/credentials"
)

// signalStore persists one session's peer ratchets through the vault.
type signalStore struct {
	manager *signalsession.Manager
}

// newSignalStore wires the record manager for one session. The vault reports
// a missing record as storagecredentials.ErrNotFound, so the manager is told
// how to recognise it; without that an empty store reads as a failure.
func newSignalStore(store signalsession.Store, sessionID string) (*signalStore, error) {
	manager, err := signalsession.New(store, sessionID, signalsession.WithNotFound(func(err error) bool {
		return errors.Is(err, storagecredentials.ErrNotFound)
	}))
	if err != nil {
		return nil, err
	}
	return &signalStore{manager: manager}, nil
}

// loadAll returns every stored peer session, keyed by the peer address. A
// peer whose record is gone is skipped: there is no state left to continue,
// and refusing the whole session over one stale index entry would be worse.
func (s *signalStore) loadAll(ctx context.Context) (map[string]*coremessaging.PeerSession, error) {
	peers, err := s.manager.Peers(ctx)
	if err != nil {
		return nil, err
	}
	sessions := make(map[string]*coremessaging.PeerSession, len(peers))
	for _, peer := range peers {
		record, err := s.manager.LoadRecord(ctx, peer)
		if errors.Is(err, storagecredentials.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("load signal session for %s: %w", peer, err)
		}
		sessions[peer] = &coremessaging.PeerSession{
			PeerIdentity: record.PeerIdentity,
			State:        record.State,
		}
	}
	return sessions, nil
}

// save writes one peer session and keeps the peer index in step.
func (s *signalStore) save(ctx context.Context, peer string, session *coremessaging.PeerSession) error {
	if session == nil || session.State == nil {
		return nil
	}
	return s.manager.SaveRecord(ctx, peer, &signalsession.Record{
		PeerIdentity: session.PeerIdentity,
		State:        session.State,
	})
}

// peers returns the peer addresses with a stored ratchet.
func (s *signalStore) peers(ctx context.Context) ([]string, error) {
	return s.manager.Peers(ctx)
}
