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
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	coremessaging "github.com/angga0x3/whatscore/core/messaging"
	"github.com/angga0x3/whatscore/core/signalsession"
	storagecredentials "github.com/angga0x3/whatscore/storage/credentials"
)

// signalStore persists one session's peer ratchets through the vault.
type signalStore struct {
	manager *signalsession.Manager
	// vault is the same encrypted store the manager writes through, used for
	// the group ratchets (one JSON record per session).
	vault signalsession.Store
	// senderMu serializes the read-modify-write of that record.
	senderMu sync.Mutex
	// sessionID names the records; the manager keeps its own copy.
	sessionID string
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
	return &signalStore{manager: manager, vault: store, sessionID: sessionID}, nil
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

// senderKeysKey names the single vault record that holds every group ratchet
// for a session. They are small and updated together; one record keeps the
// index problem away.
func senderKeysKey(sessionID string) string { return "sessions/" + sessionID + "/sender-keys.json" }

// storedSenderKey is one member's group ratchet as persisted.
type storedSenderKey struct {
	Group      string `json:"group"`
	Sender     string `json:"sender"`
	ID         uint32 `json:"id"`
	Iteration  uint32 `json:"iteration"`
	ChainKey   []byte `json:"chain_key"`
	SigningKey []byte `json:"signing_key"`
}

// loadSenderKeys returns every stored group ratchet.
func (s *signalStore) loadSenderKeys(ctx context.Context) ([]coremessaging.SenderKeyEntry, error) {
	s.senderMu.Lock()
	defer s.senderMu.Unlock()
	return s.readSenderKeys(ctx)
}

// readSenderKeys reads the record. The caller holds senderMu.
func (s *signalStore) readSenderKeys(ctx context.Context) ([]coremessaging.SenderKeyEntry, error) {
	raw, err := s.vault.Get(ctx, senderKeysKey(s.sessionID))
	if errors.Is(err, storagecredentials.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("load sender keys: %w", err)
	}
	var stored []storedSenderKey
	if err := json.Unmarshal(raw, &stored); err != nil {
		return nil, fmt.Errorf("decode sender keys: %w", err)
	}
	entries := make([]coremessaging.SenderKeyEntry, 0, len(stored))
	for _, rec := range stored {
		if rec.Group == "" || rec.Sender == "" || len(rec.ChainKey) != 32 || len(rec.SigningKey) != 32 {
			continue
		}
		var key coremessaging.SenderKey
		key.ID = rec.ID
		key.Iteration = rec.Iteration
		copy(key.ChainKey[:], rec.ChainKey)
		copy(key.SigningKey[:], rec.SigningKey)
		entries = append(entries, coremessaging.SenderKeyEntry{Group: rec.Group, Sender: rec.Sender, Key: key})
	}
	return entries, nil
}

// saveSenderKey upserts one group ratchet in the vault record.
func (s *signalStore) saveSenderKey(ctx context.Context, group, sender string, key *coremessaging.SenderKey) error {
	if key == nil {
		return nil
	}
	s.senderMu.Lock()
	defer s.senderMu.Unlock()
	entries, err := s.readSenderKeys(ctx)
	if err != nil {
		return err
	}
	replaced := false
	for i := range entries {
		if entries[i].Group == group && entries[i].Sender == sender {
			entries[i].Key = *key
			replaced = true
			break
		}
	}
	if !replaced {
		entries = append(entries, coremessaging.SenderKeyEntry{Group: group, Sender: sender, Key: *key})
	}
	stored := make([]storedSenderKey, 0, len(entries))
	for _, entry := range entries {
		stored = append(stored, storedSenderKey{
			Group:      entry.Group,
			Sender:     entry.Sender,
			ID:         entry.Key.ID,
			Iteration:  entry.Key.Iteration,
			ChainKey:   append([]byte(nil), entry.Key.ChainKey[:]...),
			SigningKey: append([]byte(nil), entry.Key.SigningKey[:]...),
		})
	}
	raw, err := json.Marshal(stored)
	if err != nil {
		return fmt.Errorf("encode sender keys: %w", err)
	}
	if err := s.vault.Put(ctx, senderKeysKey(s.sessionID), raw); err != nil {
		return fmt.Errorf("save sender keys: %w", err)
	}
	return nil
}
