package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	coremessaging "github.com/angga0x3/whatscore/core/messaging"
	"github.com/angga0x3/whatscore/protocol/signal"
)

// sessionsFile is the on-disk set of Signal peer sessions this device holds.
//
// A bootstrapped ratchet is a one-way door: the phone continues that session
// with msg-carrier messages, and a run that does not persist the state cannot
// open any of them. The PF-087 redelivery proved it the hard way — messages
// queued for a session whose state died with the previous process are
// permanently unreadable. Every installed session and every ratchet advance
// goes through the receiver's session observer into this file.
type sessionsFile struct {
	Sessions map[string]storedSession `json:"sessions"`
}

// storedSession holds one peer's identity key (the sender's Signal identity,
// which every decrypt verifies against) and the ratchet state.
type storedSession struct {
	PeerIdentity []byte `json:"peer_identity"`
	State        string `json:"state"` // base64 of signal.State.MarshalBinary
}

// sessionsPathFor derives the sessions file from the key file path:
// paired.keys.json -> paired.sessions.json.
func sessionsPathFor(keysPath string) string {
	return filepath.Join(filepath.Dir(keysPath),
		string(strings.TrimSuffix(filepath.Base(keysPath), filepath.Ext(keysPath)))+".sessions.json")
}

func loadSessionsFile(path string) (*sessionsFile, error) {
	if path == "" {
		return nil, fmt.Errorf("no sessions file path")
	}
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return &sessionsFile{Sessions: map[string]storedSession{}}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read sessions file: %w", err)
	}
	var file sessionsFile
	if err := json.Unmarshal(raw, &file); err != nil {
		return nil, fmt.Errorf("decode sessions file: %w", err)
	}
	if file.Sessions == nil {
		file.Sessions = map[string]storedSession{}
	}
	return &file, nil
}

// save writes the session store with owner-only permissions.
func (s *sessionsFile) save(path string) error {
	if path == "" {
		return fmt.Errorf("no sessions file path")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create sessions directory: %w", err)
	}
	raw, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("encode sessions file: %w", err)
	}
	raw = append(raw, '\n')
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		return fmt.Errorf("write sessions file: %w", err)
	}
	return nil
}

// record serializes one session into the store.
func (s *sessionsFile) record(peer string, session *coremessaging.PeerSession) error {
	if session == nil || session.State == nil {
		return nil
	}
	raw, err := session.State.MarshalBinary()
	if err != nil {
		return fmt.Errorf("marshal session for %s: %w", peer, err)
	}
	if s.Sessions == nil {
		s.Sessions = map[string]storedSession{}
	}
	s.Sessions[peer] = storedSession{
		PeerIdentity: append([]byte(nil), session.PeerIdentity[:]...),
		State:        base64.StdEncoding.EncodeToString(raw),
	}
	return nil
}

// install registers every stored session with the receiver and the sender,
// so a msg-carrier message from a peer this device has already bootstrapped
// decrypts in this run instead of dying with "no peer session" — and an
// outbound send (the app state key request) rides the same chain.
func (s *sessionsFile) install(r *coremessaging.Receiver, sender *coremessaging.Sender) error {
	for peer, rec := range s.Sessions {
		raw, err := base64.StdEncoding.DecodeString(rec.State)
		if err != nil {
			return fmt.Errorf("decode session for %s: %w", peer, err)
		}
		state := &signal.State{}
		if err := state.UnmarshalBinary(raw); err != nil {
			return fmt.Errorf("restore session for %s: %w", peer, err)
		}
		var identity [32]byte
		if len(rec.PeerIdentity) == len(identity) {
			copy(identity[:], rec.PeerIdentity)
		}
		ps := &coremessaging.PeerSession{PeerIdentity: identity, State: state}
		if err := r.SetReceiverPeer(peer, ps); err != nil {
			return fmt.Errorf("install session for %s: %w", peer, err)
		}
		if sender != nil {
			if err := sender.SetPeer(peer, ps); err != nil {
				return fmt.Errorf("install sender session for %s: %w", peer, err)
			}
		}
	}
	return nil
}
