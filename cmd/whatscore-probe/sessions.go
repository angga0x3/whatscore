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
	// SenderKeys are the group ratchets, one per (group, member). They are
	// as load-bearing as a 1:1 session: a group message the phone sends
	// after a restart is only readable if the chain survived (PF-093).
	SenderKeys map[string]storedSenderKey `json:"sender_keys,omitempty"`
}

// storedSenderKey is one member's group ratchet on disk.
type storedSenderKey struct {
	Group      string `json:"group"`
	Sender     string `json:"sender"`
	ID         uint32 `json:"id"`
	Iteration  uint32 `json:"iteration"`
	ChainKey   []byte `json:"chain_key"`
	SigningKey []byte `json:"signing_key"`
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
	if keysPath == "" {
		// No key file means no session file. Returning a derived name here
		// once produced "..sessions.json" in the working directory, and every
		// send started from an empty store without saying so.
		return ""
	}
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
	if file.SenderKeys == nil {
		file.SenderKeys = map[string]storedSenderKey{}
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

// persist records one session and writes the store in the same step.
//
// The receiver's observer covers decrypts, but an outbound send advances the
// ratchet too. A send that leaves the state on disk one step behind makes the
// next run encrypt from a spent chain — the peer cannot open it, and the
// message key is gone. Every outbound session the sender returns is written
// here before the process can end.
func (s *sessionsFile) persist(path, peer string, session *coremessaging.PeerSession) error {
	if err := s.record(peer, session); err != nil {
		return err
	}
	return s.save(path)
}

// recordSenderKey stores one group ratchet in memory, keyed by group and
// member. The file is written by the caller, once per change.
func (s *sessionsFile) recordSenderKey(group, sender string, key *coremessaging.SenderKey) error {
	if key == nil {
		return nil
	}
	if s.SenderKeys == nil {
		s.SenderKeys = map[string]storedSenderKey{}
	}
	s.SenderKeys[senderKeyKey(group, sender)] = storedSenderKey{
		Group:      group,
		Sender:     sender,
		ID:         key.ID,
		Iteration:  key.Iteration,
		ChainKey:   append([]byte(nil), key.ChainKey[:]...),
		SigningKey: append([]byte(nil), key.SigningKey[:]...),
	}
	return nil
}

// installSenderKeys loads every stored group ratchet into the receiver.
func (s *sessionsFile) installSenderKeys(r *coremessaging.Receiver) error {
	for _, rec := range s.SenderKeys {
		if rec.Group == "" || rec.Sender == "" {
			continue
		}
		if len(rec.ChainKey) != 32 || len(rec.SigningKey) != 32 {
			return fmt.Errorf("sender key for %s in %s has %d/%d byte keys", rec.Sender, rec.Group, len(rec.ChainKey), len(rec.SigningKey))
		}
		key := &coremessaging.SenderKey{ID: rec.ID, Iteration: rec.Iteration}
		copy(key.ChainKey[:], rec.ChainKey)
		copy(key.SigningKey[:], rec.SigningKey)
		if err := r.SetSenderKey(rec.Group, rec.Sender, key); err != nil {
			return fmt.Errorf("install sender key for %s in %s: %w", rec.Sender, rec.Group, err)
		}
	}
	return nil
}

// senderKeyKey is the in-file identity of one group ratchet.
func senderKeyKey(group, sender string) string { return group + "|" + sender }

// installSender restores every stored session into a sender, for callers that
// send but never receive. A session -listen bootstrapped is one -send must
// continue: initiating a new prekey session instead would spend another
// one-time prekey and orphan the chain the peer is already answering on.
func (s *sessionsFile) installSender(sender *coremessaging.Sender) (int, error) {
	if sender == nil {
		return 0, fmt.Errorf("no sender to install sessions into")
	}
	installed := 0
	for peer, rec := range s.Sessions {
		if strings.HasSuffix(peer, "@g.us") {
			// A 1:1 Signal session cannot belong to a group. Older builds
			// keyed group stanzas by their "from", which wrote exactly that;
			// installing it would shadow the real sender's session.
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(rec.State)
		if err != nil {
			return installed, fmt.Errorf("decode session for %s: %w", peer, err)
		}
		state := &signal.State{}
		if err := state.UnmarshalBinary(raw); err != nil {
			return installed, fmt.Errorf("restore session for %s: %w", peer, err)
		}
		var identity [32]byte
		if len(rec.PeerIdentity) == len(identity) {
			copy(identity[:], rec.PeerIdentity)
		}
		if err := sender.SetPeer(peer, &coremessaging.PeerSession{PeerIdentity: identity, State: state}); err != nil {
			return installed, fmt.Errorf("install sender session for %s: %w", peer, err)
		}
		installed++
	}
	return installed, nil
}

// install registers every stored session with the receiver and the sender,
// so a msg-carrier message from a peer this device has already bootstrapped
// decrypts in this run instead of dying with "no peer session" — and an
// outbound send (the app state key request) rides the same chain.
func (s *sessionsFile) install(r *coremessaging.Receiver, sender *coremessaging.Sender) error {
	for peer, rec := range s.Sessions {
		if strings.HasSuffix(peer, "@g.us") {
			// See installSender: a group can never own a 1:1 session.
			continue
		}
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
