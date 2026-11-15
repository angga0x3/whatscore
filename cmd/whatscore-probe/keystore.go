package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/angga0x3/whatscore/protocol/signal"
)

// keyFile is the on-disk set of key material this device has published.
//
// A prekey is a promise: once an ID is on the server, a peer may encrypt to it
// at any later date, and losing the private half makes those messages
// permanently unreadable. Regenerating the set on every run broke exactly that
// promise — the server rejected a second upload for the same IDs, and inbound
// prekey messages could not be opened. This file is the fix.
type keyFile struct {
	NextOneTimeID uint32              `json:"next_one_time_id"`
	Signed        serializedSignedKey `json:"signed"`
	NextSignedID  uint32              `json:"next_signed_id"`
	OneTime       []serializedOneKey  `json:"one_time"`
	Consumed      []uint32            `json:"consumed"`
	// Published records that the current set is on the server, so a later run
	// does not upload it again and get rejected.
	Published bool `json:"published"`
}

type serializedSignedKey struct {
	ID        uint32 `json:"id"`
	Private   []byte `json:"private"`
	Public    []byte `json:"public"`
	Signature []byte `json:"signature"`
}

type serializedOneKey struct {
	ID      uint32 `json:"id"`
	Private []byte `json:"private"`
	Public  []byte `json:"public"`
}

// seedFromRecord puts the signed prekey that pairing registered into the key
// file, so inbound messages addressed to that key can still be opened.
//
// This is the difference between a working client and a broken one: peers fetch
// the bundle as soon as the device appears, and every message they send before
// the next rotation is encrypted to this key. Losing it does not degrade
// anything visibly — it silently makes those messages unreadable forever.
func (k *keyFile) seedFromRecord(record *credentialRecord) {
	if len(record.SignedPreKey.Private) != signal.KeySize {
		return
	}
	k.Signed = serializedSignedKey{
		ID:        record.SignedPreKey.ID,
		Private:   append([]byte(nil), record.SignedPreKey.Private...),
		Public:    append([]byte(nil), record.SignedPreKey.Public...),
		Signature: append([]byte(nil), record.SignedPreKey.Signature...),
	}
	if record.SignedPreKey.ID >= k.NextSignedID {
		k.NextSignedID = record.SignedPreKey.ID + 1
	}
}

// loadKeyFile reads the key store, returning a fresh empty one when the file
// does not exist yet.
func loadKeyFile(path string) (*keyFile, error) {
	if path == "" {
		return nil, fmt.Errorf("no key file path")
	}
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return &keyFile{NextOneTimeID: 1}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read key file: %w", err)
	}
	var file keyFile
	if err := json.Unmarshal(raw, &file); err != nil {
		return nil, fmt.Errorf("decode key file: %w", err)
	}
	if file.NextOneTimeID == 0 {
		file.NextOneTimeID = 1
	}
	return &file, nil
}

// save writes the key store with owner-only permissions.
func (k *keyFile) save(path string) error {
	if path == "" {
		return fmt.Errorf("no key file path")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create key directory: %w", err)
	}
	raw, err := json.MarshalIndent(k, "", "  ")
	if err != nil {
		return fmt.Errorf("encode key file: %w", err)
	}
	raw = append(raw, '\n')
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		return fmt.Errorf("write key file: %w", err)
	}
	return nil
}

// publishFreshBatch tops the server up with a brand-new set of one-time
// prekeys. The private halves are written to disk BEFORE the upload: a crash
// mid-upload must not orphan a key the server has already handed to peers
// (PF-085). Silence from the upload is not fatal — the server's own count,
// queried right after, is the only verdict that matters (PF-082 re-test).
func publishFreshBatch(ctx context.Context, d *dispatcher, record *credentialRecord, keys *keyFile, signer signal.XEdDSASigner, path string) error {
	fresh, err := keys.generateFresh(preKeyBatch, signer)
	if err != nil {
		return err
	}
	signed, err := keys.signedPreKey()
	if err != nil {
		return err
	}
	if err := keys.save(path); err != nil {
		return err
	}
	if uploadErr := uploadPreKeysVia(ctx, d, record, fresh, *signed); uploadErr != nil {
		fmt.Printf("prekeys: top-up upload not acknowledged (%v)\n", uploadErr)
		return nil
	}
	keys.Published = true
	return keys.save(path)
}

// store converts the file into the receiver's key source.
func (k *keyFile) store(identity signal.KeyPair) (*preKeyStore, error) {
	signed, err := k.signedPreKey()
	if err != nil {
		return nil, err
	}
	source := &preKeyStore{
		identity: identity,
		signed:   *signed,
		oneTime:  make(map[uint32]signal.PreKey, len(k.OneTime)),
	}
	for _, key := range k.OneTime {
		parsed, err := key.toSignal()
		if err != nil {
			return nil, err
		}
		source.oneTime[parsed.ID] = parsed
	}
	return source, nil
}

func (k *keyFile) signedPreKey() (*signal.SignedPreKey, error) {
	if len(k.Signed.Private) != signal.KeySize || len(k.Signed.Public) != signal.KeySize {
		return nil, fmt.Errorf("signed prekey in key file has the wrong length")
	}
	if len(k.Signed.Signature) != signal.SignatureSize {
		return nil, fmt.Errorf("signed prekey signature is %d bytes, want %d", len(k.Signed.Signature), signal.SignatureSize)
	}
	var pair signal.KeyPair
	copy(pair.Private[:], k.Signed.Private)
	copy(pair.Public[:], k.Signed.Public)
	return &signal.SignedPreKey{
		ID:        k.Signed.ID,
		Pair:      pair,
		Signature: append([]byte(nil), k.Signed.Signature...),
	}, nil
}

func (o serializedOneKey) toSignal() (signal.PreKey, error) {
	if len(o.Private) != signal.KeySize || len(o.Public) != signal.KeySize {
		return signal.PreKey{}, fmt.Errorf("one-time prekey %d has the wrong length", o.ID)
	}
	var pair signal.KeyPair
	copy(pair.Private[:], o.Private)
	copy(pair.Public[:], o.Public)
	return signal.PreKey{ID: o.ID, Pair: pair}, nil
}

// nextSignedID hands out an unused signed-prekey id.
//
// Reusing an id is not cosmetic: the server keeps the first key it accepted for
// an id, so a second upload of the same id with a different key is silently
// pointless — and any peer encrypting to the old key produces messages this
// device cannot open.
func (k *keyFile) nextSignedID() uint32 {
	if k.NextSignedID == 0 {
		k.NextSignedID = 1
	}
	id := k.NextSignedID
	k.NextSignedID++
	return id
}

// addSigned stores a freshly generated signed prekey.
func (k *keyFile) addSigned(key signal.SignedPreKey) {
	if key.ID >= k.NextSignedID {
		k.NextSignedID = key.ID + 1
	}
	k.Signed = serializedSignedKey{
		ID:        key.ID,
		Private:   append([]byte(nil), key.Pair.Private[:]...),
		Public:    append([]byte(nil), key.Pair.Public[:]...),
		Signature: append([]byte(nil), key.Signature...),
	}
}

// addOneTime stores a one-time prekey and advances the id counter.
func (k *keyFile) addOneTime(key signal.PreKey) {
	k.OneTime = append(k.OneTime, serializedOneKey{
		ID:      key.ID,
		Private: append([]byte(nil), key.Pair.Private[:]...),
		Public:  append([]byte(nil), key.Pair.Public[:]...),
	})
	if key.ID >= k.NextOneTimeID {
		k.NextOneTimeID = key.ID + 1
	}
}

// generate fills the file to at least count one-time prekeys, generating
// fresh IDs from the persistent counter so an ID is never reused.
func (k *keyFile) generate(count int, signer signal.Signer) ([]signal.PreKey, error) {
	var added []signal.PreKey
	for len(k.OneTime)+len(added) < count {
		key, err := signal.GeneratePreKey(k.NextOneTimeID)
		if err != nil {
			return nil, fmt.Errorf("one-time prekey %d: %w", k.NextOneTimeID, err)
		}
		k.NextOneTimeID++
		k.addOneTime(key)
		added = append(added, key)
	}
	if len(k.Signed.Signature) != signal.SignatureSize {
		signed, err := signal.GenerateSignedPreKey(k.nextSignedID(), signer)
		if err != nil {
			return nil, fmt.Errorf("signed prekey: %w", err)
		}
		k.addSigned(signed)
	}
	return added, nil
}

// generateFresh creates count new one-time prekeys regardless of how many the
// file already holds, for a top-up upload when the server's count hits zero.
func (k *keyFile) generateFresh(count int, signer signal.Signer) ([]signal.PreKey, error) {
	var added []signal.PreKey
	for i := 0; i < count; i++ {
		key, err := signal.GeneratePreKey(k.NextOneTimeID)
		if err != nil {
			return nil, fmt.Errorf("one-time prekey %d: %w", k.NextOneTimeID, err)
		}
		k.NextOneTimeID++
		k.addOneTime(key)
		added = append(added, key)
	}
	return added, nil
}

// consume removes a one-time prekey that has been used, so a replay cannot
// reuse it and the file does not grow without bound.
func (k *keyFile) consume(id uint32) {
	for i := range k.OneTime {
		if k.OneTime[i].ID != id {
			continue
		}
		k.OneTime = append(k.OneTime[:i], k.OneTime[i+1:]...)
		k.Consumed = append(k.Consumed, id)
		return
	}
}

// publishMissingKeys uploads the key set only when the server has not seen it.
//
// Re-uploading the same ids is rejected, and generating new ones each run
// orphans every message addressed to the old set. The reference solves this by
// querying the count first and skipping when the server already holds enough.
func publishMissingKeys(ctx context.Context, d *dispatcher, record *credentialRecord, keys *keyFile, path string) error {
	if keys.Published {
		fmt.Println("prekeys: already published by an earlier run, not re-uploading")
		return nil
	}

	oneTime := make([]signal.PreKey, 0, len(keys.OneTime))
	for _, stored := range keys.OneTime {
		key, err := stored.toSignal()
		if err != nil {
			return err
		}
		oneTime = append(oneTime, key)
	}
	signed, err := keys.signedPreKey()
	if err != nil {
		return err
	}
	// A rejected upload is not fatal here. The device already has a working key
	// set on the server from pairing, and the server answers a repeat upload
	// with silence rather than an error. Reporting the silence as a failure
	// would stop a session that can actually receive messages.
	uploadErr := uploadPreKeysVia(ctx, d, record, oneTime, *signed)
	if uploadErr != nil {
		fmt.Printf("prekeys: upload not acknowledged (%v)\n", uploadErr)
		fmt.Println("prekeys: continuing with the key set pairing registered")
		return nil
	}
	keys.Published = true
	return keys.save(path)
}
