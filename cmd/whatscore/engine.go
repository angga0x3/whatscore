// engine.go builds the engine-backed session factory behind the REST service.
//
// Before this file existed the API's Manager created no core/session at all:
// POST /sessions registered a row and POST /sessions/{id}/connect flipped an
// in-memory string to "CONNECTED" without opening a socket. The factory below
// replaces that stub with a real session whose dial goes through
// transport.WebSocketDialer and whose handshake is core/engine.
//
// Layering:
//
//	api.Manager (REST view)  →  sessionFactory.newSession
//	                              ├── core/credentials (encrypted Record:
//	                              │     Noise key, identity key, adv secret,
//	                              │     registration id)
//	                              ├── core/prekeys (signed prekey behind the
//	                              │     same encrypted store)
//	                              └── core/engine.AuthConnector() → session.Connector
//
// core/session owns dialing, retry and lifecycle; core/engine owns the
// ClientPayload and the Noise handshake. The engine's connector rebuilds the
// payload on every attempt, so a rotated signed prekey is picked up without
// rebuilding the session.
//
// Every secret is written through storage/credentials.Vault (AES-256-GCM) or
// not at all: a factory built without a vault refuses to create sessions
// instead of running with unencrypted key material.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"golang.org/x/crypto/curve25519"

	"github.com/angga0x3/whatscore/config"
	corecredentials "github.com/angga0x3/whatscore/core/credentials"
	"github.com/angga0x3/whatscore/core/engine"
	"github.com/angga0x3/whatscore/core/events"
	"github.com/angga0x3/whatscore/core/prekeys"
	"github.com/angga0x3/whatscore/core/session"
	"github.com/angga0x3/whatscore/internal/waref"
	"github.com/angga0x3/whatscore/protocol/noise"
	"github.com/angga0x3/whatscore/protocol/signal"
	"github.com/angga0x3/whatscore/protocol/transport"
	storagecredentials "github.com/angga0x3/whatscore/storage/credentials"
	"github.com/angga0x3/whatscore/storage/envelope"
)

const (
	// credentialTimeout bounds the vault I/O done while a session is created,
	// so a slow or wedged database cannot pin an API request forever.
	credentialTimeout = 10 * time.Second

	// signedPreKeyID is the id of the single signed prekey this device
	// publishes in its registration payload. core/prekeys rotates the key in
	// place, so the id stays stable across restarts.
	signedPreKeyID = 1

	// signerSeedSuffix names the per-session Ed25519 seed record. The seed is
	// kept beside the core/credentials Record because that Record has no field
	// for it; identityFromSeed derives the Signal identity key from the seed so
	// prekey signatures verify under the identity that the payload carries.
	signerSeedSuffix = "/signer-seed"
)

// Factory sentinel errors. Callers match with errors.Is.
var (
	// ErrEncryptionKeyRequired is returned when production configuration has
	// no ENCRYPTION_KEY. config.Load already rejects that combination; the
	// check is repeated here so an embedder that builds a config by hand still
	// fails closed instead of storing key material in the clear.
	ErrEncryptionKeyRequired = errors.New("cmd/whatscore: ENCRYPTION_KEY is required in production")

	// ErrEncryptionKeyInvalid is returned when ENCRYPTION_KEY is set but is
	// not a base64-encoded 32-byte key.
	ErrEncryptionKeyInvalid = errors.New("cmd/whatscore: invalid ENCRYPTION_KEY")

	// ErrNoCredentialVault is returned when a session would have to run
	// without an encrypting store. Falling back to plaintext keys is never an
	// acceptable failure mode.
	ErrNoCredentialVault = errors.New("cmd/whatscore: session factory has no encrypted credential vault")

	// ErrCredentialState is returned when persisted key material is internally
	// inconsistent (for example a Record whose identity does not match the
	// signing seed). Guessing would silently produce a device the server
	// rejects, so this fails closed.
	ErrCredentialState = errors.New("cmd/whatscore: inconsistent session credentials")

	// ErrInvalidSessionID is returned for a session id that cannot be used as
	// a credential record key.
	ErrInvalidSessionID = errors.New("cmd/whatscore: invalid session id")
)

// newCredentialVault builds the encrypting store for session secrets.
//
// With ENCRYPTION_KEY set, secrets are sealed with that key and persisted in
// backend. Without it, development falls back to an in-memory backend and an
// ephemeral key: `docker compose up` works with no configuration, at the cost
// of losing every device identity on restart. Production never takes that
// fallback (config.Load enforces the key) and this function refuses it.
func newCredentialVault(cfg *config.Config, backend storagecredentials.Backend, logger *slog.Logger) (*storagecredentials.Vault, error) {
	if cfg == nil {
		return nil, fmt.Errorf("%w: nil config", ErrNoCredentialVault)
	}
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}

	if key := strings.TrimSpace(cfg.Security.EncryptionKey); key != "" {
		parsed, err := envelope.ParseKey(key)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrEncryptionKeyInvalid, err)
		}
		if backend == nil {
			return nil, fmt.Errorf("%w: ENCRYPTION_KEY is set but no storage backend was provided", ErrNoCredentialVault)
		}
		return storagecredentials.NewVault(backend, parsed)
	}

	if cfg.IsProduction() {
		return nil, fmt.Errorf("%w: generate one with `openssl rand -base64 32`", ErrEncryptionKeyRequired)
	}

	// Development only: encrypt with a throwaway key held in process memory.
	// The warning is deliberately loud because device identities do not
	// survive a restart in this mode.
	logger.Warn("ENCRYPTION_KEY is not set; session keys are encrypted with an ephemeral in-memory key and will not survive a restart")
	raw := make([]byte, envelope.KeySize)
	if _, err := rand.Read(raw); err != nil {
		return nil, fmt.Errorf("cmd/whatscore: ephemeral credential key: %w", err)
	}
	key, err := envelope.NewKey(raw)
	if err != nil {
		return nil, fmt.Errorf("cmd/whatscore: ephemeral credential key: %w", err)
	}
	// The passed backend is intentionally ignored: records sealed with a
	// throwaway key must not be written to durable storage, where the next
	// process could not read them.
	return storagecredentials.NewVault(storagecredentials.NewMemoryBackend(), key)
}

// sessionFactoryOptions are the factory's dependencies.
//
// Dialer, Endpoint and RootPub exist so tests can drive the whole factory
// against an in-memory fake server; production leaves them zero and gets
// transport.DefaultEndpoint() and the pinned internal/waref root key.
type sessionFactoryOptions struct {
	// vault is the encrypting store for every session secret. Required.
	vault *storagecredentials.Vault

	// bus receives session lifecycle events. Required: core/session rejects a
	// nil bus.
	bus *events.Bus

	// logger receives structured lifecycle logs.
	logger *slog.Logger

	// dialer opens the transport connection. Unset means
	// transport.WebSocketDialer.
	dialer transport.Dialer

	// endpoint is passed verbatim to the dialer. Unset means
	// transport.DefaultEndpoint().
	endpoint transport.Endpoint

	// rootPub is the pinned 32-byte Noise server root key. Unset means
	// waref.RootPublicKey().
	rootPub []byte

	// handler consumes inbound frames after the handshake. Nil discards them;
	// core/session still reads, so a dropped connection is detected.
	handler session.FrameHandler
}

// sessionFactory builds one core/session per API session. It holds no
// per-session state, so it is safe for concurrent use.
type sessionFactory struct {
	credentials *corecredentials.Manager
	vault       *storagecredentials.Vault
	bus         *events.Bus
	logger      *slog.Logger
	dialer      transport.Dialer
	endpoint    transport.Endpoint
	rootPub     []byte
	handler     session.FrameHandler
}

// newSessionFactory validates its dependencies once, so a misconfigured
// process fails at startup rather than on the first POST /sessions.
func newSessionFactory(opts sessionFactoryOptions) (*sessionFactory, error) {
	if opts.vault == nil {
		return nil, fmt.Errorf("%w: refusing to create sessions without encryption", ErrNoCredentialVault)
	}
	if opts.bus == nil {
		return nil, fmt.Errorf("cmd/whatscore: session factory needs an event bus")
	}
	logger := opts.logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	dialer := opts.dialer
	if dialer == nil {
		dialer = &transport.WebSocketDialer{}
	}
	endpoint := opts.endpoint
	if endpoint.URL == "" {
		endpoint = transport.DefaultEndpoint()
	}
	rootPub := opts.rootPub
	if len(rootPub) == 0 {
		rootPub = waref.RootPublicKey()
	}
	if len(rootPub) != 32 {
		return nil, fmt.Errorf("cmd/whatscore: root public key must be 32 bytes, got %d", len(rootPub))
	}

	manager, err := corecredentials.NewManager(opts.vault)
	if err != nil {
		return nil, fmt.Errorf("cmd/whatscore: credential manager: %w", err)
	}

	return &sessionFactory{
		credentials: manager,
		vault:       opts.vault,
		bus:         opts.bus,
		logger:      logger,
		dialer:      dialer,
		endpoint:    endpoint,
		rootPub:     append([]byte(nil), rootPub...),
		handler:     opts.handler,
	}, nil
}

// newSession is the api.WithSessionFactory hook. It loads (or creates) the
// session's key material and returns a session that dials for real when
// Connect is called.
//
// The factory signature has no context because api.Manager calls it during
// CreateSession; the vault work is bounded by credentialTimeout instead.
func (f *sessionFactory) newSession(id string) (*session.Session, error) {
	ctx, cancel := context.WithTimeout(context.Background(), credentialTimeout)
	defer cancel()

	connector, err := f.engineConnector(ctx, id)
	if err != nil {
		return nil, err
	}

	sess, err := session.New(session.Config{
		ID:           id,
		Endpoint:     f.endpoint,
		Dialer:       f.dialer,
		Connector:    connector,
		FrameHandler: f.handler,
		Bus:          f.bus,
		Logger:       f.logger,
	})
	if err != nil {
		return nil, fmt.Errorf("cmd/whatscore: build session %s: %w", id, err)
	}
	return sess, nil
}

// engineConnector builds the core/session.Connector for one session: it
// constructs a core/engine from the session's persisted key material and
// returns the engine's handshake adapter.
//
// This is the "level-appropriate construction" boundary: the engine is built
// here, once per session, and knows nothing about credentials or storage.
func (f *sessionFactory) engineConnector(ctx context.Context, id string) (session.Connector, error) {
	if f.vault == nil {
		return nil, fmt.Errorf("%w: session %s", ErrNoCredentialVault, id)
	}

	keys, err := f.loadKeys(ctx, id)
	if err != nil {
		return nil, err
	}

	eng, err := engine.New(engine.Config{
		SessionID:      id,
		Endpoint:       f.endpoint,
		Dialer:         f.dialer,
		NoiseKey:       keys.noiseKey,
		RootPub:        f.rootPub,
		Identity:       keys.identity,
		RegistrationID: keys.registrationID,
		PreKeys:        keys.preKeys,
		// Signer stays nil on purpose: it gates device-identity signing for
		// pairing (PF-017), which needs an XEdDSA signer that does not exist
		// yet (ADR 0001). Pairing therefore ends with ErrSignerRequired
		// instead of fabricating a signature.
		AdvSecret: keys.advSecret,
		Bus:       f.bus,
		Logger:    f.logger,
	})
	if err != nil {
		return nil, fmt.Errorf("cmd/whatscore: build engine for session %s: %w", id, err)
	}
	// AuthConnector finishes the post-handshake verdict, so a session only
	// reaches CONNECTED after the server accepted the payload. Connector alone
	// would report a healthy connection while the server was still deciding.
	return eng.AuthConnector(), nil
}

// sessionKeys is the engine-ready key material for one session.
type sessionKeys struct {
	noiseKey       noise.KeyPair
	identity       signal.KeyPair
	advSecret      [32]byte
	registrationID uint32
	preKeys        *prekeys.Manager
}

// loadKeys loads the session's key material, generating and persisting it on
// first use. Generation and persistence happen under the same encrypting
// vault, so no private key exists outside it.
func (f *sessionFactory) loadKeys(ctx context.Context, id string) (*sessionKeys, error) {
	if err := validateSessionID(id); err != nil {
		return nil, err
	}

	seed, err := f.loadSignerSeed(ctx, id)
	if err != nil {
		return nil, err
	}
	identity, signer, err := identityFromSeed(seed)
	if err != nil {
		return nil, err
	}

	record, err := f.credentials.Load(ctx, id)
	switch {
	case err == nil:
		noiseKey, noiseErr := noiseKeyFromRecord(record)
		if noiseErr != nil {
			return nil, fmt.Errorf("session %s: %w", id, noiseErr)
		}
		if record.IdentityPublicKey != identity.Public || record.IdentityPrivateKey != identity.Private {
			return nil, fmt.Errorf("%w: session %s identity does not match its signing seed", ErrCredentialState, id)
		}
		keys := &sessionKeys{
			noiseKey:       noiseKey,
			identity:       identity,
			advSecret:      record.AdvSecret,
			registrationID: record.RegistrationID,
		}
		if err := f.attachPreKeys(ctx, id, keys, signer); err != nil {
			return nil, err
		}
		return keys, nil

	case errors.Is(err, storagecredentials.ErrNotFound):
		// First use: generate a device and persist it before handing the keys
		// to the engine, so a crash cannot leave a device the server knows
		// about but this process cannot reproduce.
		noiseKey, genErr := noise.GenerateKeyPair()
		if genErr != nil {
			return nil, fmt.Errorf("session %s: noise key: %w", id, genErr)
		}
		registrationID, genErr := newRegistrationID()
		if genErr != nil {
			return nil, fmt.Errorf("session %s: registration id: %w", id, genErr)
		}
		record = &corecredentials.Record{
			NoisePrivateKey:    noiseKey.Priv,
			NoisePublicKey:     noiseKey.Pub,
			IdentityPrivateKey: identity.Private,
			IdentityPublicKey:  identity.Public,
			RegistrationID:     registrationID,
		}
		if _, genErr := rand.Read(record.AdvSecret[:]); genErr != nil {
			return nil, fmt.Errorf("session %s: adv secret: %w", id, genErr)
		}
		if saveErr := f.credentials.Save(ctx, id, record); saveErr != nil {
			return nil, fmt.Errorf("session %s: save credentials: %w", id, saveErr)
		}
		keys := &sessionKeys{
			noiseKey:       noiseKey,
			identity:       identity,
			advSecret:      record.AdvSecret,
			registrationID: record.RegistrationID,
		}
		if err := f.attachPreKeys(ctx, id, keys, signer); err != nil {
			return nil, err
		}
		return keys, nil

	default:
		return nil, fmt.Errorf("session %s: load credentials: %w", id, err)
	}
}

// attachPreKeys wires the signed prekey store for this session. core/prekeys
// generates the signed prekey on first use and persists it in the same vault.
func (f *sessionFactory) attachPreKeys(ctx context.Context, id string, keys *sessionKeys, signer signal.Signer) error {
	manager, err := prekeys.New(ctx, f.vault, id, keys.identity, signer, prekeys.Config{
		SignedPreKeyID: signedPreKeyID,
		// Registration does not publish a one-time prekey (PF-023), so none
		// are generated up front. Rotation stays manual until a caller
		// schedules it.
		OneTimeCount: 0,
		NotFound:     func(err error) bool { return errors.Is(err, storagecredentials.ErrNotFound) },
	})
	if err != nil {
		return fmt.Errorf("session %s: prekeys: %w", id, err)
	}
	keys.preKeys = manager
	return nil
}

// loadSignerSeed returns the session's Ed25519 signing seed, creating it on
// first use. The seed is the root of the device identity: identityFromSeed
// derives both the Curve25519 identity key pair and the prekey signer from it,
// which is what makes a signed prekey verifiable against the identity in the
// registration payload.
func (f *sessionFactory) loadSignerSeed(ctx context.Context, id string) ([]byte, error) {
	key := signerSeedKey(id)
	seed, err := f.vault.Get(ctx, key)
	switch {
	case err == nil:
		if len(seed) != ed25519.SeedSize {
			return nil, fmt.Errorf("%w: session %s signing seed is %d bytes, want %d",
				ErrCredentialState, id, len(seed), ed25519.SeedSize)
		}
		return seed, nil
	case errors.Is(err, storagecredentials.ErrNotFound):
		seed = make([]byte, ed25519.SeedSize)
		if _, err := rand.Read(seed); err != nil {
			return nil, fmt.Errorf("session %s: signing seed: %w", id, err)
		}
		if err := f.vault.Put(ctx, key, seed); err != nil {
			return nil, fmt.Errorf("session %s: save signing seed: %w", id, err)
		}
		return seed, nil
	default:
		return nil, fmt.Errorf("session %s: load signing seed: %w", id, err)
	}
}

// identityFromSeed derives the Signal identity key pair and the prekey signer
// from an Ed25519 seed.
//
// XEdDSA verifies a standard Ed25519 signature under the Montgomery form of the
// same key (PF-009, ADR 0001), so deriving the Curve25519 private scalar as
// SHA-512(seed)[0:32] clamped — the same construction core/prekeys tests use —
// keeps the signer and the published identity consistent.
func identityFromSeed(seed []byte) (signal.KeyPair, signal.Signer, error) {
	if len(seed) != ed25519.SeedSize {
		return signal.KeyPair{}, nil, fmt.Errorf("%w: signing seed is %d bytes, want %d",
			ErrCredentialState, len(seed), ed25519.SeedSize)
	}
	signing := ed25519.NewKeyFromSeed(seed)
	digest := sha512.Sum512(signing.Seed())

	var pair signal.KeyPair
	copy(pair.Private[:], digest[:32])
	pair.Private[0] &= 248
	pair.Private[31] &= 127
	pair.Private[31] |= 64
	pub, err := curve25519.X25519(pair.Private[:], curve25519.Basepoint)
	if err != nil {
		return signal.KeyPair{}, nil, fmt.Errorf("cmd/whatscore: derive identity key: %w", err)
	}
	copy(pair.Public[:], pub)
	return pair, signal.Ed25519Signer{Private: signing}, nil
}

// noiseKeyFromRecord rebuilds the Noise key pair and checks that its halves
// belong together, so a corrupted record fails at creation instead of
// producing an unopenable handshake.
func noiseKeyFromRecord(record *corecredentials.Record) (noise.KeyPair, error) {
	if record == nil {
		return noise.KeyPair{}, fmt.Errorf("%w: nil credential record", ErrCredentialState)
	}
	key := noise.KeyPair{Priv: record.NoisePrivateKey, Pub: record.NoisePublicKey}
	if key.Priv == ([32]byte{}) || key.Pub == ([32]byte{}) {
		return noise.KeyPair{}, fmt.Errorf("%w: noise key pair is unset", ErrCredentialState)
	}
	derived, err := curve25519.X25519(key.Priv[:], curve25519.Basepoint)
	if err != nil {
		return noise.KeyPair{}, fmt.Errorf("%w: derive noise public key: %w", ErrCredentialState, err)
	}
	if subtle.ConstantTimeCompare(derived, key.Pub[:]) != 1 {
		return noise.KeyPair{}, fmt.Errorf("%w: noise public key does not match its private key", ErrCredentialState)
	}
	return key, nil
}

// signerSeedKey names the signing seed record. It shares the "sessions/<id>/"
// prefix with core/credentials and core/prekeys so one session's records sort
// and delete together.
func signerSeedKey(id string) string { return "sessions/" + id + signerSeedSuffix }

// newRegistrationID returns a Signal registration id (1..16383, PF-023).
func newRegistrationID() (uint32, error) {
	var raw [2]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return 0, err
	}
	return uint32(binary.BigEndian.Uint16(raw[:])%16383) + 1, nil
}

// validateSessionID keeps credential record keys unambiguous. It mirrors the
// rule core/credentials and core/prekeys apply, so a bad id is reported here
// with the factory's own sentinel.
func validateSessionID(id string) error {
	if id == "" {
		return fmt.Errorf("%w: empty", ErrInvalidSessionID)
	}
	if len(id) > 128 {
		return fmt.Errorf("%w: %q longer than 128 bytes", ErrInvalidSessionID, id)
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' {
			continue
		}
		return fmt.Errorf("%w: %q contains %q", ErrInvalidSessionID, id, c)
	}
	return nil
}
