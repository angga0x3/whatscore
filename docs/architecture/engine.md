# Engine orchestration (`core/engine`)

`core/engine` is the thin layer that turns the existing protocol modules into
an actual connection sequence. Until now every module was proven in isolation
(`protocol/*` against the fake server, `core/session` for lifecycle) but
nothing wired dial → handshake → payload → pairing. This package is that
wiring, and it deliberately contains no wire format and no cryptography of its
own.

Scope: one dial, one Noise handshake, one connection. Reconnection, backoff,
and session lifecycle stay in `core/session`; Signal sessions and message
encryption stay in `core/messaging` / `protocol/signal`.

## Connect sequence

```
 caller                     core/engine                      protocol modules
   │                            │                                   │
   │ New(Config)                │ validate + default                │
   ├───────────────────────────►│                                   │
   │                            │                                   │
   │ Connect(ctx)               │                                   │
   ├───────────────────────────►│                                   │
   │                    ┌───────┴────────┐                          │
   │                    │ clientPayload  │  auth.BuildLoginPayload  │
   │                    │  (select form) │  auth.BuildClientPayload │
   │                    └───────┬────────┘  (PF-020..PF-027)        │
   │                            │                                   │
   │                    ┌───────┴────────┐                          │
   │                    │ Dialer.Dial    │  transport.Dialer        │
   │                    └───────┬────────┘  (PF-002, PF-003)        │
   │                            │                                   │
   │                    ┌───────┴────────────────┐                  │
   │                    │ noise.DoClientHandshake│  PF-004..PF-009  │
   │                    │  msg1 clientHello      │                  │
   │                    │  msg2 serverHello+cert │                  │
   │                    │  msg3 clientFinish     │                  │
   │                    │       payload = above  │                  │
   │                    └───────┬────────────────┘                  │
   │                            │ SecureConn (write/read keys)      │
   │◄───────────────────────────┤ *Conn                             │
   │                            │                                   │
   │ WriteNode / ReadNode       │  binary.Codec (dictionary injected)
   ├───────────────────────────►│  protocol/binary (PF-010..PF-014) │
   │                            │                                   │
   │ Pump / StartPump           │  FrameHandler per frame           │
   ├───────────────────────────►│  (core/messaging.Receiver plugs in)
```

Why this order: the payload must exist before the handshake because Noise
`msg3.payload` carries it encrypted (PF-007), and the handshake must be built
before the dial is usable for nodes. Dialing first would also work, but
building the payload first means a configuration error fails before a socket
is opened.

## Pairing sequence

```
 server                                   core/engine
   │  iq{type=get, id, from}                 │
   │   └ pair-device                         │
   │      ├ ref: "abc"                       │
   │      └ ref: "def"                       │
   ├────────────────────────────────────────►│
   │                                         │ pairing.ParsePairDevice
   │                                         │   → []string refs
   │                                         │ pairing.PairDeviceAck
   │◄────────────────────────────────────────┤ iq{to=from, id, type=result}
   │                                         │
   │                                         │ per ref: pairing.QRPayload
   │                                         │   {Ref, NoisePub, IdentityPub,
   │                                         │    AdvSecret, ClientType}
   │                                         │ payload.Encode() → QR string
   │                                         │   → channel + optional Bus event
   │                                         │
   │  iq{type=result, id}                    │
   │   └ pair-success                        │
   │      ├ device{jid, lid}                 │
   │      ├ biz{name}, platform{name}        │
   │      ├ client-props (bytes)             │
   │      └ device-identity (bytes)          │
   ├────────────────────────────────────────►│
   │                                         │ pairing.ParsePairSuccess
   │                                         │ pairing.VerifyDeviceIdentity
   │                                         │   (HMAC + account XEdDSA,
   │                                         │    PF-017)
   │                                         │
   │                                         │ Signer == nil ?
   │                                         │   → ErrSignerRequired
   │                                         │ Signer set: CredentialResult
   │◄────────────────────────────────────────┤   (DeviceSignature empty)
```

`StartPairing` returns the QR batch channel immediately and runs the reader in
a goroutine; `WaitPairing` blocks for the outcome. Both the ack and the QR
payloads are produced before the flow waits for `pair-success`, which is what
a real client does: the user scans while the server waits.

## What is injected (and why)

| Injected | Type | Rationale |
|---|---|---|
| `Dialer` | `transport.Dialer` | The engine never constructs a socket, so tests run over an in-memory pipe and production injects `transport.WebSocketDialer` (§4.1). |
| `NoiseKey` | `noise.KeyPair` | Long-lived static key (PF-006, PF-007); its public half also appears in the QR payload. |
| `RootPub` | `[]byte` (32) | Pinned server root for certificate verification (PF-009). Required, because accepting any root would make PF-009 decorative. |
| `Identity` | `signal.KeyPair` | Registration identity key (PF-023) and QR identity key (PF-015). |
| `RegistrationID` | `uint32` | `eRegid` in the registration payload (PF-023). |
| `PreKeys` | `PreKeyProvider` (`Bundle(bool) signal.PreKeyBundle`) | Supplies the signed prekey + signature for the registration form. `*core/prekeys.Manager` satisfies it directly, so the engine does not import `core/prekeys`. |
| `Signer` | `signal.Signer` | Gates the signing step of PF-017 (see below). |
| `Credentials` | `*Credentials` | Presence selects the login form (PF-026) instead of registration (PF-020). |
| `AdvSecret`, `ClientType` | `[32]byte`, `string` | QR payload fields (PF-015) and the HMAC key of PF-017. |
| `Codec` | `binary.Codec` | The token dictionary is data, not code (§4.3); `nil` means `binary.NewCodec(nil)` (empty dictionary, every string raw). |
| `FrameHandler` | `FrameHandler` | Structurally identical to `core/session.FrameHandler`, so `*core/messaging.Receiver` is passed without importing it. |
| `Bus`, `Logger` | `*events.Bus`, `*slog.Logger` | Pairing codes become `events.TypePairingCode` (protocol types never cross the boundary); logs use the session's logger. |

Deliberate non-dependency: the engine does **not** import `core/messaging`.
`Receiver.HandleFrame` already has the right signature, and callers (the SDK
facade, or `core/session` as `Connector`) compose the two. This keeps the
import direction `core/engine → protocol/*` and avoids a cycle the moment
`core/messaging` wants an engine helper.

## Reader ownership

A `transport.FrameConn` supports exactly one reader. The engine enforces it:

- `Pump` / `StartPump` claim the reader slot and feed every frame to the
  configured `FrameHandler`.
- `ReadNode` claims the slot for one frame.
- `StartPairing` claims the slot for the whole pairing exchange.

A second concurrent reader returns `ErrReaderBusy` naming the current owner
instead of racing inside AES-GCM counters. `WriteNode` is independent and may
run concurrently with any reader, which is what the pairing ack relies on.

## What is not wired, and why

**Device-identity signing (PF-017 deviceSignature).** `pairing.VerifyDeviceIdentity`
authenticates the server's container, but the companion's own
`deviceSignature` is an XEdDSA signature over
`0x06 0x01 ‖ details ‖ identityPub ‖ accountSignatureKey` produced with the
device identity private key. `protocol/signal` exposes a `Signer` for *prekey*
signatures (`0x05 ‖ prekey`) only; there is no device-identity signer, and
ADR 0001 keeps XEdDSA signing out of the standard library path. Rather than
silently returning an unsigned credential, the flow:

1. verifies the container (HMAC-SHA256 with the adv secret, then the account
   XEdDSA signature over the identity key);
2. if no `Signer` is configured, returns `ErrSignerRequired` with the JID in
   the message;
3. if a `Signer` is configured, returns a `CredentialResult` whose
   `DeviceSignature` is still `nil`, because generating it is the missing
   step. Callers must not persist the record until that lands.

**Challenge handling / registration crypto.** `protocol/auth` builds and
parses payloads; the post-handshake `<success>`/`<failure>` and challenge
exchange is not modelled anywhere yet, so the engine stops at "handshake
completed". `Connect` succeeding means the Noise channel is up and the
payload was accepted structurally, not that the account is authenticated.

**Reconnect and lifecycle.** Deliberately out of scope: this package is one
dial, one handshake, one connection. `core/session` already owns retry via
`transport.ReconnectPolicy`, but its `Connector` slot is
`Connect(ctx, raw FrameConn) (transport.FrameConn, error)` — a shape the
engine does not use, because `Engine.Connect` owns the dial itself. Bridging
the two (an adapter that hands the engine an already-dialed frame connection)
is a small follow-up and is intentionally not part of this package; the
duplicate dial path would otherwise be untested.

**Live interop.** All tests run against an in-test fake server. PF-002/PF-003
remain Probable until a manual live run; the engine does not change that.

## Findings map

| Finding | Where it is used |
|---|---|
| PF-004, PF-005, PF-006, PF-008 | `noise.DoClientHandshake` + `Conn.WriteNode`/`ReadNode` framing (unchanged, called once per connection) |
| PF-007 | The three-message handshake; `msg3.payload` is the built `ClientPayload` |
| PF-009 | `RootPub` is required and passed straight to the handshake's certificate check |
| PF-015 | `pairing.QRPayload.Encode`, one payload per `<ref>`, `ClientType`/`AdvSecret` from config |
| PF-016 | `pairing.ParsePairDevice`, `pairing.PairDeviceAck`, `pairing.ParsePairSuccess` |
| PF-017 | `pairing.VerifyDeviceIdentity`; the device signature is the documented gap |
| PF-020…PF-025 | `auth.BuildClientPayload` with prekeys from `PreKeyProvider` |
| PF-026, PF-027 | `auth.BuildLoginPayload` when `Credentials` is set; the two forms are mutually exclusive by construction |
| PF-010…PF-014 | `binary.Codec` injected in `Config.Codec`, default empty dictionary |

## Tests

`core/engine/engine_test.go` builds its own fake server: an in-memory
`transport.FrameConn` pair, the server role of the PF-007 handshake written
against the public `noise.NewHandshake`, a synthetic PF-009 chain signed by a
generated test root, and a server-side AES-256-GCM frame layer for PF-008. It
imports no test helpers from other packages. Coverage:

| Test | Proves |
|---|---|
| `TestConnectRegistrationPayload` | dial → handshake → registration payload inside msg3, then nodes both ways |
| `TestConnectLoginPayload` | login form chosen when `Credentials` is set; each parser rejects the other form |
| `TestStartPairingEmitsQRPayloads` | pair-device ack + one QR payload per ref, plus `pairing_code` bus events |
| `TestPairingSuccessRequiresSigner` | verified pair-success with no signer → `ErrSignerRequired` |
| `TestPairingSuccessWithSigner` | verified pair-success → `CredentialResult` with JID/LID/identity |
| `TestPairingRejectsTamperedIdentity` | corrupted `device-identity` → `ErrPairingFailed` |
| `TestConnectRejectsUnknownServerRoot` | wrong pinned root → `ErrAuthFailed` |
| `TestPumpAndClose` | frame handler pump, `ErrReaderBusy`, clean shutdown, `ErrNotConnected` |
| `TestReaderOwnershipContract` | pairing owns the reader: second pairing and `ReadNode` refused; `WaitPairing` without `StartPairing` fails |
| `TestPairingNeedsAdvSecret` | a zero adv secret is refused before the reader is claimed |
| `TestConnectUsesInjectedCodec` | the injected dictionary actually changes the bytes on the wire |
| `TestConnectRejectsMismatchedPreKeyIdentity` | a prekey provider signed by a different identity fails before dialing |
| `TestNewValidation` | required fields and defaults |

No network, no sleeps: only context timeouts bound the flows.
