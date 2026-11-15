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

## Auth outcome sequence (`WaitAuth`)

`Connect` returning a `*Conn` means the Noise channel is up and the payload
was accepted *structurally*. Whether the device is authenticated is a separate
step: the server answers the payload with one stanza (PF-028, PF-029), and
`Conn.WaitAuth` reads it.

```
 server                                   core/engine
   │  (msg1/msg2/msg3, PF-007)              │
   │  <success lid=… t=…/>                  │  WaitAuth → nil
   ├────────────────────────────────────────►│
   │  <failure reason=… code=… message=…/>  │  WaitAuth → *AuthError
   ├────────────────────────────────────────►│    errors.Is → ErrAuthFailed
   │  <stream:error code=…>                 │  WaitAuth → *StreamError
   │   └ conflict type=…                    │    errors.Is → ErrStreamError
   ├────────────────────────────────────────►│
   │  <ack …/>                              │  skipped, keep waiting
   ├────────────────────────────────────────►│
   │  anything else                         │  WaitAuth → ErrUnexpectedStanza
   ├────────────────────────────────────────►│
```

| Stanza | Outcome | Error sentinel |
|---|---|---|
| `<success/>` (`lid`, `t` attributes) | `nil` | — |
| `<failure reason code message/>` | `*AuthError{Reason, ReasonRaw, Code, Message}` | `ErrAuthFailed` |
| `<stream:error code><conflict type/></stream:error>` | `*StreamError{Code, ConflictType}` | `ErrStreamError` |
| `<ack/>` | consumed, loop continues | — |
| anything else | `*ErrUnexpectedStanza` with the offending tag | `ErrUnexpectedStanza` |
| transport closed / ctx done | the transport error, or `ctx.Err()` | — (not `ErrAuthFailed`) |

**Policy for anything else: fail closed.** A stanza that is neither an auth
outcome nor the documented benign `ack` is reported rather than skipped. The
reason is reader ownership: `WaitAuth` holds the single reader slot, and a
skipped stanza would be lost to whoever needs it next. The concrete case is
registration, where the server sends `<iq><pair-device>` right after the
handshake; `StartPairing` must be the reader for that stanza. The reference
client avoids the problem differently — it routes every tag into a handler
queue — which this package deliberately does not have (one reader at a time).
Only the offending stanza is consumed; the reported error is fatal for the
connection from the caller's point of view.

`<ack/>` is the one skip. In whatsmeow's `handleFrame` it is explicitly
excluded from the "didn't handle node" log, i.e. an ack is an expected
background stanza with no payload this package needs.

Diagnostic text (`failure@message`, `failure@reason` when non-numeric,
`stream:error@code`, an unexpected tag) comes from the server, so it is
sanitized before it can reach a log or an error: control characters are
replaced and the value is truncated to 120 runes with an explicit `...`
marker. Log lines carry only the machine-readable `reason`/`code`/`conflict`,
never the free-form message.

`WaitAuth` releases the reader slot before returning, so `Pump`, `ReadNode`,
or `StartPairing` can take over. A second caller while it waits gets
`ErrReaderBusy`, like every other reader.

## Connector bridge (`Engine.Connector`)

`core/session` owns dialing, retry, and lifecycle; its `Connector` slot wraps
an already-dialed `transport.FrameConn` (for example with a handshake).
`Engine.Connector()` returns an adapter implementing exactly that interface, so
there is **one** dial path per process:

```
 composition root                core/session                core/engine
   │                                │                            │
   │ eng.Connector()                │                            │
   ├────────────────────────────────┼───────────────────────────►│ connector{eng}
   │ session.New(Config{            │                            │
   │   Dialer: dialer,              │                            │
   │   Connector: connector})       │                            │
   ├───────────────────────────────►│                            │
   │                                │ Dialer.Dial(ctx, endpoint) │
   │                                ├───────────────────────────►│   (transport)
   │                                │ raw FrameConn              │
   │                                │ Connector.Connect(ctx, raw)│
   │                                ├───────────────────────────►│ clientPayload()
   │                                │                            │ DoClientHandshake
   │                                │◄───────────────────────────┤ SecureConn
   │                                │ reader → FrameHandler      │
```

The adapter holds a `*Engine`, not a connection: it is stateless, safe to
share between sessions and reconnect attempts, and rebuilds the
`ClientPayload` on every attempt so rotated prekeys are picked up. Both
`Connect` and the adapter build the payload through `Engine.clientPayload` and
run the handshake through `Engine.handshakeOver`, so the payload construction
and the `ErrAuthFailed` wrapping exist once. The adapter returns the
`noise.SecureConn` itself rather than a `*Conn`, because `core/session` owns
the reader loop and a `*Conn` would also claim reader ownership.

Failure contract: a payload-build failure or handshake failure closes `raw`
before returning (the handshake already does this; the adapter closes it for
the payload-build case), and every error wraps `ErrAuthFailed`. A nil `raw`
is `ErrInvalidConfig`.

The dependency stays one-way: `core/engine` imports `core/session` for the
interface only, and `core/session` never imports `core/engine`. The adapter is
passed in from the composition root, which is why `tests/architecture` keeps
passing unchanged.

`WaitAuth` is *not* called by the connector: the session's frame reader starts
immediately after the connector returns, so the auth stanza is delivered to the
session's `FrameHandler`. A composition root that wants the typed outcome must
call `HandleFrame`-side or use `Engine.Connect` (which returns the `*Conn` and
leaves the reader free) and call `WaitAuth` before starting a pump.


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
facade) compose the two. The engine *does* import `core/session`, but only for
its `Connector` interface (`session.go`); `core/session` never imports
`core/engine`, so the direction stays one-way and the adapter is injected from
the composition root.

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
parses payloads and `Conn.WaitAuth` now maps the post-handshake
`<success>`/`<failure>`/`<stream:error>` outcome to typed errors (PF-028,
PF-029, see the sequence above). What is still not modelled is everything the
server may send *after* a `<success>` — the `ib` offline-sync prologue, the
`passive`/`active` IQ, prekey upload, and the `digest` check — plus any
challenge exchange for the registration form. `WaitAuth` returning nil
therefore means "the server accepted this device", not "the session is ready
for messaging".

**Reconnect and lifecycle.** Deliberately out of scope: this package is one
dial, one handshake, one connection. `core/session` already owns retry via
`transport.ReconnectPolicy`; `Engine.Connector` bridges its `Connector` slot
(see above), so the duplicate dial path is gone: the session dials, the
engine handshakes.

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
| PF-028 | `Conn.WaitAuth` treats `<success>` as the accepted outcome (its `lid`/`t` attributes are logged, not surfaced) |
| PF-029 | `Conn.WaitAuth` maps `<failure>` and `<stream:error>` to `*AuthError`/`*StreamError` |
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
| `TestWaitAuthSuccess` | `<success>` → nil; the reader slot is released afterwards |
| `TestWaitAuthSkipsAck` | a benign `<ack/>` is skipped, not reported |
| `TestWaitAuthFailureCarriesCode` | `<failure reason code message>` → `*AuthError` (reason, code, message) wrapping `ErrAuthFailed` |
| `TestWaitAuthFailureRequiresCode` | a non-numeric or absent reason still yields `ErrAuthFailed`, with the raw value reported |
| `TestWaitAuthStreamError` | `<stream:error code><conflict type>` → `*StreamError`, distinct from `ErrAuthFailed` |
| `TestWaitAuthUnexpectedStanza` | fail-closed policy: a `<pair-device>` is reported as `ErrUnexpectedStanza` and only that stanza is consumed |
| `TestWaitAuthTimeout` | the wait ends at the caller's context deadline and is not reported as an auth failure |
| `TestWaitAuthReaderOwnership` | `WaitAuth` competes for the reader slot (`ErrReaderBusy`), and a closed Conn returns `ErrNotConnected` |
| `TestWaitAuthSanitizesServerText` | server text is control-character-stripped and capped at 120 runes |
| `TestConnectorPerformsHandshake` | `session.Connector` from `Engine.Connector()` handshakes over an in-memory pipe and returns an encrypted connection whose frames do not decode as plaintext |
| `TestConnectorRejectsUnknownRoot` | a failed handshake over an already-dialed connection wraps `ErrAuthFailed` and closes the raw connection |
| `TestConnectorDrivesSession` | composition-root shape: `session` dials once, the engine connector handshakes on that same connection, and frames round-trip through the session encrypted |

No network, no sleeps: only context timeouts bound the flows.
