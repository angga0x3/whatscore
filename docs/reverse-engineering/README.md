# Reverse-Engineering Methodology

How the protocol findings in [../protocol/README.md](../protocol/README.md)
are obtained. The discipline matters as much as the technique: the WhatsApp
Web protocol is proprietary and unpublished, so every fact this project
relies on must be traceable to an ethical, reproducible observation.

The method below is inspired by the WhatsApp Calls Research Group's
write-up of their techniques
([wacrg.org/spec/techniques](https://wacrg.org/spec/techniques/)) — a good
example of disciplined, ethical protocol research where every published fact
carries its provenance and confidence. WhatsCore is not affiliated with that
group; we share the attitude: own-account observations, graded confidence,
provenance on every claim.

## The method loop

Every finding follows the same loop, in order:

1. **Observe** — connect with your own device and your own session and
   capture what actually happens on the wire. Log the date; keep nothing
   personal.
2. **Hypothesize** — write a specific, falsifiable guess about what the
   observed bytes or behavior mean.
3. **Minimal repro** — build the smallest experiment that would fail if the
   hypothesis were wrong.
4. **Extract test vector** — turn the observation into a synthetic,
   deterministic fixture (hex + JSON mirror; conventions in
   [../../tests/fixtures/README.md](../../tests/fixtures/README.md)).
5. **Add CI test** — encode the expectation as a test under `tests/protocol/`
   so the hypothesis is now checked on every commit.
6. **Record finding with provenance** — add the record to
   [../protocol/README.md](../protocol/README.md) with source, observation
   date, confidence, and the proving test.

The loop is finished only when the finding exists. A good observation that
never becomes a test plus a finding is work half-done — it stays folklore,
and folklore does not enter the codebase.

## Techniques allowed

- **Observing traffic of connections you own.** Capture frames from sessions
  you established with your own account and your own device.
- **Instrumenting your own client sessions.** Add logging around your own
  WhatsCore engine (or a scratch client) to inspect pre- and post-encryption
  data of your own connection.
- **Comparing library behaviors.** Read-only reference study of existing
  open implementations — for example wax or chiwa-go — for orientation:
  which layers exist, what to look for, which constants matter. This is a
  source of *hypotheses*, never of code:
  - never copy code wholesale or in fragments from other implementations;
  - check the license of anything you read and note it in the finding's
    Notes; license-incompatible material must not shape committed artifacts;
  - anything adopted into WhatsCore must be re-derived through the loop
    above and proven by our own tests.

Techniques outside this list (capturing third-party traffic, probing beyond
your own session, decompiling WhatsApp's clients) are out of scope for this
project and produce no findings here.

## Ethics & legal boundaries

Non-negotiable. A contribution that crosses any of these lines is rejected
regardless of technical merit.

- **Only use accounts and devices you control.** Never experiment against
  someone else's account, number, or device — including a friend's session,
  even with their blessing.
- **Respect WhatsApp's Terms of Service.** Understand that unofficial clients
  violate them and carry a real risk of **account restriction or ban** — use
  dedicated accounts for research, never your personal number.
- **Never intercept third-party traffic.** No man-in-the-middle of other
  people's connections and no capturing traffic you are not a party to.
- **Never publish credentials, QR codes, or personal data.** This includes
  session keys, phone numbers, contact lists, and message content — in
  findings, fixtures, issues, logs, and screenshots alike.
- **Coordinate any disclosure that could enable abuse.** Findings that would
  meaningfully enable spam, harassment, bulk automation, or account
  compromise are reported privately first (see
  [../../SECURITY.md](../../SECURITY.md)) rather than published as-is.
- **No false feature claims.** If a behavior is untested, say so. Demo >
  promises — compatibility is proven by tests, never claimed in prose.

## What belongs in this folder

Going forward, this folder accumulates **per-layer methodology notes** as
work progresses (Phase 1 and later) — one file per layer, each describing
what to observe, how to capture it, and how a capture becomes a fixture and
a finding:

- `transport.md` — observing the WebSocket transport: endpoints, framing,
  keepalive behavior, capture setup.
- `binary.md` — working out the node codec: token dictionary recovery,
  string/int encoding, fixture conventions for wire captures.
- `crypto.md` — studying the Noise handshake and the Signal-style layer:
  key-derivation observations, synthetic-key discipline, test strategy.

Do not create a file before there is real content for it.

---

Status: methodology only — first per-layer notes land with Phase 1
(Transport & Noise).
