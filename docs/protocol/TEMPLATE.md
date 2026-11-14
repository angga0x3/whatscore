# Finding template

Copy the skeleton below into [README.md](README.md), assign the next free
`PF-NNN` ID, replace every placeholder, and add a matching row to the
findings index table. Field definitions and lifecycle rules live in
[README.md](README.md) — do not invent new fields or new confidence levels.

---

<!-- copy from here -->

## PF-XXX — EXAMPLE (synthetic): placeholder finding title

- **Layer:** transport
- **Source:** direct observation of own session
- **Observed date:** YYYY-MM-DD
- **Confidence:** Speculative — single observation; not yet reproduced or
  tested
- **Status:** Observed-only
- **Proving test:** none yet — target path `tests/protocol/<area>/<name>_test.go`
- **Related findings:** none (or: depends on PF-YYY · supersedes PF-YYY ·
  contradicted by PF-YYY)
- **Notes:** Placeholder text. Record what was observed and how it was
  captured, in enough detail that another contributor could reproduce the
  observation against their own session. If the finding is later reopened or
  retired, keep every earlier observation here as history — never delete it.

<!-- copy until here -->

---

Checklist before opening the PR:

- [ ] Layer is one of `transport`, `noise`, `binary`, `pairing`, `signal`,
      `sync`, `media`
- [ ] Source is one of `direct observation of own session`,
      `captured handshake of own device`, `derived from test`, `inferred`
- [ ] Observed date is the real date of the observation, `YYYY-MM-DD`
- [ ] Confidence is Confirmed / Probable / Speculative and matches its
      definition (Confirmed requires an automated test)
- [ ] Status is Verified-by-test / Observed-only / Retired
- [ ] A Confirmed finding lists a green proving test under **Proving test**
- [ ] Notes contain no credentials, QR codes, phone numbers, session keys,
      or message content — synthetic/anonymous values only
- [ ] A row was added to the findings index table in README.md
