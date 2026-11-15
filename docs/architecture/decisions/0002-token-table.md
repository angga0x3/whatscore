# ADR 0002 — Token table as operator data

Status: **Accepted** · 2026-11-15

## Decision

The WhatsApp token table is **not** shipped in this repository, in whole or in
part. It is treated as **operator-supplied data**:

- the codec always takes an injected `binary.Dictionary`;
- the server loads a table from the path in `WHATSAPP_TOKEN_DICTIONARY`, if set;
- that table must pass `internal/tokendict` validation first (source, ISO
  observation date, licence, plus structural hygiene);
- with no table configured, the codec runs with an empty dictionary and the
  software keeps working in every path that does not need WhatsApp string
  tokens.

This resolves the open question in spec §10.2 without taking a licensing
position on a table the project does not distribute.

## Why

The project cannot both (a) forbid transplanting another implementation and
(b) ship that implementation's table. Any table committed here would be the
transplant, just stored as JSON. Meanwhile the codec mechanics — layout,
packing, JIDs, limits — are already proven and do not require the real tokens.

Making it a startup input has three concrete benefits:

1. **No licence question in the repo.** Nothing here is derived from a table
   with unclear terms.
2. **Auditable provenance.** A table without `source`/`observed_date`/`license`
   is rejected at startup, so the operator's choice is recorded in their own
   deployment rather than lost in a commit.
3. **Reversible.** If the maintainer later decides a clean-room table is safe
   to publish, nothing in the codec changes: it becomes another table.

## Consequences

- A fresh clone cannot decode real WhatsApp traffic. That is honest and
  visible: `/ready` and `whatscore -doctor` report the table as absent.
- A wrong or stale table fails at startup with a typed error instead of
  producing garbled stanzas later.
- Tests and fixtures keep using the synthetic table, so CI never needs real
  data.

## Rejected alternatives

| Alternative | Why not |
|-------------|---------|
| Copy a table from an existing client | Licensing, and it is the transplant the project exists to avoid |
| Reconstruct tokens from observed traffic | Requires live traffic and produces at best a partial table; licence question unchanged |
| Hand-write a minimal table | Would silently mis-encode anything outside the subset — worse than failing |
