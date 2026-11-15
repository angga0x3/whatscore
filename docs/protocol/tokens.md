# Token table policy

The binary codec resolves strings through a token table: up to 235 single-byte
tokens at indices 1–235 (index 0 is reserved) and up to four double-byte
dictionaries of 256 entries each. The wire mechanics are recorded in
[binary.md](binary.md) (PF-011, PF-012). This page is about the *table itself*:
why it is not here, what a candidate must prove about itself, and what the
validator enforces before anyone builds a dictionary from it.

**Status: no token table ships in this repository.** `DefaultDictionary()`
returns an empty dictionary, so every string encodes raw. That is a deliberate
choice, not an unfinished stub.

## Why the table is not in this repo

The table is WhatsApp's data, not ours. Two questions are unresolved, and both
have to be answered by the maintainer before a single entry can enter the tree
(technical specification §10.2):

1. **Derivation.** Is a table acceptable when it is derived from an observed,
   published, or third-party source, or must it be reconstructed clean-room
   from behaviour alone? Derivation and clean-room reconstruction produce
   different provenance claims and different reviewer obligations.
2. **Licensing.** Do the licences of any source table permit redistribution in
   this repository, and under which terms? A table that is technically correct
   but cannot be redistributed is not admissible regardless of quality.

Until §10.2 is decided, the project treats every token string as material it
has no right to publish. The codec therefore takes an injected dictionary
(`binary.NewDictionaryFromTokens`, `binary.LoadDictionary`), which keeps all
codec mechanics testable with synthetic tables while the policy question stays
open. Nothing in `protocol/binary` is blocked by the absence of the real table.

Consequences of that stance:

- No real table, fragment, or "example" of one lives in the repository, in
  tests, in fixtures, in docs, in issues, or in commit messages.
- Tests and fixtures use obviously synthetic tokens (`example-one`,
  `example-bravo`). If a value could plausibly be a real token, it does not
  belong in a test.
- A validator run must not print token values. A rejected table is described by
  index and reason, so copying a candidate into a prompt, a log, or a bug
  report cannot leak the material the policy is protecting.

## What a candidate table must carry

A candidate table is not just two arrays. It is a claim about origin, and the
claim is checked before the entries are. Every candidate is a JSON object with
these five fields and no others:

| Field | JSON key | Requirement |
|-------|----------|-------------|
| Source | `source` | Non-empty. How the table was obtained, in enough detail for a reviewer to judge it: direct observation of the operator's own session, a captured handshake of their own device, derivation from a named published source, or clean-room reconstruction. "The internet" is not a source. |
| Observed date | `observed_date` | Non-empty and exactly `YYYY-MM-DD`. The date the observation behind the table was made — not the date the file was written. A table is a snapshot of protocol state that drifts. |
| License | `license` | Non-empty. The terms under which the table's origin permits its use here, with enough specificity to check (an SPDX identifier, a licence name, or a written permission reference). |
| Single tokens | `single` | Array of strings. Index 0 must be `""` and is reserved; usable slots are 1–235. |
| Double tokens | `double` | Array of arrays of strings. At most four rows of at most 256 entries. |

```json
{
  "source": "synthetic example written for this document; describes no real table",
  "observed_date": "2026-11-15",
  "license": "CC0-1.0 (example only)",
  "single": ["", "example-one", "example-two"],
  "double": [["example-bravo"], ["example-charlie"]]
}
```

That object is illustrative only. It is synthetic by construction; it is not a
subset, excerpt, or reconstruction of any real table, and it must not be
"completed" by anyone.

Empty strings are how a candidate truncates a row: slots past the last entry
are simply absent. Since the validator rejects an empty token anywhere except
`single[0]`, a row cannot use `""` as an internal hole. The codec's own loader
tolerates holes by skipping them; the policy does not, because a hole in the
middle of a table is far more often a truncation bug than an intentional gap.

## Acceptance checklist

A candidate table is acceptable only when every box is ticked. The validator
proves the mechanical ones; the reviewer owns the rest.

- [ ] `source` is specific enough to audit, and is a source the reviewer can
      independently check.
- [ ] `observed_date` is the real observation date, `YYYY-MM-DD`.
- [ ] `license` states terms that permit this repository to hold the table.
- [ ] §10.2 is **decided**, and this table's derivation method matches the
      decision.
- [ ] `tokendict -in table.json -check` exits 0.
- [ ] No token value appears in the PR description, the commit message, CI
      output, a log, or a test failure message.
- [ ] The table is loaded through the injected-dictionary API; no code path
      falls back to a built-in table.
- [ ] A finding records the observation, dated, with the proving test — a table
      without a finding is unverified material (see
      [README.md](README.md)).

The last two items are the ones the tooling cannot enforce. A validator can
only prove that a file is well-formed; it cannot make a licence claim true.

## What the validator enforces

`internal/tokendict` implements the mechanical half of this policy.
`Validate` takes a `Table`; `LoadAndValidate` decodes JSON under the same rules;
`Build` validates and then calls `binary.NewDictionaryFromTokens`.

| Check | Rule | Kind |
|-------|------|------|
| Source present | `source` is non-empty after trimming whitespace | `missing-field` |
| Date present | `observed_date` is non-empty after trimming whitespace | `missing-field` |
| Date format | `observed_date` parses as `YYYY-MM-DD` and round-trips unchanged; impossible dates (`2026-02-30`) and unpadded forms (`2026-1-5`) fail | `invalid-date` |
| License present | `license` is non-empty after trimming whitespace | `missing-field` |
| Single table present | `single` has at least one element | `missing-single-table` |
| Reserved slot | `single[0]` is exactly `""` | `reserved-index` |
| Single bound | at most 236 entries (the reserved slot plus 235 usable) | `too-many-single-entries` |
| Double rows | at most 4 rows | `too-many-dictionaries` |
| Row bound | at most 256 entries per row | `too-many-dictionary-entries` |
| Total bound | at most 1259 tokens (235 single + 4 × 256 double) | `too-many-tokens` |
| No empty tokens | every slot other than `single[0]` is non-empty | `empty-token` |
| No duplicates | unique across `single` and across every `double` row together | `duplicate-token` |
| Valid UTF-8 | every token decodes as UTF-8 | `invalid-utf8` |
| No control characters | no `unicode.IsControl` rune in any token | `control-character` |
| Length cap | at most 256 bytes per token | `token-too-long` |
| Strict JSON | malformed JSON, trailing values, and non-object roots fail | `malformed-json` |
| No unknown fields | any key other than the five above fails, including wrong-case variants | `unknown-json-field` |
| Input bound | the input exceeds 4 MiB | `file-too-large` |

Every failure is a `*tokendict.Error` carrying a stable `Kind`, the offending
`Field`, and the offending `Index` (`-1` when not applicable) and `Dict` (`-1`
when not applicable); all of them wrap `ErrInvalid`, so callers can branch with
`errors.Is` instead of matching message text. Error messages contain indices
and reasons only — never a token value. A duplicate is reported as
`duplicate of index N`, not as the duplicated string.

The total bound is re-checked explicitly even though the shape limits imply it,
so relaxing a shape limit cannot silently raise the maximum table size.

## Using the validator

```bash
go run ./cmd/tokendict -in /path/to/candidate.json
```

Prints one JSON object: the three provenance fields and the counts
(`single_entries`, `single_tokens`, `double_rows`, `double_tokens`,
`total_tokens`). With `-check` it prints nothing on success and exits 0, which
is the form to use in a script or CI gate. On any failure both forms exit 1 and
print the typed error to stderr, for example:

```
tokendict: rejected: tokendict: reserved-index: field single: index 0: index 0 is reserved and must be empty
```

The command deliberately has no `-build`, `-export`, or pretty-print mode.
Producing a `binary.Dictionary` from a table is a code decision, made through
`tokendict.Build` where a reviewer can see it, not a shell side effect.
Candidate tables are inputs for local checking only; they are never committed.

## Decision (2026-11-15): operator data

§10.2 is now decided, in
[ADR 0002](../architecture/decisions/0002-token-table.md). The table is
**operator-supplied input**:

- loaded from `WHATSAPP_TOKEN_DICTIONARY`;
- validated at startup by the same rules below (source, ISO date, licence,
  structure, hygiene);
- never committed to this repository, in whole or in part.

A deployment with no table runs with an empty dictionary, which is correct for
every code path that does not encode WhatsApp string tokens. A configured table
that fails validation stops startup with a typed error, so a bad table cannot
produce garbled stanzas later.

### What this does and does not solve

It removes the licensing question from the repository: nothing here is derived
from a table of unclear provenance. It does not make a fresh clone able to talk
to WhatsApp — an operator must supply a table they have the right to use, and
that choice is recorded in their deployment, not in a commit.

### If the maintainer later publishes a table

Nothing in the codec changes. A published table becomes another input: the
validator still runs, and the finding that records it must carry its derivation
method, licence, and a proving test.
