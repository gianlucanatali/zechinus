# DataCloak — threat model

DataCloak is a client-side E2E encryption layer: the DEK never leaves the client, and the
server (storage backend) only ever holds ciphertext plus a small amount of structural
metadata (table/row/user identifiers, timestamps, row size). This document states plainly
what that buys you and what it doesn't — read it before assuming a capability the design
doesn't actually provide.

## What a compromised or curious server CANNOT do

- **Read plaintext.** Every field/blob is AES-256-GCM encrypted with a DEK derived
  entirely client-side; the server never receives the DEK or any key derived from it in a
  form that lets it decrypt.
- **Move ciphertext to a different row, field, table, or user and have it still decrypt.**
  AAD binds every ciphertext to exactly where it's supposed to live
  (`{userId, table, field, rowId}`) — moving it anywhere else makes the GCM auth tag fail
  to verify. This also means the server can't quietly reassign one user's encrypted row to
  another user's account.
- **Fingerprint or compare plaintext via `content_hash`.** The column is a keyed
  HMAC-SHA256 (MAC key derived from the DEK, never the DEK itself) — the server sees an
  opaque string it cannot invert, cannot use to detect two rows share the same plaintext,
  and cannot dictionary-attack even for low-entropy values. (Rows written before this
  guarantee existed, or by a not-yet-upgraded consumer, may still carry the older unkeyed
  hash — see README's `content_hash` section for the self-healing convergence path.)
- **Exploit an AAD-serialization collision.** AAD's canonical serialization
  (`JSON.stringify([userId, table, field, rowId])`, envelope `v: 3`/`4`) is unambiguous —
  no character in any component can make two logically different AADs collide to the same
  byte string. (Envelope `v: 1`/`2`, read-only legacy data, used an unescaped pipe-join
  that could theoretically collide; see README's "Wire format" section.)

## What a compromised or curious server CAN still do

- **Serve a stale-but-authentic old version of a row (rollback).** DataCloak has no
  monotonic version counter enforced server-side — if the server returns an older,
  legitimately-encrypted blob instead of the current one, the client has no way to detect
  that it's stale purely from the ciphertext. Not built; see "Non-goals" below.
- **Observe write frequency, row size, and coarse timing.** Ciphertext length correlates
  with plaintext length (modulo the gzip step); how often a row changes and roughly when
  are both visible to anything with DB/network access.
- **Delete data, or refuse to serve it.** Availability is not something client-side
  encryption can protect against — that's an infrastructure/backup concern, out of scope
  for this package entirely.
- **Observe the structural metadata itself** (which table, which row id, which user —
  DataCloak's AAD is deliberately NOT confidential, only integrity-bound). If the row id
  or table name is itself sensitive, that's a modeling decision to make before choosing
  DataCloak, not something the crypto layer hides.

## Declared non-goals (deliberately not built)

- **Rollback protection** (a monotonic counter or signed high-water-mark the client
  verifies against). No consumer has asked for it; would need a place to store the
  high-water-mark the server can't tamper with either, which is a meaningfully bigger
  design than this package's current scope.
- **True DEK rotation** (the DEK's actual bytes change, as opposed to `wrapWithKek`
  re-wrapping the same DEK under a new KEK, which IS built). See README's "What DataCloak
  doesn't do yet" section for the full rationale — every production zero-knowledge system
  either keeps the DEK stable (1Password/Bitwarden-style re-wrap) or does rotation as a
  synchronous, session-invalidating ceremony, never a lazy per-row migration.

## Where to look for more

- README's "Mental model" and "Wire format" sections for how AAD/envelope actually work.
- README's `content_hash` section for the HMAC design and the legacy-hash convergence path.
- `AGENTS.md`'s "Known v1 boundaries" for the full list of what isn't built yet, security
  and non-security alike.
