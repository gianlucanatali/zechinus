# Zechinus — secure-store framework

**Read this before writing, reading, or extending code inside `zechinus/`, when a
consuming app needs to persist encrypted user data via `defineStore`/`defineLabelDict`,
OR before writing/editing any AAD, envelope, encrypt/decrypt, or storage-upsert logic in
the consuming app — that logic almost always belongs in Zechinus, not inline.**

This file is the tool-agnostic guide: any AI coding agent (Claude Code, Codex, Cursor,
etc.) or human contributor can read it directly, with no dependency on any one tool's
folder conventions. It ships inside `zechinus/` on purpose, so it travels with the
package if/when it's extracted as a standalone repo.

Zechinus is an E2E encryption layer: the app declares data **shape** (Zod schema) +
**cardinality** (`perUser` / `perKey` / `many`) + **what stays plaintext**; Zechinus owns
all the mechanics (AAD, envelope, versioning, validation, I/O). It is NOT an auth system —
the host app's existing auth handles login; Zechinus only encrypts data at rest after
authentication.

**Read `README.md` first.** It is the source of truth for the current public API and v1
scope boundaries. This guide is a checklist for using/extending Zechinus correctly — it
does not replace the README, and it can go stale faster than the code (see "Keeping this
guide honest" below), so when in doubt, re-derive from the README and the code, not from
memory of a past session.

**This codebase is English-only — code, comments, docs, tests, error messages, test
names.** No exceptions, even for a quick one-liner comment.

## Package boundary — `docs/package-boundary.md`

Read that file before adding an export, touching `index.ts`/`react/index.ts`, or adding a
new adapter file. Gist: never import `zechinus`/`zechinus/*` (own package name) from
inside `zechinus/` — always relative paths; `npm run zechinus:typecheck` catches a
violation. The bare barrel (`index.ts`) exports only `core/` — never an adapter.

## Reflection checkpoint

Before writing AAD, envelope, versioning, or storage-upsert logic **anywhere in the
consuming app** — not just inside this package — stop and classify it:

- **Generic** (any store could need this: a new cardinality, a new way to address rows) →
  it belongs **inside Zechinus itself** (`core/`), as a new capability with a TDD test in
  `tests/`. Do not build it as a one-off in the calling service.
- **App-specific but still storage/crypto mechanics** (not domain logic) → it belongs as an
  **adapter or extension behind an existing port** (`StorageAdapter`, `CacheAdapter`, or
  `KeyProvider`) — still not inline in the service.
- **Actual domain logic** (validation rules, business decisions, what a field means) → that
  one genuinely belongs in the calling service, outside Zechinus.

The tell that you're about to violate this: you're about to write `{userId, table, field,
rowId}` AAD, manual field-level encrypt/decrypt serialization, or a manual
`upsert(..., { onConflict })` in a service file, for a table this package doesn't manage
yet. That's exactly what `defineStore` replaces — if you're about to retype it, add
support for that table/pattern in Zechinus instead of copying the pattern one more time.

## Before writing any code

1. Read `README.md` (quickstart, cardinality table, v1 scope).
2. Skim the current public API for real, don't assume it matches what you remember —
   open `index.ts` and `core/store.ts` directly, or search for
   `defineStore`/`Store`/`KeyedStore`/`CollectionStore`. The API evolves across sessions.
3. Look at `examples/basic-usage.ts` — these are real, compiled, tested examples, more
   trustworthy than any prose (including this file).

## Choosing cardinality

| Identity              | When                                                                                       |
| --------------------- | ------------------------------------------------------------------------------------------ |
| `"perUser"` (default) | one secret object per user                                                                 |
| `{ perKey: "col" }`   | one object per (user, domain key) — e.g. a monthly batch, a per-table dictionary           |
| `"many"`              | a collection, framework-generated id, independent rows — e.g. simulations, scheduled items |

Cardinality drives PK, AAD `rowId`, and upsert-vs-insert — never hand-roll this.

`perKey` stores also have `.list(userId, dek, { from, to })` for range queries over
sortable keys (needs `listByKeyRange` on the adapter). For the recurring "dictionary of
labels" shape on top of `perKey`, use `defineLabelDict` instead of hand-rolling
load-mutate-save — see README.

`identity: "many"`'s row id generator is pluggable (`idGenerator?: () => string` on
`StoreDef`, defaults to UUIDv4) — see README's Cardinality section.

Each cardinality is its own standalone builder (`buildKeyedStore`/`buildCollectionStore`/
`buildPerUserStore` in `core/store.ts`), taking a shared `BuildContext` (def, migrators,
validateRead/Write) rather than closing over `defineStore`'s whole body. Adding a 4th
cardinality means writing one more `buildXyzStore` function + one dispatch branch in
`defineStore` — never growing the existing branches.

## Porting an existing table (legacy AAD) — `docs/legacy-aad-porting.md`

Read that file only when porting an existing table already encrypted under a different
AAD convention — omit entirely for a brand-new store. Gist: `legacyAAD` on `defineStore`,
read-old-if-needed/always-write-canonical, lazy per-row convergence, no live migration
script needed.

## `content_hash` — `contentHash: true`, not an injected function

If a table has a `content_hash` column, set `contentHash: true` — Zechinus computes it as
a keyed HMAC-SHA256 (anti-fingerprinting), self-heals legacy unkeyed rows on first write.
Full mechanics: README § "content_hash" + `SECURITY.md`.

Quick reference — turning it on gets you the column, not any capability automatically:
**optimistic locking** (built, needs `optimisticLock: true` too, see below), **skip-write**
(built — `mutate()` on perUser/perKey skips a no-op write; needs only `contentHash: true`;
OFF when `optimisticLock: true` is also set, since it would also skip the server-side
conflict check), **in-session skip-fetch revalidation** (built — needs a configured `cache`

- an adapter with `getHash`; excludes `identity: "many"`), **cross-session persistent
  caching for web** (not built, no consumer — but mobile has its own persistent
  `CacheAdapter`, see "Known v1 boundaries" below).

## Optimistic locking — `optimisticLock: true`, requires `contentHash: true`

Conditional write that rejects instead of silently overwriting a row changed since you
last read it (two tabs editing the same record — without this, the second save silently
clobbers the first, no error). `defineStore` throws at definition time if `optimisticLock`
is set without `contentHash`. Full pattern (`loadWithHash`/`saveIfMatch`, per-cardinality
API, `expectedHash: null` semantics, per-adapter conditional-write implementation, and
`mutate()`'s `retryOnConflict` option): README § "Optimistic locking".

**The React hooks (`useStore`/`useKeyedStore`/`useCollectionStore`) thread the hash
automatically** — `save`/`update` call `saveIfMatch`/`updateIfMatch` transparently, and a
conflict throws `OptimisticLockConflictError` (from `zechinus/react`) instead of
`{ok:false}` — app code using the hooks never sees `expectedHash` at all. Only code calling
`Store`/`KeyedStore`/`CollectionStore` directly (outside React) uses the raw
`saveIfMatch`/`updateIfMatch` pattern from the README.

## Versioning: bump `version`, migrators are checked at definition time

`version: N` requires exactly N-1 `migrators` — `defineStore` throws immediately at
definition if the count is off, not just later when it hits old data. **Always pair a
`version` bump with its migrator in the same change.** Not to be confused with
`EncryptedField.v` (the wire format's own crypto envelope version — compression + AAD
serialization, orthogonal to a store's `version`/migrators): README § "Wire format:
envelope version".

This package also requires a `schemaFingerprint` on every store: `defineStore` throws
immediately if the schema's shape doesn't match the declared fingerprint, naming the
correct value to paste in — that's the moment to decide whether a `version` bump +
migrator is also needed, or whether it's a safe (Zod-absorbable) change that only needs
the fingerprint updated. Full decision tree + rationale: README § "versioning is
mandatory".

**Never compute `schemaFingerprint` inline** (`fingerprintSchema(MySchema, ...)` in the
same `defineStore()` call that uses `MySchema`) — that compares the schema against itself,
a tautology that can never fail regardless of future drift. Always a frozen string literal,
committed to git. Fix a fingerprint error with:

```
npm run zechinus:sync-fingerprints -- path/to/yourBlobService.ts
```

**Deliberately not wired into pre-commit** — auto-fixing on every commit would remove the
"stop and decide: does this need a migrator?" moment the guardrail exists for. Run it
yourself, after deciding, not before.

## The guardrail you cannot bypass

`defineStore` throws at definition time unless you declare `encrypt: "all"`,
`encrypt: "none"`, or mark fields with `enc()`. If you hit this error, declare
encryption explicitly — do not look for a way around it, it exists to stop
plaintext-by-omission.

**`perUser`/`perKey` only support `encrypt: "all"`** (whole record, one blob).
**`identity: "many"` also supports mixed `enc()` fields** (plaintext columns — real
DB columns, filterable — next to one encrypted blob per row): mark the encrypted fields
with `enc()`, leave the rest of the object plain, omit `encrypt` entirely. `encrypt: "none"`
(fully plaintext row) and mixed `enc()` on `perUser`/`perKey` still throw an explicit
`FIXME` error — no real consumer needs them yet. Check `README.md` § "What Zechinus
doesn't do yet" before assuming a capability exists; if you need it, that's a framework
extension task, not a workaround in the calling service.

**Plaintext field names must literally equal the DB column names** — the storage adapters
pass them through with no camelCase↔snake_case mapping. If your table is snake_case, name
the schema fields snake_case too and translate to your app's own domain type in the
service (that translation is domain-shaping, not Zechinus's job).

## Zechinus does not own your schema/DDL

The table/collection must already exist, with a shape matching the store's Zod fields,
before `defineStore` touches it — `defineStore` never runs `CREATE TABLE` and never
verifies your physical DB schema. Keeping them in sync is manual discipline, same as any
ORM/ODM without a migration generator; get it wrong and it fails at read/write time, not
at definition time (unlike `schemaFingerprint`, which only checks plaintext data shape,
never the physical schema). `StorageAdapter` itself is backend-neutral by design — its
methods move opaque records around, nothing assumes SQL — so a non-relational backend
(MongoDB, say) is a new adapter implementing the same interface, no core changes; but that
adapter still needs its own collection/table set up correctly first.

## Extending `StorageAdapter` — `docs/extending-storage-adapter.md`

Read that file when a new access pattern needs a capability the shipped adapters don't
have. Gist: optional method on `StorageAdapter`, implement in the adapter(s), explicit
throw if unsupported (never silent fallback), TDD test first. `getHashesByKeys` is the
reference example of this recipe.

## Aggregation extras — `docs/aggregation-extras.md`

Read that file when working with `defineAggregation` (not needed for plain `defineStore`
work): `flush()`, `invalidateOn`/`invalidateChannel`, the cold-session hash check,
`isAnyAggregationComputing()`, the aggregate-as-source cold-start gotcha, and why
`tanstackAdapter` throws at construction unless `gcTime: Infinity`.

## Node scripts & multi-user concurrency — `docs/node-multi-user.md`

Read that file when writing a Node script/service (not browser code) that touches
Zechinus stores. Gist: `configureSecureStore`'s ambient identity is one module-level
variable, unsafe for concurrent multi-user Node code — use `alsKeyProvider` +
`withIdentity()` from `zechinus/node` for that case. Never import `zechinus/node` from
`zechinus/index.ts` or `zechinus/react/index.ts`.

## The one invariant you must never break

**Store `name` = DB table name = the `table` value baked into the AAD.** Changing it for
data that already exists makes existing blobs permanently undecryptable (AAD is an input
to AES-GCM decryption, not metadata). If a rename is genuinely needed, it requires a
one-shot migration (decrypt under old AAD, re-encrypt under new), never a plain rename.

## After changing the public API

Follow `README.md` § "How these docs stay in sync":

1. Update `examples/basic-usage.ts` until it compiles (typecheck) and
   `tests/examples.test.ts` passes.
2. Mirror the change into `README.md` (Quickstart snippets, "Cardinality" or "What
   Zechinus doesn't do yet" tables) — manual, but a broken example in step 1 is the
   signal you can't skip.

## Before declaring work done

Changes here ripple into whatever app-side services consume this package, and into the
build's alias/config. Run the full check chain used by the consuming app (typecheck, unit
tests, component tests, build) — not just this package's own test suite.

## Known v1 boundaries (don't build these unless explicitly asked)

- No `encrypt: "none"` (fully plaintext row) yet, and mixed `enc()` fields only work with
  `identity: "many"` — not `perUser`/`perKey`.
- No hub-and-spoke storage adapter (cleartext+ref on one backend, blob on another).
- No cross-session persistent skip-fetch cache **for web** (skip the round-trip across
  page reloads, not just within a session) — `tanstackAdapter` stays in-memory only, no
  consumer yet. Optimistic locking AND in-session skip-fetch revalidation (the other two
  `content_hash` capabilities) ARE built — see the section above, don't confuse the three.
  **Mobile already has a persistent `CacheAdapter`** — `mobilePersistentCacheAdapter`/
  `expoPersistentCacheAdapter()` (`adapters/`), device-encrypted, hydrates on cold launch
  — not yet wired into `mobile/`'s own bootstrap.
- Existing hooks and `KeyProvider` implementations (React binding per cardinality,
  `useIsUnlocked`, `passkeyDekController`/`usePasskeyDek`, `alsKeyProvider`,
  `useDevDekInjection`, `useIsAnyKeyedStoreLoading`, `setGzipImpl`): `docs/capability-reference.md`.

## Keeping this guide honest

This file describes conventions and known gaps as of the last time someone updated it — it
is hand-maintained, not generated, so it can drift. If something here contradicts
`README.md` or the code, **those win**: update this guide to match, don't propagate the
stale claim.
