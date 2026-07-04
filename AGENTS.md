# DataCloak — secure-store framework

**Read this before writing, reading, or extending code inside `datacloak/`, when a
consuming app needs to persist encrypted user data via `defineStore`/`defineBlobStore`,
OR before writing/editing any AAD, envelope, encrypt/decrypt, or storage-upsert logic in
the consuming app — that logic almost always belongs in DataCloak, not inline.**

This file is the tool-agnostic guide: any AI coding agent (Claude Code, Codex, Cursor,
etc.) or human contributor can read it directly, with no dependency on any one tool's
folder conventions. It ships inside `datacloak/` on purpose, so it travels with the
package if/when it's extracted as a standalone repo.

DataCloak is an E2E encryption layer: the app declares data **shape** (Zod schema) +
**cardinality** (`perUser` / `perKey` / `many`) + **what stays plaintext**; DataCloak owns
all the mechanics (AAD, envelope, versioning, validation, I/O). It is NOT an auth system —
the host app's existing auth handles login; DataCloak only encrypts data at rest after
authentication.

**Read `README.md` first.** It is the source of truth for the current public API and v1
scope boundaries. This guide is a checklist for using/extending DataCloak correctly — it
does not replace the README, and it can go stale faster than the code (see "Keeping this
guide honest" below), so when in doubt, re-derive from the README and the code, not from
memory of a past session.

**This codebase is English-only — code, comments, docs, tests, error messages, test
names.** No exceptions, even for a quick one-liner comment.

## Package boundary — never import the host app's alias from inside `datacloak/`

`datacloak/` has its own `package.json` (real `dependencies`/optional `peerDependencies`)
and its own `tsconfig.json` (no `paths`, no `@datacloak` alias — that alias only exists in
the host application's config). Any file under `datacloak/` — including tests — must
import the rest of the package via **relative paths** (`../core/types.ts`,
`./testKeyHandle.ts`), never `@datacloak`/`@datacloak/*`. Run `npm run
datacloak:typecheck` before declaring work done on anything inside `datacloak/` — it
type-checks the package standalone and fails immediately if a file crossed this boundary
by accident (this caught 4 real violations the first time it was written).

Also: `@datacloak` (the bare barrel, `index.ts`) exports **only `core/`** — never an
adapter. `supabaseStorageAdapter`, `pgStorageAdapter`, `webauthnKeyProvider`,
`mnemonicRecovery`, `workerKeyHandle` each live at their own file path
(`@datacloak/adapters/<name>.ts`) so importing `@datacloak` for `defineStore` never drags
in Supabase, a Postgres driver, or the WebAuthn browser API. The React binding
(`useStore`/`tanstackAdapter`/...) is its own separate sub-entry, `@datacloak/react`, for
the same reason (never pulls React into a non-React consumer). See README's "Package
boundary" section for the consumer-facing version of this rule.

## Reflection checkpoint

Before writing AAD, envelope, versioning, or storage-upsert logic **anywhere in the
consuming app** — not just inside this package — stop and classify it:

- **Generic** (any store could need this: a new cardinality, a new way to address rows) →
  it belongs **inside DataCloak itself** (`core/`), as a new capability with a TDD test in
  `tests/`. Do not build it as a one-off in the calling service.
- **App-specific but still storage/crypto mechanics** (not domain logic) → it belongs as an
  **adapter or extension behind an existing port** (`StorageAdapter` today; `CacheAdapter`/
  `KeyProvider` once they exist) — still not inline in the service.
- **Actual domain logic** (validation rules, business decisions, what a field means) → that
  one genuinely belongs in the calling service, outside DataCloak.

The tell that you're about to violate this: you're about to write `{userId, table, field,
rowId}` AAD, manual field-level encrypt/decrypt serialization, or a manual
`upsert(..., { onConflict })` in a service file, for a table this package doesn't manage
yet. That's exactly what `defineStore` replaces — if you're about to retype it, add
support for that table/pattern in DataCloak instead of copying the pattern one more time.

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

## Porting an existing table (legacy AAD)

For porting an existing table only — omit entirely for a brand-new store. If a table
already has data encrypted under a different AAD convention than DataCloak's canonical
one, declare `legacyAAD: (dek, rowKey) => ({...})` on `defineStore` — a function
returning the FULL old AAD (not just the `field` piece; it can differ in `rowId` too,
e.g. an old table that pinned `rowId: pid` for what is now a `perKey` store). The
framework never guesses at historical conventions — the caller supplies the complete old
shape.

Behavior: **read-old-if-needed, always-write-canonical**, same pattern as
`version`/migrators. Every read tries the canonical AAD first — that's the only attempt
in the common case (new data, or an already-migrated row), one decrypt, forever. Only on
failure does it retry under `legacyAAD`; a successful legacy decrypt is immediately
re-encrypted under canonical AAD and persisted — that row converges permanently from then
on. Writes (`save`/`create`/`update`) ALWAYS use canonical AAD, never the legacy one. If
both attempts fail, the canonical error propagates (never masked). No live migration
script needed — rows convert lazily, one at a time, exactly when touched.

The underlying primitive, `migrateLegacyAAD` (still exported for one-shot scripts outside
the `defineStore` read path), does only the generic decrypt-old/re-encrypt-new mechanics;
a record that exists with a missing/malformed blob throws — never reported as
`migrated: false` (reserved for a genuinely absent record).

## `content_hash` — `contentHash: true`, not an injected function

If a table has a `content_hash` column, set `contentHash: true` — DataCloak computes it
internally (SHA-256 of the plaintext envelope, `core/contentHash.ts`) on every write.
Unlike `StorageAdapter`/`KeyProvider`, hashing JSON needs zero app-specific knowledge, so
this is a boolean declaration ("does this table have the column"), not an app-supplied
function. Omit for tables without the column.

Populating the column unlocks two independent capabilities: **optimistic locking** (built,
below) and **skip-fetch caching** (not built — needs a persisted cross-session cache the
current `CacheAdapter` doesn't provide; no consumer yet). Turning `contentHash` on gets
you the column, not either capability automatically.

## Optimistic locking — `optimisticLock: true`, requires `contentHash: true`

Conditional write that rejects instead of silently overwriting a row changed since you
last read it (two tabs editing the same record — without this, the second save silently
clobbers the first, no error). `defineStore` throws at definition time if `optimisticLock`
is set without `contentHash`.

```ts
const { data, hash } = await store.loadWithHash!(userId, dek);
const result = await store.saveIfMatch!(userId, dek, data, hash);
if (!result.ok) {
  // conflict — someone else saved first. Never thrown: an expected, recoverable outcome.
} else {
  // result.hash is the new current hash — feed it into the next saveIfMatch,
  // no extra fetch needed (computed client-side, before the write, in encodeBlob)
}
```

Available on all 3 cardinalities: `Store.saveIfMatch` (perUser), `KeyedStore.saveIfMatch`
(perKey, per-key lock), `CollectionStore.updateIfMatch` (many, per-row lock — a conflict
on one row never touches another). Underlying adapter capability: `StorageAdapter.
putIfMatch`/`updateByIdIfMatch` (optional — missing capability throws an explicit error at
the first conditional write, never a silent unconditional fallback). Both shipped adapters
implement it: `expectedHash: null` → plain INSERT (a unique-violation is the conflict,
caught and turned into `{ok:false}`, never rethrown); non-null → `UPDATE ... WHERE ... AND
content_hash = expected`, zero rows affected = conflict.

**The React hooks (`useStore`/`useKeyedStore`/`useCollectionStore`) thread the hash
automatically** — their cache slot holds `{data, hash}` internally, `save`/`update` call
`saveIfMatch`/`updateIfMatch` transparently when the store has the lock configured, and a
conflict rolls back the optimistic update and throws `OptimisticLockConflictError` (from
`@datacloak/react`) instead of `{ok:false}` — app code using the hooks never sees
`expectedHash` at all. Only code calling `Store`/`KeyedStore`/`CollectionStore` directly
(outside React) uses the raw `saveIfMatch`/`updateIfMatch` pattern above.

## Versioning: bump `version`, migrators are checked at definition time

`version: N` requires exactly N-1 `migrators` (v1→v2, …, v(N-1)→vN) — `defineStore` throws
immediately at definition (boot/import) if the count is off, not just later when it hits
old data. **Always pair a `version` bump with its migrator in the same change.**

This package also requires a `schemaFingerprint` on every store (see the README's
"versioning is mandatory" guardrail): if you change a schema's shape without updating its
fingerprint, `defineStore` throws immediately with the correct value to paste in — that's
the moment to decide whether a `version` bump + migrator is also needed. Treat this as
non-optional whenever you touch a `schema` or `version` field.

**Fingerprint change does not automatically mean `version` change.** Two distinct cases:
an additive change Zod can absorb on its own at parse time (a new field with `.default()`)
only needs the fingerprint updated — old ciphertext still validates fine against the new
schema, nothing to migrate. A change old data can't satisfy as-is (renamed/retyped field,
new required field with no default) needs `version` bump + migrator too, since decrypted
old data would otherwise fail `schema.safeParse()` on read. The error message names both
options; read it before picking one.

It's still technically a different shape either way — "safe" means Zod can absorb it, not
"not a version." The guardrail doesn't forbid bumping `version` for a backward-compatible
change too (write an identity migrator, `(d) => d`, if a team wants every shape change
tracked explicitly for a stricter audit trail); it just doesn't require it. Don't present
the "safe change, skip the bump" path as the only correct one — it's the default the
guardrail allows, not a rule it enforces.

**Never compute `schemaFingerprint` inline** (`fingerprintSchema(MySchema, ...)` in the
same `defineStore()` call that uses `MySchema`) — that compares the schema against itself,
a tautology that can never fail regardless of future drift. Always a frozen string literal,
computed once, committed to git. Fix a fingerprint error with:

```
npm run datacloak:sync-fingerprints -- path/to/yourBlobService.ts
```

It re-imports the file, catches the thrown error, and patches the correct value in for
you (assumes one `defineStore()` per file). **Deliberately not wired into pre-commit** —
auto-fixing on every commit would remove the "stop and decide: does this need a migrator?"
moment the guardrail exists for. Run it yourself, after deciding, not before.

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
`FIXME` error — no real consumer needs them yet. Check `README.md` § "What DataCloak
doesn't do yet" before assuming a capability exists; if you need it, that's a framework
extension task, not a workaround in the calling service.

**Plaintext field names must literally equal the DB column names** — the storage adapters
pass them through with no camelCase↔snake_case mapping. If your table is snake_case, name
the schema fields snake_case too and translate to your app's own domain type in the
service (that translation is domain-shaping, not DataCloak's job).

## DataCloak does not own your schema/DDL

The table/collection must already exist, with a shape matching the store's Zod fields,
before `defineStore` touches it — `defineStore` never runs `CREATE TABLE` and never
verifies your physical DB schema. Keeping them in sync is manual discipline, same as any
ORM/ODM without a migration generator; get it wrong and it fails at read/write time, not
at definition time (unlike `schemaFingerprint`, which only checks plaintext data shape,
never the physical schema). `StorageAdapter` itself is backend-neutral by design — its
methods move opaque records around, nothing assumes SQL — so a non-relational backend
(MongoDB, say) is a new adapter implementing the same interface, no core changes; but that
adapter still needs its own collection/table set up correctly first.

## Extending `StorageAdapter`

If a new access pattern needs a capability the adapter doesn't have:

1. Add the method as **optional** (`method?:`) on `StorageAdapter` in `core/types.ts` —
   never required, so existing adapters keep compiling.
2. Implement it in `adapters/supabaseStorageAdapter.ts` (or your own adapter). Any
   query/update/delete should filter by the owning user id explicitly, even when
   row-level security also enforces it — index usage, not just correctness.
3. In `defineStore` (`core/store.ts`), the code path using the new capability must throw an
   explicit, descriptive error if `storage.<method>` is undefined — mirror the existing
   pattern (`the configured adapter doesn't support 'many' (list missing)`). Never
   silently no-op or fall back.
4. Write a TDD test in `tests/` **before** the implementation: an in-memory `StorageAdapter`
   double (copy the pattern from `defineStoreMany.test.ts` or `defineStorePerKey.test.ts`),
   4+ cases (roundtrip, AAD-per-row not movable across rows/keys/ids,
   adapter-missing-capability → explicit error, Zod validation rejects bad writes).

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
   DataCloak doesn't do yet" tables) — manual, but a broken example in step 1 is the
   signal you can't skip.

## Before declaring work done

Changes here ripple into whatever app-side services consume this package, and into the
build's alias/config. Run the full check chain used by the consuming app (typecheck, unit
tests, component tests, build) — not just this package's own test suite.

## Known v1 boundaries (don't build these unless explicitly asked)

- No `encrypt: "none"` (fully plaintext row) yet, and mixed `enc()` fields only work with
  `identity: "many"` — not `perUser`/`perKey`.
- No hub-and-spoke storage adapter (cleartext+ref on one backend, blob on another).
- No skip-fetch caching (don't re-download a blob if `content_hash` hasn't changed) —
  needs a persisted cross-session cache, no consumer yet. Optimistic locking (the _other_
  `content_hash` capability) IS built — see the section above, don't confuse the two.
- React binding exists for all 3 cardinalities (`useStore`/`useKeyedStore`/
  `useCollectionStore`, all in `react/`). Each needs `keys` (`KeyProvider`) and `cache`
  (`CacheAdapter`) in `configureSecureStore`; without them it throws explicitly. Both
  ports are plain get/subscribe objects, deliberately not hook-shaped
  (`useSyncExternalStore` reads them inside the hook, not inside the port itself) — don't
  design a new port as `useXyz()`.
- `KeyProvider` has one known concrete implementation (the host app's, bridging
  `PasskeyContext`/`UserContext` — see README's React binding section for the pointer).
  Whatever a _second_ implementation looks like must not assume a browser: React Native
  needs a different `getDek`/`getUserId`/`subscribe` behind native passkey/biometrics,
  but the port itself already doesn't require WebAuthn — only a future concrete
  implementation would.

## Keeping this guide honest

This file describes conventions and known gaps as of the last time someone updated it — it
is hand-maintained, not generated, so it can drift. If something here contradicts
`README.md` or the code, **those win**: update this guide to match, don't propagate the
stale claim.
