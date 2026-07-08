# DataCloak

**End-to-end encryption as an adapter layer, for apps that already own their backend.**

DataCloak isn't "an encrypted store" — it's the correct cryptographic decisions made for
you. Anyone can write a CRUD store; DataCloak owns the hard 20% that gets skipped or
gotten wrong — per-row AAD, versioned envelopes, runtime validation, always-explicit
encryption — so the domain only declares **the shape of its data**, never the mechanics.

> Status: v1 in development, inside the the host app repo (`datacloak/`). Extraction into a
> standalone OSS MIT package is planned but not done yet — see
> `_local/plans/done/20260626-1111000-secure-store-framework.md` for the full design-decision
> history (that file is for people working _on_ DataCloak; this README is for people who
> _use_ it).
>
> **Language:** `datacloak/` is English-only — code, comments, docs, tests, error
> messages. This is deliberate: it's the one part of the repo meant to become a
> standalone OSS package, and OSS ships in English. The rest of the host app follows its own
> Italian/English convention (see `AGENTS.md`) — that convention does NOT apply inside
> `datacloak/`.
>
> **Threat model:** see `SECURITY.md` for what a compromised/curious server can and
> cannot do, and what's a declared non-goal (rollback protection, true DEK rotation).

## Mental model

A record = **cardinality** (how many blobs, addressed how) + **what to encrypt** (default:
everything) + **schema** (Zod: type + validation). From this, DataCloak derives AAD,
envelope, upsert/insert, lazy migration — all the mechanics stay invisible to the author.

```
frontend/service → defineStore({ name, identity, encrypt, schema, version }) → store.load/save/...
                                            ↓
                              StorageAdapter (Supabase today; pluggable)
```

## Wire format: envelope version (`EncryptedField.v`)

Every ciphertext blob carries a `v: 1 | 2 | 3 | 4` alongside the ciphertext and nonce —
NOT the same thing as `StoreDef.version` (the schema's own version, used for migrators).
`v` tells decrypt which compression AND which AAD serialization the blob was written
with, so decoding is deterministic from the stored value alone (no try-and-fallback, no
double decrypt):

| `v` | Compression | AAD serialization |
| --- | ----------- | ----------------- |
| 1   | none (raw)  | v1 — pipe-join    |
| 2   | gzip        | v1 — pipe-join    |
| 3   | none (raw)  | v2 — JSON 4-tuple |
| 4   | gzip        | v2 — JSON 4-tuple |

AAD-v1 (legacy) joined the 4 AAD fields (`userId|table|field|rowId`) with no escaping — a
`|` inside any component made two logically different AADs serialize to the identical byte
string, which AES-GCM then treated as interchangeable. AAD-v2 (canonical) is
`JSON.stringify([userId, table, field, rowId])` — unambiguous regardless of what
characters a component contains. **`1`/`2` are read-only** (a blob already on disk before
this fix): every new write always emits `3` or `4`. A row still holding `1`/`2` converges
to canonical the next time anything touches it, via the same lazy write-back
`legacyAAD`/schema-version migrations already use — no live migration script needed.

## Quickstart

The three examples below are **real, compiled, tested code** (not prose that rots):
`datacloak/examples/basic-usage.ts` + `datacloak/tests/examples.test.ts`. If the API
changes, those files stop compiling or the test fails — that's the alignment guarantee,
see ["How these docs stay in sync"](#how-these-docs-stay-in-sync) below.

```ts
import { z } from "zod";
import {
  configureSecureStore,
  defineStore,
  supabaseStorageAdapter,
} from "datacloak";

// once, at app bootstrap
configureSecureStore({ storage: supabaseStorageAdapter(getSupabaseClient) });

// perUser — one blob per user (portfolio, asset, snapshot)
const portfolioStore = defineStore({
  name: "portfolio_blobs",
  identity: "perUser", // default, can be omitted
  encrypt: "all", // ALWAYS explicit — see guardrail below
  schema: z.object({ positions: z.array(Position).default([]) }),
  version: 1,
});
await portfolioStore.save(userId, cryptoHandle, data);
const data = await portfolioStore.load(userId, cryptoHandle);

// perKey — one blob per (user, domain key) — e.g. transactions per month
const transactionStore = defineStore({
  name: "transaction_blobs",
  identity: { perKey: "year_month" },
  encrypt: "all",
  schema: z.object({ transactions: z.array(Tx).default([]) }),
  version: 1,
});
await transactionStore.save(userId, cryptoHandle, "2026-07", data);
const data = await transactionStore.load(userId, cryptoHandle, "2026-07");

// many — a collection with a generated id — e.g. rebalance simulations
const simulationStore = defineStore({
  name: "rebalance_simulations",
  identity: "many",
  encrypt: "all",
  schema: z.object({
    name: z.string().default(""),
    addedLiquidity: z.number().default(0),
  }),
  version: 1,
});
const id = await simulationStore.create(userId, cryptoHandle, data);
const rows = await simulationStore.list(userId, cryptoHandle); // [{ id, data }, ...]
await simulationStore.update(userId, cryptoHandle, id, data);
await simulationStore.remove(userId, cryptoHandle, id);
```

Full runnable examples (in-memory adapter, no Supabase required):
`datacloak/examples/basic-usage.ts`.

## Cardinality — which one to pick

| Identity               | When                                                      | EW example                                                               |
| ---------------------- | --------------------------------------------------------- | ------------------------------------------------------------------------ |
| `"perUser"` (default)  | a single secret object per user                           | portfolio, asset, snapshot                                               |
| `{ perKey: "column" }` | one object per user **per domain key**                    | transactions per month (`year_month`), label dictionaries (`table_name`) |
| `"many"`               | a collection, id generated by DataCloak, independent rows | rebalance simulations, scheduled transactions                            |

Cardinality determines the PK, the AAD (`rowId`), upsert-vs-insert — the author never
implements this by hand.

**`many`'s row id is pluggable:** `identity: "many"` defaults to an RFC4122 UUIDv4
(`core/randomId.ts`), but `defineStore({ ..., idGenerator: () => yourId() })` overrides
it — useful for sortable ids (ULID, a timestamp-prefixed scheme). DataCloak only needs
the result unique per `(userId, collection)`; it never inspects the id's shape.

**`perKey` range queries:** `keyedStore.list(userId, cryptoHandle, { from, to })` returns all
entries whose key falls in `[from, to]` (lexicographic — works for sortable keys like
`year_month`), decrypted, AAD still enforced per row. Needs `listByKeyRange` on the
adapter (both shipped adapters have it); throws explicitly if the configured adapter
doesn't.

**`perKey` bulk creation:** `keyedStore.createMany([{ key, data }, ...])` writes N distinct
keys in a single round-trip — a real INSERT, not an upsert: a key that already exists
fails the WHOLE batch instead of silently overwriting it. Ambient (no `userId`/
`cryptoHandle`, like `get`/`set`/`mutate`). Built for callers that create many brand-new
keys at once and know none of them exist yet (e.g. seeding 36 months of demo transactions
right after a full wipe) — N `mutate()` calls in parallel each pay their own round-trip
(read + conditional write), which doesn't scale past a handful of keys. Updating an
existing key still goes through `mutate`/`set`. Needs `insertMany` on the adapter (both
shipped adapters have it); throws explicitly if the configured adapter doesn't.

## Recipe: `defineLabelDict` — dictionaries of labels

```ts
import { defineLabelDict } from "datacloak";

const accountLabels = defineLabelDict({ name: "user_label_dicts" }); // keyColumn defaults to "table_name"

await accountLabels.setLabel(
  userId,
  cryptoHandle,
  "accounts",
  accountId,
  "Checking account",
);
const label = await accountLabels.getLabel(
  userId,
  cryptoHandle,
  "accounts",
  accountId,
);
await accountLabels.deleteLabel(userId, cryptoHandle, "accounts", accountId);
const all = await accountLabels.getAll(userId, cryptoHandle, "accounts");
```

Zero new mechanics — it's `defineStore({ identity: { perKey }, schema: z.record(...) })`
plus load-mutate-save helpers, so callers never touch the raw dict shape. `keyColumn` is
the one injectable bit (defaults to `"table_name"`, EW's convention) — whatever DB column
identifies _which_ dictionary a row belongs to is a naming decision that belongs to the
consuming app's schema, not to DataCloak.

## Porting a table with a different historical AAD — `legacyAAD`

**For porting an existing table only — omit entirely for a brand-new store** (the vast
majority of stores never set this). DataCloak's canonical AAD is
`{ userId: pid, table: name, field: "data", rowId }`. A table already encrypted by
hand-rolled code before the port often used a different convention — a different `field`
string (`"snapshot"`, `"transactions"`, `"blob"`, …), sometimes a different `rowId` too
(e.g. a table that pinned `rowId: pid` for what is now modeled as a `perKey` store).
Without matching it, old ciphertext won't decrypt (GCM auth tag mismatch) — the AAD is an
input to decryption, not metadata.

`legacyAAD` is a function returning the **entire old AAD**, not just a piece of it — the
framework never guesses at historical conventions, the caller supplies the full shape:

```ts
defineStore({
  name: "account_snapshot_blobs",
  identity: { perKey: "year_month" },
  encrypt: "all",
  schema: SnapshotSchema,
  version: 1,
  legacyAAD: (cryptoHandle, key) => ({
    userId: cryptoHandle.pid,
    table: "account_snapshot_blobs",
    field: "snapshot", // the OLD service's field value
    rowId: key, // here it happens to match the canonical rowId too
  }),
  schemaFingerprint: "…",
});
```

**Read-old-if-needed, always-write-canonical** — the same pattern already used for
`version`/migrators, applied to AAD:

- On every read, the canonical AAD is tried **first**. If it decrypts, that's the only
  attempt — the common case (new data, or a row already migrated) costs exactly one
  decrypt, forever.
- Only if the canonical attempt **fails** does the store retry under `legacyAAD`. A
  successful legacy decrypt is immediately re-encrypted and persisted under the canonical
  AAD — that one row converges permanently; every future read of it costs one decrypt
  again. No live migration script, no big-bang rewrite: rows convert lazily, one at a
  time, exactly when touched. A row nobody ever reads simply stays under the old
  convention until someone does.
- **Every write** (`save`/`create`/`update`) **always** uses the canonical AAD — a store
  never has two ways to write, only (optionally) two ways to read.
- If **both** the canonical and legacy attempts fail, the canonical error propagates
  (never masked by the legacy attempt's own failure) — real corruption or a wrong DEK
  still surfaces clearly.

`rowKey` passed to `legacyAAD` is `cryptoHandle.pid` for `perUser`, the domain key for `perKey`,
the row id for `many` — whatever the store's own "row address" is.

## The underlying primitive — `migrateLegacyAAD`

`legacyAAD` (above) is built on top of `migrateLegacyAAD`, which stays exported for
one-shot scripts outside the `defineStore` read path (e.g. a deliberate backfill job) —
pure decrypt-under-old → re-encrypt-under-new mechanics, old AAD always supplied by the
caller:

```ts
import { migrateLegacyAAD } from "datacloak";

const oldRecord = await storage.getByKey(
  "transaction_blobs",
  userId,
  "year_month",
  "2026-06",
);
const { migrated, record } = await migrateLegacyAAD(
  cryptoHandle,
  oldRecord,
  {
    userId: cryptoHandle.pid,
    table: "transaction_blobs",
    field: "transactions",
    rowId: "2026-06",
  }, // old
  {
    userId: cryptoHandle.pid,
    table: "transaction_blobs",
    field: "data",
    rowId: "2026-06",
  }, // canonical
);
if (migrated)
  await storage.putByKey(
    "transaction_blobs",
    userId,
    "year_month",
    "2026-06",
    record!,
  );
```

`migrated: false` (no throw) only for a genuinely missing record — a row that exists with
a missing/malformed blob throws explicitly, never silently reported the same as "nothing
to migrate".

## `content_hash` — `contentHash: true`

If a table has a `content_hash` column, set `contentHash: true` and DataCloak computes it
for you — a **keyed HMAC-SHA256** (hex) of the plaintext envelope, before encryption, on
every write. The MAC key is derived from the DEK (`keyDerivation.ts`'s `createKeyHandle`),
never the DEK itself, so the server only ever sees an opaque, non-fingerprintable string —
it cannot compare two rows' plaintext for equality, detect a rollback to old content, or
run a dictionary attack against low-entropy values, all of which a plain (unkeyed) hash
would let it do:

```ts
defineStore({
  name: "asset_blobs",
  schema: AssetSchema,
  version: 1,
  contentHash: true, // table has a content_hash column
  schemaFingerprint: "…",
});
```

Unlike `StorageAdapter`/`KeyProvider` (which genuinely need an app-supplied
implementation), hashing a JSON payload requires zero app-specific knowledge — so this is
a boolean, not an injected function by default. DataCloak computes it internally via the
`CryptoHandle`'s optional `hashContent` method (`keyDerivation.ts`'s `createKeyHandle`
implements it; `KeyHandle`s always have it). The app only declares whether the column
exists. Omit (or `false`) for tables without the column — writing a hash the schema has no
column for would fail at the storage layer.

If you need the MAC computed elsewhere (e.g. delegated to a KMS instead of derived from the
DEK), pass `createKeyHandle(rawBytes, pidSalt, pidInfo, { hashContent })` — everything else
(encryption, PID, key wrapping) keeps the default DEK-derived behavior; only the hash
computation is overridden.

**Transition note:** rows written before this change (or by an app that hasn't upgraded
yet) may still carry the old plain SHA-256 hash. That's harmless and self-healing: the
optimistic-lock/skip-write comparisons only ever compare a _stored_ hash against a _freshly
computed_ one for equality, never recompute or trust the algorithm that produced the stored
value — so an old-format row simply converges to the new HMAC the first time anything
writes to it (worst case, one extra write instead of a skipped one; see `content_hash
transition` tests).

`content_hash` unlocks four independent capabilities:

- **Optimistic locking** (`optimisticLock: true`, below) — **built.** Prevents a tab from
  silently overwriting another tab's write.
- **Skip-write** — **built.** `mutate()` (perUser and perKey) compares the hash of what
  it's about to write against the hash of what it just read — if the transform produced
  no real change, the encrypt+upload is skipped entirely, `mutate()` just returns the
  value. Requires only `contentHash: true` (no `cache` needed, unlike skip-fetch — the
  comparison uses the hash `mutate()` already has from its own load, not a cross-call
  cache slot). **Gated off when `optimisticLock: true` is also set**: with optimistic
  locking, `mutate()` writes through `saveIfMatch`, which does the real conflict check
  server-side — skipping that write for a "no-op" transform would also skip the conflict
  check, silently accepting a stale view. Not built for `set()`/`save()` (blind writes,
  no "current" to compare against) or `identity: "many"` (no `mutate()`-equivalent).
- **In-session skip-fetch revalidation** — **built.** Transparent to the app: when a store
  declares `contentHash: true`, `configureSecureStore` has a `cache`, and the adapter
  implements `getHash`, every `load`/`get`/`mutate` compares the cache slot's hash against
  a lightweight `getHash()` call before deciding whether to re-download the blob — a match
  serves the cached `{data, hash}` slot, no full load. Any of the three missing (no
  `contentHash`, no `cache`, no `getHash`) falls back to today's behavior (always a full
  load), so this is purely additive. Memory-only: the slot lives in the in-memory
  `CacheAdapter`, wiped on reload/lock, same as today. `identity: "many"` is not covered —
  its cache slot is an array with a hash per row; per-row or aggregate revalidation would
  be a different design with no consumer asking for it yet.
- **Cross-session persistent cache** ("skip the network round-trip entirely across page
  reloads") — **not built.** Needs a cache that survives a reload (ciphertext persisted to
  IndexedDB, say) — today's `CacheAdapter` is in-memory only. No consumer yet.

## Optimistic locking — `optimisticLock: true`

Requires `contentHash: true`. Enables a conditional write that **rejects instead of
silently overwriting** a row that changed since you last read it — the concrete problem
this solves: two browser tabs open on the same record, both editing; without this, the
second save silently clobbers the first one's changes with no error, no warning.

```ts
const store = defineStore({
  name: "asset_blobs",
  schema: AssetSchema,
  version: 1,
  contentHash: true,
  optimisticLock: true, // requires contentHash: true — guardrail throws otherwise
  schemaFingerprint: "…",
});

const { data, hash } = await store.loadWithHash!(userId, cryptoHandle);
// ... user edits `data` ...
const result = await store.saveIfMatch!(userId, cryptoHandle, data, hash);
if (!result.ok) {
  // someone else saved first — reload and show a conflict, never retry blindly
} else {
  // result.hash is the NEW current hash — feed it into the next saveIfMatch,
  // no extra fetch needed to learn it (the framework already computed it
  // client-side, before the write, as part of encoding the blob)
}
```

`expectedHash: null` means "I believe there's no REAL content yet" — covers BOTH "no row
exists" AND "the row exists but was never hashed" (legacy data written before
`content_hash` existed, or before this store declared `contentHash: true`). Both succeed;
the only genuine conflict for `null` is a row that already has a REAL hash (someone else's
write beat us to it) — the adapter resolves this against the row's actual current state,
not a stale client-side assumption. A non-`null` hash means "only write if the row's
current `content_hash` still matches this" (`UPDATE ... WHERE content_hash = expected`, an
INSERT/UPDATE-with-guard the adapter implements). **A conflict is always `{ok:false}`,
never thrown** — an expected, recoverable outcome, not a bug.

Available on all 3 cardinalities: `Store.saveIfMatch` (perUser), `KeyedStore.saveIfMatch`
(perKey, independent lock per key), `CollectionStore.updateIfMatch` (many, independent
lock per row — a conflict on one row never affects another). `StorageAdapter.putIfMatch`/
`updateByIdIfMatch` are the underlying capability (optional — an adapter without them
makes `defineStore` throw an explicit error at the first conditional write, not silently
fall back to an unconditional one). Both shipped adapters (`supabaseStorageAdapter`,
`pgStorageAdapter`) implement it.

**The React hooks thread the hash automatically** — see "React binding" below. App code
using `useStore`/`useKeyedStore`/`useCollectionStore` never touches `saveIfMatch`/
`expectedHash` directly; only code calling `Store`/`KeyedStore`/`CollectionStore` raw
(outside React, or inside a custom binding) needs the pattern above.

## Guardrail: encryption always explicit

`defineStore` **refuses** to be defined unless you declare `encrypt: "all"`,
`encrypt: "none"`, or at least one `enc()` field in the schema. No silent default —
impossible to write plaintext data by omission.

## Guardrail: versioning is mandatory, not a mental note

`version: N` **requires exactly N-1 `migrators`** (v1→v2, v2→v3, …, v(N-1)→vN).
`defineStore` throws an explicit error **at definition** (at boot/import, not on the first
read of old data) if the count doesn't match:

```ts
defineStore({
  name: "portfolio_blobs",
  version: 4,
  migrators: [v1ToV2, v2ToV3, v3ToV4], // exactly 3, or the app won't start
  // ...
});
```

This catches "bumped `version` but forgot the migrator" **immediately**, not months later
staring at a production blob that no longer decodes.

**The opposite case — "changed the schema's shape but forgot to bump `version` at all" —
is covered by a second guardrail, `schemaFingerprint` (mandatory, like `encrypt`).**
`defineStore` computes a fingerprint of the schema's current shape and compares it against
the declared one; if it's missing or doesn't match, it throws **at definition** — i.e. on
the next `npm test`/`npm run dev`/`npm run build`, not the first time the app touches real
data written with the old shape. Concretely, here's what a developer sees:

```ts
// 1. First definition — schemaFingerprint missing:
defineStore({
  name: "portfolio_blobs",
  encrypt: "all",
  schema: z.object({ positions: z.array(Position).default([]) }),
  version: 1,
});
// → throws: "schemaFingerprint missing — add schemaFingerprint: "3a7f2c11" to the def"
//   You copy the suggested value, paste it in. Zero manual computation.

// 2. Months later, you add a field to the schema WITHOUT thinking about versioning:
defineStore({
  name: "portfolio_blobs",
  encrypt: "all",
  schema: z.object({
    positions: z.array(Position).default([]),
    cashBuffer: z.number().default(0), // ← new field, version still 1
  }),
  version: 1,
  schemaFingerprint: "3a7f2c11", // ← the old value, no longer valid
});
// → throws immediately: "the schema shape has changed relative to the declared
//   schemaFingerprint (expected "3a7f2c11", computed "9e01bb44"). If this change
//   requires migrating existing data: bump version + add a migrator, THEN update
//   schemaFingerprint. If it's a safe change (e.g. a field with .default()): just
//   update schemaFingerprint."
```

The point: **you cannot change the schema "quietly".** Whether or not you remember to
think about versioning, the next boot/test run refuses to start until you consciously
update `schemaFingerprint` — that's the moment, reading the message, where you decide
whether a `version` bump + migrator is also needed, or whether it's a safe change. Zod's
reactive check (on old data, at read time) remains a second safety net, not the only check.

**Precision on "safe change" — it is still a different shape, just a backward-compatible
one.** A field added with `.default()` genuinely produces a new blob shape (the fingerprint
changing proves that). "Safe" doesn't mean "not a version" — it means Zod can absorb old
ciphertext into the new shape at parse time, with no data loss and no explicit migrator
needed, so the guardrail doesn't _require_ a `version` bump for it. It does not _forbid_
one either: if your team wants to track every shape change as an explicit version — for a
stricter audit trail, or because you don't trust "backward-compatible" judgment calls —
nothing stops you from bumping `version` and writing an identity migrator (`(d) => d`) for
every change, safe or not. The guardrail's job is to make you decide consciously each
time; it deliberately doesn't pick a house style for how strict that decision has to be.

**IMPORTANT — never compute `schemaFingerprint` inline at the call site**, e.g.
`schemaFingerprint: fingerprintSchema(MySchema, "all")` in the same `defineStore()` call
that uses `MySchema`. That makes the guardrail compare the schema against itself — a
tautology that can never fail, no matter how much the shape drifts later. Always a frozen
string literal, computed once, committed to git:

```ts
const store = defineStore({
  name: "portfolio_blobs",
  schema: PortfolioDataSchema,
  version: 1,
  // Frozen literal — NOT fingerprintSchema(PortfolioDataSchema, ...) inline (see above).
  // Regenerate with `npm run datacloak:sync-fingerprints -- path/to/this/file.ts`.
  schemaFingerprint: "da2584b4",
});
```

### Fixing a `schemaFingerprint` guardrail error

Once you've decided (per the message above) whether the change needs a `version`
bump + migrator or is safe as-is, run:

```
npm run datacloak:sync-fingerprints -- path/to/yourBlobService.ts
```

It re-imports the file, catches the guardrail's own thrown error, extracts the correct
value from the message, and writes it into the `schemaFingerprint` field for you — same
idea as `eslint --fix`, just for this one guardrail. It assumes one `defineStore()` call
per file (today's convention across every ported service); a file with more than one
needs a manual fix.

**Deliberately NOT wired into the pre-commit hook.** Auto-fixing on every commit would
silently remove the "stop and consciously decide: does this need a migrator or not?"
moment that is the entire reason this guardrail exists. Run the command yourself, after
you've made that decision — not before, and not automatically.

If you forget to run it (or fix it manually): nothing bad happens beyond friction —
`defineStore()` keeps throwing on every `npm test` / `npm run dev` / `npm run build`
until it's fixed. It cannot be silently skipped; there is no environment where the
guardrail doesn't run, because it fires the moment the module is imported.

## Mixed plaintext fields (`enc()`) — only with `identity: "many"`

```ts
const simulationStore = defineStore({
  name: "rebalance_simulations",
  identity: "many",
  schema: z.object({
    portfolioId: z.string(), // plaintext → real, filterable column
    status: z.enum(["draft", "executed"]).default("draft"), // plaintext
    name: enc(z.string()), // encrypted ┐
    addedLiquidity: enc(z.number().default(0)), // encrypted ┘ → ONE blob
  }),
  version: 1,
});
```

No `encrypt: "all"` here — having at least one `enc()` is enough to declare encryption.
Fields **not** marked `enc()` become real plaintext columns (queryable server-side); the
marked ones end up in a single blob per row. **Only `identity: "many"` supports this mix
in v1** — `perUser`/`perKey` remain bound to `encrypt: "all"` (no real consumer needs them
yet; `defineStore` throws an explicit error if you try).

**The plaintext field names must literally equal the DB column names.** `supabaseStorageAdapter`/`pgStorageAdapter` pass them through as-is — `portfolioId` in the schema above means DataCloak will write/read a column literally called `portfolioId`, NOT `portfolio_id`. There is no camelCase↔snake_case mapping layer. If your table uses snake_case (the common SQL convention), name the schema fields snake_case too (`portfolio_id: z.string()`) and translate to your app's own camelCase domain type in the service, outside `defineStore` — that translation is domain-shaping, not DataCloak's job.

## DataCloak does not own your schema/DDL — and is not tied to Postgres

**The table/collection must already exist, with the right shape, before `defineStore` touches it.** DataCloak never runs `CREATE TABLE`, never generates a migration, and never checks that your actual DB schema matches what a store's Zod fields expect. Keeping them in sync (id/user*id/blob/schema_version columns for every store, PLUS the plaintext columns above for a mixed `many` store) is manual developer discipline — the same discipline any ORM/ODM requires of you, just without a migration generator. Get it wrong and you won't find out until a read/write actually fails at runtime; there's no compile-time or definition-time check for this (unlike `schemaFingerprint`, which only validates the \_shape of the plaintext data*, never the physical DB schema).

**`StorageAdapter` (`core/types.ts`) is deliberately backend-neutral** — its methods (`getOne`, `putOne`, `getByKey`, `list`, `insert`, ...) are plain async functions moving opaque `BlobRecord` objects around; nothing about the interface assumes SQL, tables, or Postgres specifically. Two implementations exist today, both relational (`supabaseStorageAdapter` via PostgREST, `pgStorageAdapter` via raw SQL) — but a document store like MongoDB could implement the exact same interface (a collection instead of a table, a document instead of a row; the plaintext-column passthrough above maps naturally onto document fields). Nothing in `defineStore`, the crypto, or the guardrails would need to change — only a new adapter file, same shape as the two that exist. That adapter would still need the target collection/table to physically exist with a matching shape; DataCloak's neutrality is about _how_ to talk to storage, not about _whether_ you still have to set that storage up yourself.

## React binding — one hook per cardinality

```tsx
import {
  useStore,
  useKeyedStore,
  useKeyedStoreRange,
  useCollectionStore,
} from "datacloak/react";

function PortfolioPanel() {
  const { data, loading, locked, error, save } = useStore(portfolioStore); // perUser

  if (locked) return <UnlockScreen />;
  if (loading) return <Spinner />;
  return <PortfolioView data={data} onSave={save} />;
}

function TransactionsForMonth({ month }: { month: string }) {
  const { data, save } = useKeyedStore(transactionStore, month); // perKey
  // ...
}

function TransactionsForYear() {
  const { data, loading } = useKeyedStoreRange(transactionStore, {
    from: "2026-01",
    to: "2026-12",
  }); // perKey range — read-only, no save() (write a single key via useKeyedStore/mutate)
  // data: Array<{ key: string; data: T }> | undefined
}

function RebalanceSimulations() {
  const { items, create, update, remove } = useCollectionStore(simulationStore); // many
  // ...
}
```

All three hide the same things from the caller: cryptoHandle+userId gating (`locked`), the initial
fetch, cache read/subscribe, and optimistic write-through with automatic rollback if the
underlying persist fails (`useCollectionStore` rolls back the whole list on `update`/
`remove` failure — read-modify-write, not per-field patching). Wipe-on-lock is centralized
once in `configureSecureStore` (not per hook call) — see `core/config.ts`.

**If the store has `optimisticLock: true`, the hash is threaded automatically — no
`expectedHash`/`saveIfMatch` in sight.** Each hook's cache slot holds `{data, hash}`
internally (`useCollectionStore`'s `items` exposes `hash` per row, since a consumer may
want it for a "someone else edited this" hint); `save`/`update` use `saveIfMatch`/
`updateIfMatch` transparently when available, reading the hash from the cache and writing
the new one back on success — the same `save(data)`/`update(id, data)` call site works
whether or not the store has the lock configured. On conflict, the hook rolls back the
optimistic update and throws `OptimisticLockConflictError` (from `datacloak/react`) —
catch it separately from a generic save failure to show "someone else edited this, reload"
instead of a generic error:

```tsx
try {
  await save(newData);
} catch (e) {
  if (e instanceof OptimisticLockConflictError) {
    // reload and let the user re-apply their change, don't just retry blindly
  } else {
    // generic save failure (network, validation, ...)
  }
}
```

Requires `keys` (a `KeyProvider`) and `cache` (a `CacheAdapter`) in
`configureSecureStore`:

```ts
import { tanstackAdapter } from "datacloak/react";

configureSecureStore({
  storage: supabaseStorageAdapter(getSupabaseClient),
  cache: tanstackAdapter(queryClient),     // requires queryClient's defaultOptions.queries.gcTime: Infinity — see below
  keys: {                                  // KeyProvider: plain subscribable snapshot,
    getCryptoHandle: () => /* your app's current key handle | null — only needs to satisfy CryptoHandle: { pid, encryptJson, decryptJson } */,
    getUserId: () => /* your app's current userId | null */,
    subscribe: (cb) => /* subscribe to changes, return an unsubscribe fn */,
  },
});
```

`KeyProvider` is deliberately **not** hook-shaped (no `useCryptoHandle()`) — a plain
get/subscribe snapshot, read via `useSyncExternalStore` inside each hook, so the port
itself isn't subject to the Rules of Hooks. Since your app's crypto handle/userId almost
always live inside a React context (not a plain external store), bridge them with a small
invisible component that calls your context's hooks and forwards their values into a
module-level `KeyProvider` — see the host app's own
`src/lib/datacloakKeyProvider.ts` + `src/components/DataCloakKeyBridge.tsx` for a
concrete, working reference (bridges `PasskeyContext`/`UserContext`).

**`tanstackAdapter`'s `queryClient` must set `defaultOptions.queries.gcTime: Infinity`
— the adapter throws immediately at construction if it doesn't.** This adapter writes
via `setQueryData`/`getQueryData` and never mounts a real `useQuery` observer, so every
entry it creates has zero observers for its whole life; TanStack schedules that entry's
garbage collection unconditionally at creation time (a separate axis from `staleTime`)
and evicts it once `gcTime` elapses, no matter how many times it was refreshed in
between. With the default 5-minute `gcTime`, cached decrypted data would silently
disappear from every DataCloak-backed hook after that long of the app sitting idle —
with no error, since the `CacheAdapter` contract has no "refetch" concept for a caller to
notice or recover from. `staleTime: Infinity` alone does **not** cover this — it only
stops automatic refetch, not garbage collection. Bounded lifetime still comes from your
app calling `queryClient.clear()` on logout/lock, same as today.

**Ambient writes (`store.set()`/`store.mutate()`, called directly from a service —
not through a hook's `save()`) are cache-aware too:** after a successful persist,
`set()`/`mutate()` (perUser and perKey) push the fresh `{data, hash}` into the
configured `CacheAdapter` themselves, under the exact same key `useStore`/
`useKeyedStore` read from. A service calling `.mutate()` directly (e.g.
`patchPortfolioTransaction`) now keeps every mounted hook for that store in sync,
same as if the write had gone through the hook's own `save()`.

**Deliberate exclusion: `CollectionStore.add()`/`.update()` (`many` cardinality)
do NOT write through to the cache.** Only `perUser`/`perKey` ambient writes
(`set()`/`mutate()` above) do. Safe today because the only consumer is
`useCollectionStore` itself, which already applies its own optimistic
write-through before calling `add()`/`update()` — but the first service that
calls `add()`/`update()` ambiently (bypassing the hook, the same way
`patchPortfolioTransaction` calls `.mutate()` directly) will silently desync
every other mounted `useCollectionStore` for that store until a manual
refetch. If you add such a caller, either write through the cache the same
way `perUser`/`perKey` do, or document why not.

**In-flight fetch deduplication:** all three React bindings (`useStore`,
`useKeyedStore`, `useKeyedStoreRange`) keep a module-level `Map<key, Promise>`
registry — when two components mount at once and both need the SAME cache slot
(same store, same user, same key/range), only the FIRST one actually calls
`store.load*()`; the second awaits that same in-flight promise instead of
firing its own fetch. Without this, two globally-mounted components reading
the same `perUser`/`perKey` slot (e.g. a copilot widget and an import provider
both reading the `budget_categories` label dict on every page) each see an
empty cache and independently hit the network — a real regression, found via
HAR analysis of a full-app tour (see `docs/PERFORMANCE_HAR_ANALYSIS.md` in the
main repo) and fixed the same night `useKeyedStoreRange`'s own range-level
dedup (`inflightRangeFetches`) was already covering the range case. Tests:
"dedupes concurrent fetches across independent hook instances" in
`useStore.test.tsx`/`useKeyedStore.test.tsx`/`useKeyedStoreRange.test.tsx`.

**`useKeyedStoreRange(store, {from, to})`** is the range counterpart of
`useKeyedStore` — read-only (no `save`), for showing several keys at once (e.g. a
year of monthly batches). A `CacheAdapter` has no notion of "subscribe to every key
in `[from, to]`", so the range result is cached as one slot, invalidated via a
per-`(store, user)` write counter that `set()`/`mutate()` bump on every keyed write
(regardless of which key changed) — simple and always correct, at the cost of an
occasional refetch for a write outside the mounted range. `list`/`getRange` need
`listByKeyRange` on the adapter, same requirement as `KeyedStore.list()`.

Verified, runnable usage (including optimistic-rollback and lock-clears-cache behavior)
lives in `datacloak/tests/useStore.test.tsx`, `useKeyedStore.test.tsx`,
`useKeyedStoreRange.test.tsx`, `useCollectionStore.test.tsx`,
`cacheAwareWrites.test.ts` — read them before writing a `KeyProvider` for a new
consumer.

**If a component only needs a boolean lock/unlock gate — never the data or the
`save()` — use `useIsUnlocked()` instead of one of the three hooks above.** It only
needs `keys` (no `cache`), and never exposes the `CryptoHandle` to the caller. See
`datacloak/tests/useIsUnlocked.test.tsx`.

## Aggregations

**A `defineAggregation` is a persisted, declarative read-model derived from one or more
stores — never a value the app computes and writes itself.** Where `defineStore` owns a
row the app writes directly, `defineAggregation` owns a row the FRAMEWORK writes, by
calling the app's `compute()` whenever a source changes or an external's TTL expires. The
persisted result goes through the exact same encrypted envelope/AAD/versioning machinery
`defineStore` already provides (an aggregation is, internally, one `defineStore` the
framework builds and drives) — this section documents the layer on top: source
fingerprinting, debounced recompute, and the extra wire-format guarantees the persisted
envelope makes.

### `defineAggregation` — perUser only

Real read-model from this branch, trimmed for length (`src/services/dashboardAggregation.ts`):

```ts
import { defineAggregation, keyedSource } from "datacloak";

export const dashboardAgg = defineAggregation({
  version: 1,
  schema: DashboardSummarySchema,
  schemaFingerprint: "62df50f2",
  // Same physical row `dashboardSummaryStore` used before this branch (zero migration).
  // `keyColumn: "year_month"` because `account_snapshot_blobs`'s sentinel column is
  // called that, not "key" — see "storage.keyColumn" below.
  storage: {
    table: "account_snapshot_blobs",
    key: "__dashboard__",
    keyColumn: "year_month",
  },
  sources: {
    assets: assetStore,
    accountMeta: keyedSource(accountMetaStore, ACCOUNT_META_KEY),
    snapshots: keyedSource(snapshotStore, STORE_KEY),
    portfolioSeries: portfolioSeriesAgg, // an Aggregation used as a Source — see below
    netWorthSeries: netWorthSeriesAgg, //   same
  },
  externals: {
    currentPortfolio: {
      load: loadCurrentPortfolioMetrics,
      ttlMs: 5 * 60 * 1000,
    },
    existingAccountIds: { load: loadExistingAccountIds, ttlMs: 5 * 60 * 1000 },
  },
  compute: computeDashboardSummary, // a plain function here — see "declarative operator kit" below for the other form
});
```

`version`/`schema`/`schemaFingerprint` follow the exact same discipline as `defineStore`
(a mismatch between `schema` and `schemaFingerprint` throws at definition time — see
"Guardrail: versioning is mandatory" above). The difference: an aggregation never needs a
`BlobMigrator` — a shape or `version` change just means "recompute from sources", there is
no old ciphertext to migrate in place, since nothing but the framework ever wrote that row.

`storage.table` is a `defineStore` `name` (a real backing table); `storage.key` is the
sentinel row identifier within it. Several aggregations commonly share ONE physical table
via distinct `key` values (`dashboardAgg`/`netWorthSeriesAgg` above both live in
`account_snapshot_blobs`, alongside the real per-month snapshot rows) — the same "generic
domain key column" convention `snapshotStore` itself already uses.

**`storage.keyColumn`** (optional, defaults to `"key"`): the DB column name backing that
sentinel key. Set it when wiring an aggregation onto a PRE-EXISTING table whose sentinel
column has a different name — `account_snapshot_blobs.year_month` above, not `key` — so
reusing an already-shipped table costs zero DB migration. Omit it for a table that only
ever exists for aggregations (this module's own convention, `"key"`).

### Sources: stores, keyed stores, and other aggregates

A `sources` entry can be any of three things (`Source` in `core/aggregation.ts`):

- **A `perUser` `Store`** — passed directly, e.g. `assets: assetStore` above.
- **`keyedSource(store, key)`** — wraps a `perKey` `KeyedStore` read through ONE fixed
  key, for the two real cases in this branch where a `perKey` store is always read
  through a single sentinel key per user, never a real range: `snapshotStore` and
  `accountMetaStore` (`accountMeta: keyedSource(accountMetaStore, ACCOUNT_META_KEY)`,
  `snapshots: keyedSource(snapshotStore, STORE_KEY)` above). A `KeyedStore` can't be
  passed as a `Source` directly — `perKey` reads/writes always need a key, there's no
  key-less signature to fall back to the way a `perUser` `Store` has one. Deliberately
  fixed-key-only: reading a range or the whole collection of a `KeyedStore` as a single
  aggregation input isn't supported (no real caller needs it).
- **Another `Aggregation`** — "aggregate-as-source", below.

**Aggregate-as-source.** A `sources` entry can itself be an `Aggregation` — a downstream
aggregate reads the upstream one's PERSISTED value via its own `.get()`, never
duplicating its `compute`/`externals` logic. Real example, `src/services/netWorthSeriesAggregation.ts`:

```ts
export const netWorthSeriesAgg = defineAggregation({
  version: 1,
  schema: NetWorthSeriesSchema,
  schemaFingerprint: "2d5aa43a",
  storage: {
    table: "account_snapshot_blobs",
    key: "__net_worth_series__",
    keyColumn: "year_month",
  },
  sources: {
    assets: assetStore,
    accountMeta: keyedSource(accountMetaStore, ACCOUNT_META_KEY),
    snapshots: keyedSource(snapshotStore, STORE_KEY),
    portfolioSeries: portfolioSeriesAgg, // aggregate-as-source
  },
  compute: ({ sources }) => {
    const portfolioHistory =
      sources.portfolioSeries.byPortfolio[ALL_PORTFOLIOS_KEY]?.Max ?? [];
    return buildRetroactiveHistoryClient(/* ... */ portfolioHistory /* ... */);
  },
});
```

The product motivation is avoiding a double fetch: `portfolioSeriesAgg` (Task 5, point A)
computes an expensive time series against live market data behind an `ExternalInput`
TTL. Without aggregate-as-source, both `netWorthSeriesAgg` and `dashboardAgg` (which ALSO
lists `portfolioSeries: portfolioSeriesAgg` in its own `sources`, above) would each need
their own copy of that fetch/compute logic — instead both read the SAME persisted series,
computed once. A change in `portfolioSeriesAgg` still propagates: its own fingerprint
(see "Aggregation envelope wire format" below) flows into every aggregation that sources
it, marking them stale through the exact same `ensureSubscribed`/`isFresh` machinery a
`Store` source already uses — no special-casing needed for the aggregate-as-source case.

**Gotcha: a cold aggregate-as-source throws, then self-heals — it never blocks or waits.**
An aggregation never waits on another aggregation's very first compute — if the upstream
source (e.g. `portfolioSeriesAgg` above) has never itself persisted a value in this
session, `computeAndPersist` throws immediately (`"source aggregation ... has no
persisted value yet"`). Reading that source (`source.get()`) is what kicks off the
upstream's OWN background compute as a side effect, though — so once it finishes and
publishes, the downstream aggregation (already `ensureSubscribed` to it like any other
source) reacts exactly like it would to any other source write, and recomputes
successfully. In practice this means: the FIRST page load of a session that reads a
multi-level aggregation DAG (e.g. a dashboard sourcing three other lazy aggregates) can
throw once and settle a moment later — usually well under a second, but a UI that only
destructures `data` from `useAggregation` and ignores `computing`/`error` will show its
"nothing here yet" empty state during that window even when real data exists and just
hasn't finished computing. See "Cross-aggregation activity signal" below for how a test
(E2E or otherwise) waits this out deterministically instead of guessing with a fixed
timeout, and make sure any UI reading such an aggregation treats `data === null` as
"unknown yet", not "confirmed empty" (`src/pages/Dashboard.tsx`'s `isCompletelyEmpty`
is the reference fix for this exact gotcha).

### Declarative operator kit — `datacloak/aggregate`

A second, declarative form for `compute`, alongside the plain-function form used by every
real aggregation wired in this branch so far (`dashboardAgg`/`netWorthSeriesAgg` above
both use plain functions, because their math already lives in `shared/domain/*` — see
`aggregate/index.ts`'s own header comment for the target shape):

```ts
import * as agg from "datacloak/aggregate";

defineAggregation({
  // ...
  compute: {
    liquidita: agg.sum("banche", "saldo"),
    immobili: agg.sum("assets", "valore", { where: { tipo: "immobile" } }),
    totaleAttivi: agg.expr((f) => f.liquidita + f.immobili),
    varEur: agg.lastDelta("storicoPatrimonio", "valore"),
    effScore: agg.custom((f, src) => computeEffScore(f)),
  },
});
```

Verified, compiling usage lives in `datacloak/examples/basic-usage.ts`'s
`aggregationExample()` (`compute: { total: agg.sum("invoices", "amount") }`) and
`datacloak/tests/aggregateOperators.test.ts`. `defineAggregation` compiles a
`FieldOperators` record into the exact same function shape ONCE, at definition time
(`compileFieldOperators`, `aggregate/compile.ts`) — nothing downstream of that point knows
a declarative form exists.

The five operators, deliberately ONLY these five (YAGNI — no `avg`/`count`/`min`/`max`/
`groupBy`, however tempting in the abstract):

| Operator                       | Does                                                                                                                       |
| ------------------------------ | -------------------------------------------------------------------------------------------------------------------------- |
| `sum(source, field, {where})`  | Sums `field` across every row of `source`, optionally filtered by exact match                                              |
| `sumWith(source, fn, {where})` | Like `sum`, but the per-row value is `fn(row)` — for reductions with real logic (typically calling into `shared/domain/*`) |
| `expr(fn)`                     | `fn` reads the aggregate's OTHER already-computed fields; dependency order resolved automatically, cycles fail loud        |
| `lastDelta(source, field)`     | Reads `field` off the LAST row of `source` (an ordered time series)                                                        |
| `custom(fn)`                   | Escape hatch — `fn(fields, sources)` sees everything else already computed, plus the raw sources                           |

Prefer the declarative form when every output field is expressible as one of the five
operators over array/collection sources — no domain logic belongs in the operators
themselves (`sumWith`/`custom`'s `fn` is always the caller's own function, e.g. from
`shared/domain/*`). Prefer the plain-function form (as every real aggregate in this branch
does today) when the computation is a single existing pure function you're reusing as-is
(`calculateDashboardMetrics`, `buildRetroactiveHistoryClient`) — wrapping an
already-correct, already-tested function in five operator calls would be pure overhead for
no readability gain.

### `useAggregation` binding

Same plain get/subscribe + `useSyncExternalStore` pattern as `useStore`/`useKeyedStore`,
reading through the CacheAdapter slot `defineAggregation` publishes to
(`aggregationStateCacheKey`) — never a bespoke subscription of its own. Real usage,
`src/hooks/usePortfolioHistory.ts`:

```tsx
import { useAggregation } from "datacloak/react";

export function usePortfolioHistory({ range, portfolioId, enabled }) {
  const { data, computing, error, refresh } =
    useAggregation(portfolioSeriesAgg);
  // data: T | null · computing: boolean · stale: boolean · error: Error | null
  // refresh(opts?): forces a recompute now — see bypassExternalsTtl below
  const forceRefresh = () => refresh({ bypassExternalsTtl: true });
  // ...
}
```

`{ data, computing, stale, error, refresh }` — `data` is the last PERSISTED value (`null`
if never computed), painted immediately; `computing`/`stale` reflect a background
recompute in flight, the same non-blocking contract `Aggregation.get()` has. This is a
READ binding only — an aggregate's `compute()` is the only thing that ever produces its
data, `refresh()` exists for an explicit retry/force, not a write path.

**`refresh({ bypassExternalsTtl: true })`** clears the aggregation's in-memory external
cache before recomputing, forcing a real refetch even within the external's own `ttlMs` —
distinct from a plain `refresh()`, which still respects each external's TTL (it forces the
recompute, not a refetch of data that's still fresh by the external's own clock). The one
real consumer, `usePortfolioHistory` above: the price-history worker just wrote new market
data, and the caller — not the TTL clock — knows it's time to see it now. A plain
`refresh()` there would still serve the 15-minute-old cached `marketData` external,
showing stale prices right after an explicit "refresh". One-shot: only that ONE recompute's
external fetches are forced; the refreshed value re-enters the normal TTL-gated cache
afterward.

### Cross-aggregation activity signal — `isAnyAggregationComputing()`

`useAggregation(agg).computing` tells you whether ONE specific aggregation is mid-recompute
— useful when a component already knows which aggregation it cares about. Sometimes a
caller doesn't: an E2E test that just wrote data (created an account, imported a
transaction, added an investment) doesn't know — and shouldn't need to know — which
aggregation(s) that write marks stale, only that it should wait for ALL of them to settle
before asserting on the resulting UI (see the "cold aggregate-as-source throws, then
self-heals" gotcha above — a fixed `sleep()` before asserting is exactly the wrong tool
here, since it's either too short, racing a real recompute, or an arbitrary guess that's
too long).

`isAnyAggregationComputing()` (plus `subscribeGlobalAggregationActivity(cb)` to react to
changes) is a single counter, incremented while ANY aggregation defined anywhere in the
process has a compute in flight and decremented when it settles — not per-aggregation-name,
so a caller never needs to enumerate which aggregations exist:

```ts
import {
  isAnyAggregationComputing,
  subscribeGlobalAggregationActivity,
} from "datacloak";
import { useIsAnyAggregationComputing } from "datacloak/react";

// React: reactive boolean, same useSyncExternalStore pattern as useIsUnlocked.
const computing = useIsAnyAggregationComputing();
```

The intended shape for a host app: render the React binding once, in a hidden DOM node
somewhere always-mounted (the host app's `src/components/AggregationActivityIndicator.tsx`
— `data-testid="aggregations-status"` + `data-computing="true"|"false"`), then have an E2E
helper poll that attribute (the host app's `tests/e2e/_helpers.ts`,
`waitForAggregationsIdle(page)`) after any write that could trigger a recompute, before
asserting on the downstream effect. Deliberately NOT a per-aggregation registry: a caller
that already knows which aggregation to wait on already has `useAggregation(agg).computing`
directly — this primitive is for the "I don't know or care which ones, just tell me when
it's quiet" case only.

### `invalidateOn` / `invalidateChannel` — externals sourced from non-Store data

An `external` can depend on data that lives entirely OUTSIDE any DataCloak `Store` — a
plaintext table read via a plain REST call, e.g. "which account ids currently exist"
(`src/services/dashboardAggregation.ts`'s `existingAccountIds`). No `source` ever changes
when that data changes, so nothing naturally marks the aggregation stale before its `ttlMs`
expires — a `refresh({ bypassExternalsTtl: true })` call from the app is the only way to
force freshness, and every call site that mutates the underlying data would otherwise need
to remember to make it.

`invalidateOn` names the channel(s) an external depends on; `invalidateChannel(name)` (also
exported from `datacloak`) is called ONCE, at the single place the underlying mutation
actually happens — every aggregation with a matching `invalidateOn` entry has THAT
external's cache cleared and a recompute forced immediately, without the caller needing to
know which aggregation(s), if any, depend on it:

```ts
// dashboardAggregation.ts — declare the dependency once, where the external is defined.
externals: {
  existingAccountIds: {
    load: loadExistingAccountIds,
    ttlMs: 5 * 60 * 1000,
    invalidateOn: ["accounts-changed"],
  },
},
```

```ts
// appApi.ts — emit the event once, at the single choke point that mutates `accounts`.
import { invalidateChannel } from "datacloak";

export async function createManualAccount(input: unknown) {
  const result = await appApiRequest("/accounts/manual", {
    method: "POST",
    body: input,
  });
  invalidateChannel("accounts-changed");
  return result;
}
```

Scoped to just the ONE external that declared the channel — an unrelated external on the
same aggregation, or one with no `invalidateOn` at all, is never refetched by it. A channel
nobody subscribed to is a safe no-op.

### Cold-session freshness verification

`isFresh()` normally trusts the persisted envelope for any source never OBSERVED live
this session (`currentSourceFingerprints.get(name) === undefined` → "no signal, assume
unchanged") — correct if the source genuinely hasn't changed, wrong if it changed via a
path this session's live subscriptions never saw (a previous session's recompute
interrupted after a source write landed but before persisting, or another device/tab
writing while this one was closed/idle).

`.get()` now verifies every such never-observed source against the REAL current hash
before trusting the envelope, the first time a fresh identity subscribes — a no-op (zero
network calls) once every source has a real tracked value, which converges after the
first check. `KeyedSourceRef` sources sharing one physical table (e.g. `dashboardAgg`'s
`snapshots`/`portfolioSeries`-as-source/`netWorthSeries`-as-source/
`currentPortfolioMetrics`-as-source, all in `account_snapshot_blobs`) are verified with
ONE batched call via the adapter's optional `getHashesByKeys`, not one `getHash` per
source. `Aggregation` sources delegate to the upstream's own `.get()` (recursing its own
cold check if it's also cold) and compare via the same `aggregationSourceFingerprint`
`computeAndPersist` already persists — no new fingerprint convention.

This closes the "did a change I never observed live get missed" gap for a NEW session
(a page reload/reopen self-heals reliably now) — it does NOT make an already-open,
idle tab reactively pick up a write from a different tab/device without a fresh `.get()`
call (no server push/polling loop; `CacheAdapter` is in-memory, per tab/process, and
`ensureSubscribed`'s check happens once per identity, not on every `.get()`). Adapters
without `getHashesByKeys` (or without `getHash`/`loadWithHash` at all) fall back to more
round trips, never break correctness — see `StorageAdapter.getHashesByKeys`'s doc comment.

### Write-reaction — `onSourceWrite`

**A different primitive from `defineAggregation`, not a variant of it.** An aggregation
persists a DERIVED value the framework owns end-to-end; `onSourceWrite` instead reacts to
writes on a `KeyedStore` by calling an arbitrary app-supplied `handler` that itself
read/mutates a DIFFERENT store — one with its OWN, independent `optimisticLock` semantics.
Wrapping that in `defineAggregation`'s internal store (hardcoded `optimisticLock: false`,
see below) would silently throw away a real cross-writer conflict. `onSourceWrite` never
persists anything itself; it only observes writes and invokes `handler`.

The one real consumer, `src/lib/secureStore.ts` (registered once, at bootstrap, right
after `configureSecureStore`):

```ts
import { onSourceWrite } from "datacloak";

onSourceWrite(
  txStore,
  async ({ keys }) => {
    if (!keys.length) return;
    const sorted = [...keys].sort();
    await rebuildMonths(monthRange(sorted[0], sorted[sorted.length - 1]));
  },
  { debounceMs: 500, coalesce: true },
);
```

Every ambient write on `txStore` (import, row edit, delete, recurring-transaction
materialization, demo seed) debounces/coalesces into ONE `handler({ keys })` call carrying
the union of touched months, replacing 6 manual `rebuildMonths` call sites that used to be
scattered across the app. `rebuildMonths` writes `snapshotStore`
(`optimisticLock: true`) — a real cross-writer conflict there (two tabs rebuilding
overlapping months) throws `OptimisticLockConflictError`, and `onSourceWrite` retries that
failure automatically with exponential backoff (default: 5 attempts, 1s base delay,
doubling, capped at 30s) instead of silently dropping the failed months. The current
unresolved failure (if retries haven't succeeded yet) is inspectable via
`handle.getLastError()` on the handle `onSourceWrite` returns.

**`handle.flush()`** forces whatever is currently pending (a debounced write still waiting
out `debounceMs`, or a scheduled backoff retry) to run NOW, and awaits it — including any
single-flight rerun a write arriving mid-run queues. For a caller that just finished a known
batch (e.g. an import that wrote N months) and needs the reaction's effect visible before it
proceeds, without knowing which keys were touched or duplicating `handler`'s own logic at the
call site, and without waiting out the debounce window. Real consumer,
`src/lib/secureStore.ts` exports a thin wrapper around it:

```ts
const txSnapshotRebuildHandle = onSourceWrite(txStore, handler, {
  debounceMs: 500,
});

export function flushTxSnapshotRebuild(): Promise<void> {
  return txSnapshotRebuildHandle.flush();
}
```

`AccountsRegister.tsx`'s post-import reconcile modal calls this before reading
`conto.saldoContabile`, instead of racing the 500ms debounce. Never rejects — a `handler`
failure is already surfaced via `getLastError()`/`console.error`; resolves immediately if
nothing is pending or in flight.

**Known architectural limit (documented, not hidden):** a `handler` call already in flight
that crosses a same-tab session/identity switch can still persist under the wrong
identity — `rebuildMonths`'s own `mutate()` call resolves the ambient identity fresh at
its own invocation, not pinned to whichever identity was active when `handler` was
dispatched. `onSourceWrite` isolates its OWN bookkeeping (`lastError`, scheduled retries)
from a stale identity correctly, but it cannot retroactively stop `rebuildMonths`'s
`mutate()` from resolving a NEW identity mid-flight — a pre-existing gap in how
`rebuildMonths` resolves ambient identity, not introduced by this module. See
`datacloak/core/onSourceWrite.ts`'s own doc comment for the exact scope of this gap.

### `optimisticLock`: materialized store vs. derived aggregate

**`optimisticLock: true` belongs to materialized stores with partial update, where two
writers can legitimately conflict** — e.g. `snapshotStore`, updated incrementally by
`rebuildMonths` from potentially two tabs at once. **`optimisticLock: false` belongs to
derived read-models** — a clobber there just rewrites the same result (or gets
invalidated by fingerprints on the next read), never a real conflict.

This isn't a per-call decision for `defineAggregation`: `AggregationDef` has no
`optimisticLock` field at all — the internal store `defineAggregation` builds hardcodes
`optimisticLock: false` (`core/aggregation.ts`). Every aggregation in this branch (A/C/D —
`portfolioSeriesAgg`/`netWorthSeriesAgg`/`dashboardAgg`) gets this for free, by
construction, never by a choice a caller makes.

The choice a future developer actually faces is upstream of that: **is what I'm building a
derived read-model, or a materialized store someone partially updates?** If it's the
former, use `defineAggregation` — the framework already made the right call.
If a "read model" ever seems to need `optimisticLock: true`, that's the signal the shape
isn't a derived aggregate at all: build it as a real `defineStore` (like `snapshotStore`)
updated by a `onSourceWrite` reaction (like `rebuildMonths`), not as a `defineAggregation`.

### Anti-sprawl: when NOT to persist an aggregation

Not every derived value belongs in `defineAggregation`. If a computation is a pure
`useMemo` over data that's already cache-resident from a SINGLE store, with no remote I/O
and no cumulative-over-time logic, it stays a plain function in the view — persisting it
would add a DB row, a fingerprint subscription, and a debounce timer for something that
already recomputes for free on every render.

Reference case, explicitly excluded from this branch's plan: `src/hooks/useBudgetAggregation.ts`.
It calls `buildReportAggregation` inside a `useMemo` over `useTransactions`'s already
TanStack-cached data — no persistence, no framework involvement:

```ts
const aggregation = useMemo(
  () =>
    buildReportAggregation({
      transazioni,
      period,
      budgetCategorie: resolvedBudgetCategorie,
      budgetGruppi: resolvedBudgetGruppi,
      ...(today ? { today } : {}),
    }),
  [transazioni, period, resolvedBudgetCategorie, resolvedBudgetGruppi, today],
);
```

The signal that something DOES belong in `defineAggregation` instead: a remote fetch
(`ExternalInput`), a cumulative-over-time computation that would otherwise re-scan every
month on every render (`buildRetroactiveHistoryClient`'s net-worth history), or a value
several independent views need to agree on byte-for-byte (`dashboardAgg`'s consistency
with `Investimenti.tsx`'s portfolio metrics). Absent those, keep it a `useMemo`.

### Aggregation envelope wire format

The plaintext payload `defineAggregation` persists — BEFORE the standard DataCloak
encryption/AAD/versioning wraps it (see "Wire format: envelope version" at the top of this
file for THAT layer; the `v` below is a different field, do not confuse the two):

```ts
interface PersistedEnvelope<T> {
  v: number;
  computedAt: string;
  sourceFingerprints: Record<string, string | null>;
  externalsFetchedAt: Record<string, string>;
  data: T | null;
}
```

(`core/aggregation.ts`'s `PersistedEnvelope`.) This is a **language-neutral spec**: an
implementation in another language (e.g. Swift, for the mobile app) must be able to
read/write this envelope from this description alone, never from reading the TypeScript.
Rules that make it portable:

- **Stable JSON, no language-specific semantics.** No `undefined` anywhere — a JS-only
  value with no JSON representation; absence is always `null`, never a missing/undefined
  field. Key order carries no meaning — a reader must not assume or rely on any ordering.
  Every number is finite — never `NaN`/`Infinity`, which JSON itself cannot represent.

- **Field semantics:**
  - `v` — the aggregation DEFINITION's own version (`AggregationDef.version`), bumped
    when the compute logic or output shape changes meaningfully. NOT the ciphertext
    envelope's `EncryptedField.v` (1–4, compression + AAD format) documented earlier in
    this file — same field name, two unrelated concepts, one inside the other.
  - `computedAt` — ISO 8601 timestamp of when THIS envelope's `compute()` call finished.
  - `sourceFingerprints` — one entry per `sources` key, mapping to either a fingerprint
    string or `null` (see below for how each is computed).
  - `externalsFetchedAt` — one entry per `externals` key, the ISO 8601 timestamp of when
    that external was last actually fetched (as opposed to served from the in-memory TTL
    cache) — compared against `ttlMs` to decide whether the next recompute must refetch.
  - `data` — the aggregate's own output, validated by the aggregate's Zod `schema`; `null`
    only before the very first successful compute has ever persisted.

- **Fingerprint computation, per source kind** (verified against `core/aggregation.ts`,
  not assumed):
  - **`Store` source** (perUser, or the fixed key inside a `keyedSource`): the store's own
    `content_hash` — the keyed HMAC-SHA256 described in the `content_hash` section above,
    read via that store's `loadWithHash`. If the store was NOT defined with
    `contentHash: true`, this is always `null` — that source contributes no fingerprint
    signal, and staleness detection for it relies entirely on the CacheAdapter's
    ambient-write notification (a write that was never observed this session is treated
    as "unchanged", per `isFresh`'s own contract — see that function's doc comment).
  - **Aggregation-as-source:** an aggregation has no `content_hash` column — it isn't a
    `Store` at the storage layer — so its fingerprint is `JSON.stringify(data)` of its own
    persisted `data` (`aggregationSourceFingerprint`). Computed identically in the two
    places that must agree: the upstream aggregation publishes this digest to the shared
    cache slot right after a real (non-skip-write) persist; the downstream aggregation
    computes the SAME digest live, from the value its own `.get()` call just returned.

- **The explicit goal:** a Swift (or any other language) implementation for the mobile
  app should be able to decrypt a DataCloak blob, parse this envelope, decide freshness,
  and re-encrypt an updated one, using only this section plus the top-of-file envelope/AAD
  spec — never needing to read `datacloak/core/aggregation.ts` itself.

## What DataCloak doesn't do yet (v1 scope — 2026-07-04)

Explicit error at definition (never a silent stub), with a `FIXME` in the source:

- **`encrypt: "none"`** (fully plaintext row, zero blob) — no real EW consumer.
- **Mixed `enc()` fields with an `identity` other than `"many"`** (perUser/perKey) — no
  real consumer needs them today.
- **Hub-and-spoke storage** (plaintext columns + ref on one backend, blob on another,
  e.g. low-cost object storage) — planned capability, not implemented yet.
- **Cross-session persistent skip-fetch cache** (skip the network round-trip across page
  reloads, not just within a session) — needs a persisted cache (ciphertext on
  IndexedDB, say), no consumer yet. See "`content_hash`" above — the in-session variant
  IS built.
- **React Native**: the crypto engine (`@noble/*`) and `core/keyDerivation.ts` are
  already isomorphic — `webauthnKeyProvider` (`adapters/webauthnKeyProvider.ts`) is the
  **web** adapter (uses `navigator.credentials`, browser-only). RN needs its own adapter
  (native passkey/biometrics) calling the same `deriveKey`/`createKeyHandle` — not
  written yet, but the split already isolates exactly what would need to change.
  **Known RN gap beyond the KeyProvider:** `core/crypto.ts` uses
  `CompressionStream`/`DecompressionStream` (web + Deno API) for the gzip step of every
  encrypt/decrypt — Hermes does not implement it, so RN needs a polyfill or a
  pluggable compression hook before any store works there. `useAutoLock`
  (`react/useAutoLock.ts`) is also web-only (`window` events); the other React hooks
  (`useStore`/`useKeyedStore`/`useCollectionStore`/`useIsUnlocked`) have no DOM
  dependency and should work on RN as-is.
- **True DEK rotation** (the DEK's actual bytes change — not `KeyHandle.wrapWithKek`,
  which re-wraps the _same_ DEK under a new KEK and is already built and used by EW's
  `RecoveryUnlockModal`/`Impostazioni`) — deliberately not built, no real trigger today.
  A lazy per-row convergence (a "legacy DEK" fallback symmetric to `migrateLegacyAAD`)
  was considered and **rejected**: it breaks multi-device consistency, and no production
  zero-knowledge system rotates that way. **If ever built: a synchronous, session-
  invalidating ceremony (Bitwarden-style), never a framework-level lazy mechanism.** Full
  rationale (the multi-device failure mode, the 1Password/Bitwarden/Proton and Matrix/Olm
  comparison): `_local/plans/done/20260626-1111000-secure-store-framework.md` § "Decisioni aperte".

## Extending `StorageAdapter`

If a new usage pattern needs a capability the adapter doesn't have (e.g. a new way to
address rows): add the method as **optional** (`method?:`) on `StorageAdapter`
(`datacloak/core/types.ts`), implement it in `supabaseStorageAdapter`, and write an
in-memory adapter in the test (`datacloak/tests/*.test.ts`, see `defineStoreMany.test.ts`
for the pattern). `defineStore` must throw an explicit, descriptive error if the
configured adapter doesn't support the requested capability — never a silent fallback.
Optional methods today: `putIfMatch`/`updateByIdIfMatch` (optimistic locking), `list`/
`insert`/`updateById`/`deleteById` (`identity: "many"`), `listByKeyRange` (`perKey`
range queries), and `getHash` (in-session skip-fetch revalidation, above) — an adapter
missing one simply never unlocks that specific capability, every other capability keeps
working.

## Architecture: the ports

`StorageAdapter` (persistence — Supabase/Postgres today) · `KeyProvider` (where the app's
current key handle + userId live — the host app's implementation bridges WebAuthn/passkey,
but the port itself doesn't require that) · `CacheAdapter` (React binding's cache — a real
`tanstackAdapter(queryClient)` ships today) · `CryptoHandle` (the minimal shape a key
handle must have — `{ pid, encryptJson, decryptJson }` — see `core/types.ts`; an app
derives its key however it wants, WebAuthn/passkey, password KDF, hardware token, as long
as the resulting object structurally satisfies this). Extending DataCloak = implementing
an adapter or supplying a conforming object, never touching the core.

**`StorageAdapter` implementations shipped today:**

- `supabaseStorageAdapter(getClient)` — uses `@supabase/supabase-js`'s query builder, i.e.
  PostgREST (HTTP + RLS via JWT). Requires the Supabase stack, not just a Postgres
  connection.
- `pgStorageAdapter(getClient)` — real SQL against plain Postgres (self-hosted, RDS, etc.),
  no Supabase/PostgREST required. `getClient` is duck-typed (`query(text, params) => {
rows }`, matching node-postgres's shape) — no hard dependency on `pg` or any specific
  driver; bring your own connection.

Both implement the exact same `StorageAdapter` interface (`core/types.ts`) — swapping one
for the other requires no changes to `defineStore` calls, only to `configureSecureStore`.

## Node scripts & multi-user concurrency — `datacloak/node`

`configureSecureStore`'s ambient identity (`keys: KeyProvider`) is a single
module-level variable — fine for a browser tab (exactly one user at a time) but unsafe
for a Node script/service that handles multiple users concurrently, e.g. `Promise.all`
over per-user jobs: every ambient `store.get()`/`store.set()` call would see whichever
identity was configured last, across every in-flight promise chain.

`datacloak/node` exports `alsKeyProvider` (a `KeyProvider` backed by Node's
`AsyncLocalStorage`) and `withIdentity(userId, cryptoHandle, fn)`, which binds an
identity to the current async context for the lifetime of `fn` — every promise chain
it spawns sees its own identity, isolated from sibling chains, even under `Promise.all`.
Outside any `withIdentity` scope the getters return `null`, so an ambient call fails
loud (`"no active session (locked)"`) instead of silently reusing a stale identity.

```ts
import { alsKeyProvider, withIdentity } from "datacloak/node";

configureSecureStore({
  storage: pgStorageAdapter(getClient),
  keys: alsKeyProvider,
});

await Promise.all(
  users.map(({ userId, cryptoHandle }) =>
    withIdentity(userId, cryptoHandle, () =>
      myStore.mutate((d) => ({ ...d, synced: true })),
    ),
  ),
);
```

This is a separate entry point on purpose: `node:async_hooks` must never reach the
browser bundle, so `datacloak/node` is never imported from `datacloak` (bare barrel) or
`datacloak/react`.

## Package boundary — a real npm workspace, not a path alias

`datacloak/` is a real npm package (`"name": "datacloak"` in its own `package.json`),
wired into the host app via **npm workspaces** — the root `package.json` declares
`"workspaces": ["datacloak"]`, and `npm install` symlinks `node_modules/datacloak` →
`../datacloak`. Every consumer (the host app's `src/`/`backend/`, or any other app that
takes a dependency on this package) imports it as a bare specifier, exactly like any
npm package: `import { defineStore } from "datacloak"`. There is **no bundler-specific
path alias** (no `@datacloak` entry in `vite.config.ts`/`tsconfig.json`'s `paths`) —
resolution goes through the package's own `exports` map, the same mechanism that would
apply if `datacloak/` were published to a registry and installed as a normal dependency.
This is what makes the "OSS-extractable" claim checkable rather than aspirational: moving
the folder to its own repo and publishing it changes nothing about how consumers import
it.

`datacloak/package.json`'s `exports` map governs what's importable from outside:

```json
"exports": {
  ".": "./index.ts",
  "./react": "./react/index.ts",
  "./node": "./node/index.ts",
  "./adapters/*": "./adapters/*",
  "./core/*": "./core/*"
}
```

It also declares the real dependency split: `zod`/`@noble/ciphers`/`@noble/hashes` are
hard `dependencies` (the core needs them unconditionally); `@supabase/supabase-js`,
`react`, `@tanstack/react-query` are `peerDependencies`, all marked `optional: true` in
`peerDependenciesMeta` — a consumer using only `pgStorageAdapter` needs none of them
installed (`pgStorageAdapter` itself has zero package dependency at all, not even `pg` —
see above).

To make that real, **`datacloak` (the bare barrel, `index.ts`) exports ONLY `core/` —
zero adapters.** Importing `datacloak` for `defineStore` must never pull Supabase,
TanStack, or the WebAuthn browser API into the module graph. Import an adapter from its
own file instead — the same `.ts`-extension-inclusive style used everywhere else in this
codebase (`allowImportingTsExtensions`):

```ts
import { supabaseStorageAdapter } from "datacloak/adapters/supabaseStorageAdapter.ts";
import { pgStorageAdapter } from "datacloak/adapters/pgStorageAdapter.ts";
import { webauthnKeyProvider } from "datacloak/adapters/webauthnKeyProvider.ts";
import { mnemonicRecovery } from "datacloak/adapters/mnemonicRecovery.ts";
import { createWorkerKeyHandle } from "datacloak/adapters/workerKeyHandle.ts";
import { tanstackAdapter } from "datacloak/react"; // React binding only, not the bare barrel
```

**`datacloak/tsconfig.json`** is a second, standalone compiler config with no `paths` at
all — no reliance on the host app's `tsconfig.json`. It's the actual self-containment
check: if `datacloak/`'s own code (including its tests) only imports itself via relative
paths (`../core/...`, `./testKeyHandle.ts`, ...) — never its own package name — this
passes. Run it with `npm run datacloak:typecheck`. Any file inside `datacloak/` that
imports `datacloak`/`datacloak/*` (its own external-facing package name, only meaningful
from OUTSIDE the package) instead of a relative path breaks this check — that's the
signal a boundary was crossed by accident.

## How these docs stay in sync

Project convention: **examples are real code, not prose.** `datacloak/examples/*.ts` is
compiled by `tsc` (`npm run typecheck`, always mandatory before declaring work done) and
called from `datacloak/tests/examples.test.ts` (`npm test`). If you change the public
signature of `defineStore`/`Store`/`KeyedStore`/`CollectionStore`
(`datacloak/core/store.ts`, exported from `datacloak/index.ts`):

1. Update `datacloak/examples/basic-usage.ts` FIRST until it compiles again and the test
   passes.
2. Mirror the change into THIS README (the "Cardinality"/"What DataCloak doesn't do yet"
   tables and the Quickstart snippets, which are manually copied from the examples — not
   generated, so they need to be kept in sync by hand, but a broken example in step 1 is
   the signal you can't ignore).
3. If the change is a new capability (new cardinality, new encryption mode), add a line to
   the "What DataCloak doesn't do yet" table → move it to "Cardinality"/Quickstart once
   implemented, instead of leaving it in both places.

There is no automatic API-reference generator yet (TypeDoc or similar) — deliberately
deferred: DataCloak has no external consumers yet, generating one now would be
documentation for no reader. When DataCloak is extracted as an OSS package (plan goal
(a)), it's the first thing to add: the signatures are already documented with TSDoc in
`datacloak/core/*.ts`, ready to be extracted.
