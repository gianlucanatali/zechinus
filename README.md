# DataCloak

**End-to-end encryption as an adapter layer, for apps that already own their backend.**

DataCloak isn't "an encrypted store" — it's the correct cryptographic decisions made for
you. Anyone can write a CRUD store; DataCloak owns the hard 20% that gets skipped or
gotten wrong — per-row AAD, versioned envelopes, runtime validation, always-explicit
encryption — so the domain only declares **the shape of its data**, never the mechanics.

> Status: v1 in development, inside the the host app repo (`datacloak/`). Extraction into a
> standalone OSS MIT package is planned but not done yet — see
> `_local/plans/20260626-1111000-secure-store-framework.md` for the full design-decision
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
import { useStore, useKeyedStore, useCollectionStore } from "datacloak/react";

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
  cache: tanstackAdapter(queryClient),     // reference CacheAdapter, real TanStack Query
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

Verified, runnable usage (including optimistic-rollback and lock-clears-cache behavior)
lives in `datacloak/tests/useStore.test.tsx`, `useKeyedStore.test.tsx`,
`useCollectionStore.test.tsx` — read them before writing a `KeyProvider` for a new
consumer.

**If a component only needs a boolean lock/unlock gate — never the data or the
`save()` — use `useIsUnlocked()` instead of one of the three hooks above.** It only
needs `keys` (no `cache`), and never exposes the `CryptoHandle` to the caller. See
`datacloak/tests/useIsUnlocked.test.tsx`.

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
  comparison): `_local/plans/20260626-1111000-secure-store-framework.md` § "Decisioni aperte".

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
