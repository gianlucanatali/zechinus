# `content_hash`, optimistic locking, and `mutate()` retry

Read this to detect concurrent writes (two tabs editing the same record) or skip a no-op
write — `contentHash: true`, `optimisticLock: true`, and how `mutate()` behaves on a
locked store. Back to [README.md](../README.md).

## `content_hash` — `contentHash: true`

If a table has a `content_hash` column, set `contentHash: true` and Zechinus computes it
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
a boolean, not an injected function by default. Zechinus computes it internally via the
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

**The React hooks thread the hash automatically** — see [docs/react.md](react.md). App code
using `useStore`/`useKeyedStore`/`useCollectionStore` never touches `saveIfMatch`/
`expectedHash` directly; only code calling `Store`/`KeyedStore`/`CollectionStore` raw
(outside React, or inside a custom binding) needs the pattern above.

### `mutate()` on an optimisticLock store — single attempt by default, opt-in retry

`Store.mutate`/`KeyedStore.mutate` wrap the `loadWithHash`/`saveIfMatch` pattern above into
one call: load, apply your transform, write, done. On a store with `optimisticLock: true`,
the DEFAULT behavior is a **single attempt** — a conflict throws
`OptimisticLockConflictError` immediately, same as calling `saveIfMatch` yourself. This is
deliberate: a blind retry would re-run your transform against fresher data without you ever
deciding whether that's still valid — the right call for a transform that overwrites
specific fields from data captured outside `current` (e.g. a user-typed value), where a
genuine multi-tab edit conflict must stay visible, not get silently clobbered by whichever
writer retries harder.

Pass `{ retryOnConflict: N }` to opt into automatic retry, bounded to N total attempts: on
conflict, `mutate()` re-reads the fresh current state and re-applies your transform to it
(not the stale one), then retries the conditional write. **Only safe when the transform is
a pure, self-contained derivation of `current`** that stays correct against any fresher
state — the canonical case is appending an already-generated record:

```ts
// Safe to retry: appending `record` is correct no matter what else changed in `current`
// (e.g. an unrelated feature writing to the same row moments earlier).
await assetStore.mutate(
  (current) => ({ ...current, assets: [...current.assets, record] }),
  { retryOnConflict: 3 },
);
```

Without the option, behavior is byte-for-byte what it was before this existed — no breaking
change for any existing `mutate()` call site.
