# Wire format: envelope versions, legacy AAD, and the aggregation envelope

Read this to understand what's actually stored on the server — the ciphertext envelope
version byte, how to port a table that already has data encrypted under a different AAD
convention, and the plaintext envelope `defineAggregation` persists before Zechinus's own
encryption wraps it. Back to [README.md](../README.md).

## Envelope version (`EncryptedField.v`)

Every ciphertext blob carries a `v: 1 | 2 | 3 | 4 | 5 | 6` alongside the ciphertext and
nonce — NOT the same thing as `StoreDef.version` (the schema's own version, used for
migrators). `v` tells decrypt which compression AND which AAD serialization the blob
was written with, so decoding is deterministic from the stored value alone (no
try-and-fallback, no double decrypt):

| `v` | Compression | AAD serialization         |
| --- | ----------- | ------------------------- |
| 1   | none (raw)  | v1 — pipe-join            |
| 2   | gzip        | v1 — pipe-join            |
| 3   | none (raw)  | v2 — JSON 4-tuple         |
| 4   | gzip        | v2 — JSON 4-tuple         |
| 5   | none (raw)  | v3 — JSON 5-tuple + epoch |
| 6   | gzip        | v3 — JSON 5-tuple + epoch |

AAD-v1 (legacy) joined the 4 AAD fields (`userId|table|field|rowId`) with no escaping — a
`|` inside any component made two logically different AADs serialize to the identical byte
string, which AES-GCM then treated as interchangeable. AAD-v2 (canonical) is
`JSON.stringify([userId, table, field, rowId])` — unambiguous regardless of what
characters a component contains. **`1`/`2` are read-only** (a blob already on disk before
this fix): every new write always emits `3` or `4`, UNLESS `FieldAAD.epoch` is set, in
which case it emits `5`/`6` (AAD-v3 — the same 4-tuple plus `epoch`, key-custody rotation,
Fase 2.1 of the mobile roadmap plan). `epoch` is optional and opt-in: omit it entirely and
nothing changes, `encryptField`/`encryptJson` keep emitting `3`/`4` exactly as before —
`5`/`6` only appear once a caller starts passing an epoch (`createKeyHandle`'s consumer,
or a future rotation-aware `KeyHandle`). A row still holding `1`/`2` converges to
canonical the next time anything touches it, via the same lazy write-back
`legacyAAD`/schema-version migrations already use — no live migration script needed.

<a id="legacy-aad"></a>

## Porting a table with a different historical AAD — `legacyAAD`

**For porting an existing table only — omit entirely for a brand-new store** (the vast
majority of stores never set this). Zechinus's canonical AAD is
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
import { migrateLegacyAAD } from "zechinus";

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

<a id="aggregation-envelope-wire-format"></a>

## Aggregation envelope wire format

The plaintext payload `defineAggregation` persists — BEFORE the standard Zechinus
encryption/AAD/versioning wraps it (see "Envelope version" above for THAT layer; the `v`
below is a different field, do not confuse the two):

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
    `content_hash` — the keyed HMAC-SHA256 described in
    [docs/content-hash-and-locking.md](content-hash-and-locking.md), read via that store's
    `loadWithHash`. If the store was NOT defined with `contentHash: true`, this is always
    `null` — that source contributes no fingerprint signal, and staleness detection for it
    relies entirely on the CacheAdapter's ambient-write notification (a write that was
    never observed this session is treated as "unchanged", per `isFresh`'s own contract —
    see that function's doc comment).
  - **Aggregation-as-source:** an aggregation has no `content_hash` column — it isn't a
    `Store` at the storage layer — so its fingerprint is `JSON.stringify(data)` of its own
    persisted `data` (`aggregationSourceFingerprint`). Computed identically in the two
    places that must agree: the upstream aggregation publishes this digest to the shared
    cache slot right after a real (non-skip-write) persist; the downstream aggregation
    computes the SAME digest live, from the value its own `.get()` call just returned.

- **The explicit goal:** a Swift (or any other language) implementation for the mobile
  app should be able to decrypt a Zechinus blob, parse this envelope, decide freshness,
  and re-encrypt an updated one, using only this section plus the envelope/AAD spec above
  — never needing to read `zechinus/core/aggregation.ts` itself.
