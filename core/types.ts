/**
 * Types/ports of the secure-store framework (DataCloak).
 *
 * Initial slice: only the `StorageAdapter` port for blob-mode stores (one encrypted
 * record per user). The full `PersistenceAdapter` (ensureSchema / DDL + fields mode)
 * arrives in later phases — see the plan.
 */

/**
 * AAD for a specific field/row — cryptographically binds ciphertext to WHERE it
 * lives (table + row + user), never encrypted itself. See README's "Mental model".
 */
export type FieldAAD = {
  userId: string;
  table: string;
  field: string;
  rowId: string;
};

/**
 * Wire-serialized ciphertext shape (opaque to storage). `v` encodes both compression
 * and AAD serialization, so decrypt is deterministic from the stored value alone —
 * see `crypto.ts`'s file-level doc comment for the full 1–4 mapping.
 */
export type EncryptedField = {
  ct: string;
  n: string;
  v: 1 | 2 | 3 | 4;
};

/**
 * The minimal crypto contract DataCloak needs — NOT a specific app's full key-handle
 * type. An app derives its DEK however it wants (WebAuthn/passkey, password KDF,
 * hardware token, ...); as long as the resulting object has these three members, it
 * works with DataCloak (TypeScript's structural typing makes this automatic — no
 * adapter/wrapper code required on the app side).
 */
export interface CryptoHandle {
  /** Pseudonymous id derived from the key — used as `userId` in every AAD. */
  readonly pid: string;
  encryptJson<T>(value: T, aad: FieldAAD): Promise<EncryptedField>;
  decryptJson<T>(enc: EncryptedField, aad: FieldAAD): Promise<T>;
  /**
   * Keyed MAC (HMAC-SHA256) of the canonical (JSON-stringified) payload — the
   * server-visible `content_hash` column. Optional for structural conformance
   * only: any store declaring `contentHash: true` requires it at runtime, and
   * `encodeBlob` throws loud, naming the store, if it's missing rather than
   * falling back to an unkeyed digest (that would leak a plaintext fingerprint
   * to the server — the whole point of keying it with the DEK).
   */
  hashContent?(payload: unknown): Promise<string>;
}

/** Storage row of a blob store: one opaque encrypted record per (collection, userId). */
export interface BlobRecord {
  schemaVersion: number;
  /** Serialized EncryptedField (`enc:` prefix). Opaque to storage. */
  blob: string;
  /** Hash of the canonical content (optional: some stores don't use it). */
  contentHash?: string | null;
}

/**
 * An extra column identifying a row beyond `user_id`, which every method below takes
 * as its own mandatory, named parameter — never folded into this list. This isn't a
 * style choice: DataCloak only ever encrypts data E2E under a per-user DEK, so by
 * definition every encrypted row is scoped to exactly one user. Keeping `userId` a
 * distinguished parameter makes that structural invariant impossible to omit by
 * construction (a missing argument is a compile error; an incomplete array is not).
 * Empty array = perUser (row addressed by `user_id` alone); one entry = perKey (row
 * addressed by `user_id` + a domain key, e.g. `year_month`).
 */
export interface KeyColumn {
  column: string;
  value: string;
}

/**
 * Persistence port — neutral contract (NOT SQL): point read/write per user only,
 * NEVER rich queries. Implementations: Supabase, pg, Mongo, in-memory (tests).
 * Invariant: operates only on ciphertext, `userId` scoping mandatory.
 *
 * `get`/`put` cover BOTH perUser (`extraKeys: []`) and perKey (`extraKeys: [key]`)
 * — they're the same read/write at a row addressed by 1 vs 2 columns, not two
 * different mechanisms (a Supabase/pg implementation is the same query with one
 * extra `.eq()`/`AND` clause). Mandatory: every real adapter supports both.
 */
export interface StorageAdapter {
  get(
    collection: string,
    userId: string,
    extraKeys: KeyColumn[],
  ): Promise<BlobRecord | null>;
  put(
    collection: string,
    userId: string,
    extraKeys: KeyColumn[],
    record: BlobRecord,
  ): Promise<void>;
  /**
   * Conditional write for optimistic locking (`defineStore`'s `optimisticLock: true`,
   * requires `contentHash: true`). `expectedHash: null` means "I believe there's no
   * REAL content yet" — covers BOTH "no row exists" AND "the row exists but was never
   * hashed" (legacy data written before `content_hash` existed). Both succeed; the
   * only genuine conflict for `expectedHash: null` is a row that already has a REAL
   * hash (someone else's write beat us to it). A non-null `expectedHash` means "only
   * write if the row's current content_hash still matches this" (an `UPDATE ... WHERE
   * content_hash = expected` equivalent). Returns `false` on conflict — a conflict is
   * an expected, recoverable outcome, never thrown as an error. Optional: not every
   * adapter supports it.
   */
  putIfMatch?(
    collection: string,
    userId: string,
    extraKeys: KeyColumn[],
    record: BlobRecord,
    expectedHash: string | null,
  ): Promise<boolean>;
  /**
   * Lightweight hash-only read for skip-fetch revalidation: returns the row's
   * current content_hash without downloading the blob. `null` means "row missing
   * or its content_hash column is null" — callers treat both as "cannot skip,
   * do a full load". Optional: adapters that don't implement it simply never
   * skip (every load is a full load, today's behavior).
   */
  getHash?(
    collection: string,
    userId: string,
    extraKeys: KeyColumn[],
  ): Promise<string | null>;
  /**
   * perKey range query: all rows for the user whose key falls in `[from, to]`
   * (lexicographic comparison — works for sortable keys like `year_month`). Optional:
   * a perKey store can still `load`/`save` a single key without this; only
   * `KeyedStore.list()` needs it.
   */
  listByKeyRange?(
    collection: string,
    userId: string,
    keyColumn: string,
    from: string,
    to: string,
  ): Promise<Array<{ key: string; record: BlobRecord }>>;
  /**
   * perKey bulk creation: writes N distinct keys in a single round-trip. A real
   * INSERT, not an upsert — a key that already exists must make the WHOLE batch
   * fail (unique-constraint violation), never silently overwrite it. Built for
   * callers that create many brand-new keys at once and know none of them exist
   * yet (e.g. seeding 36 months of demo transactions right after a full wipe) —
   * `KeyedStore.createMany()` is the only caller. Optional: a keyed store can
   * still `save`/`set`/`mutate` a single key without it.
   */
  insertMany?(
    collection: string,
    userId: string,
    entries: Array<{ extraKeys: KeyColumn[]; record: BlobRecord }>,
  ): Promise<void>;
  /**
   * 'many': all rows for the user (generated id, one blob per row). `plainColumns`/`plain`
   * carry the plaintext columns (mixed enc() case) alongside the blob — empty array/object
   * when the store has no plaintext fields (pure encrypt:"all").
   */
  list?(
    collection: string,
    userId: string,
    plainColumns: string[],
  ): Promise<
    Array<{ id: string; record: BlobRecord; plain: Record<string, unknown> }>
  >;
  insert?(
    collection: string,
    userId: string,
    id: string,
    record: BlobRecord,
    plain: Record<string, unknown>,
  ): Promise<void>;
  updateById?(
    collection: string,
    userId: string,
    id: string,
    record: BlobRecord,
    plain: Record<string, unknown>,
  ): Promise<void>;
  /** Conditional variant of `updateById` — same semantics as `putIfMatch`. */
  updateByIdIfMatch?(
    collection: string,
    userId: string,
    id: string,
    record: BlobRecord,
    plain: Record<string, unknown>,
    expectedHash: string | null,
  ): Promise<boolean>;
  deleteById?(collection: string, userId: string, id: string): Promise<void>;
}

/**
 * Key lifecycle port — where the current crypto handle and user id live. Returns a
 * `CryptoHandle` (a capability object), never the raw DEK bytes — those are
 * confined to the Worker that derives them (see `RawDekBytes`/`asRawDekBytes`).
 * Deliberately NOT React-hook-shaped (no `useCryptoHandle()`): a plain subscribable
 * snapshot, so any binding (React via `useSyncExternalStore`, or something else
 * entirely) can read it without the port itself being subject to the Rules of
 * Hooks. `subscribe` fires on any change: unlock, lock, user switch.
 */
export interface KeyProvider {
  getCryptoHandle(): CryptoHandle | null;
  getUserId(): string | null;
  subscribe(callback: () => void): () => void;
}

/**
 * Cache port for the React binding — plain get/set/subscribe, no hook shape (same
 * reasoning as `KeyProvider`). Keys are plain strings, not TanStack-style arrays:
 * DataCloak owns key construction (`<storeName>:<userId>`), the adapter maps it to
 * whatever its backing cache needs.
 */
export interface CacheAdapter {
  get<T>(key: string): T | undefined;
  set<T>(key: string, data: T): void;
  subscribe(key: string, callback: () => void): () => void;
  /** Wipes everything this adapter holds — called automatically on lock (cryptoHandle → null). */
  clear(): void;
}
