/**
 * Types/ports of the secure-store framework (DataCloak).
 *
 * Initial slice: only the `StorageAdapter` port for blob-mode stores (one encrypted
 * record per user). The full `PersistenceAdapter` (ensureSchema / DDL + fields mode)
 * arrives in later phases — see the plan.
 */

import type { DekHandle } from "@crypto/field-crypto";

/** Storage row of a blob store: one opaque encrypted record per (collection, userId). */
export interface BlobRecord {
  schemaVersion: number;
  /** Serialized EncryptedField (`enc:` prefix). Opaque to storage. */
  blob: string;
  /** Hash of the canonical content (optional: some stores don't use it). */
  contentHash?: string | null;
}

/**
 * Persistence port — neutral contract (NOT SQL): point read/write per user only,
 * NEVER rich queries. Implementations: Supabase, pg, Mongo, in-memory (tests).
 * Invariant: operates only on ciphertext, `userId` scoping mandatory.
 *
 * `getOne`/`putOne` = **perUser** cardinality (one blob per user, PK `user_id`).
 * `getByKey`/`putByKey` = **perKey** cardinality (one blob per `(user_id, <keyColumn>)`,
 *   e.g. `year_month`/`table_name`). Optional: an adapter that doesn't implement them
 *   only supports perUser stores; `defineStore` throws an explicit error if missing.
 */
export interface StorageAdapter {
  getOne(collection: string, userId: string): Promise<BlobRecord | null>;
  putOne(collection: string, userId: string, record: BlobRecord): Promise<void>;
  getByKey?(
    collection: string,
    userId: string,
    keyColumn: string,
    keyValue: string,
  ): Promise<BlobRecord | null>;
  putByKey?(
    collection: string,
    userId: string,
    keyColumn: string,
    keyValue: string,
    record: BlobRecord,
  ): Promise<void>;
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
  deleteById?(collection: string, userId: string, id: string): Promise<void>;
}

/**
 * Key lifecycle port — where the DEK and current user id live. Deliberately NOT
 * React-hook-shaped (no `useDek()`): a plain subscribable snapshot, so any binding
 * (React via `useSyncExternalStore`, or something else entirely) can read it without
 * the port itself being subject to the Rules of Hooks. `subscribe` fires on any
 * change: unlock, lock, user switch.
 */
export interface KeyProvider {
  getDek(): DekHandle | null;
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
  getQueryData<T>(key: string): T | undefined;
  setQueryData<T>(key: string, data: T): void;
  subscribe(key: string, callback: () => void): () => void;
  /** Wipes everything this adapter holds — called automatically on lock (dek → null). */
  clear(): void;
}
