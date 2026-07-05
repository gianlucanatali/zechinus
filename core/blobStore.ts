/**
 * defineBlobStore — factory for encrypted stores in "blob" mode: one encrypted
 * record per user. Consolidates the load/save pattern duplicated today across
 * the host app's *Service files (asset, portfolio, snapshot, ...). No knowledge
 * of Supabase or TanStack: encrypts via the injected `CryptoHandle` (never touches
 * raw crypto itself) and persists via the `StorageAdapter` from config.
 *
 * Canonical AAD: { userId: pid, table: name, field: "data", rowId: pid } — ALWAYS
 * used for writes, and tried first on every read. `legacyAAD` (porting only) is a
 * read-only fallback — see its doc comment.
 * ⚠️ Changing `name` changes the AAD → existing blobs stop decrypting.
 */

import { type BlobMigrator } from "./versioning.ts";
import { loadRow, saveRow, saveRowIfMatch, canonicalAAD } from "./rowStore.ts";
import { getSecureStoreConfig } from "./config.ts";
import type { CryptoHandle, FieldAAD } from "./types.ts";

export interface BlobStore<T> {
  readonly name: string;
  readonly version: number;
  load(userId: string, cryptoHandle: CryptoHandle): Promise<T>;
  save(userId: string, cryptoHandle: CryptoHandle, data: T): Promise<void>;
  /** Present only when the store declares `contentHash: true`. */
  loadWithHash?(
    userId: string,
    cryptoHandle: CryptoHandle,
  ): Promise<{ data: T; hash: string | null }>;
  /**
   * Present only when the store declares `optimisticLock: true`. Conditional write:
   * `expectedHash: null` means "I believe no row exists yet"; a non-null hash means
   * "only write if the row's current content_hash still matches this". `{ok:false,
   * hash:null}` on conflict — never thrown, a conflict is an expected, recoverable
   * outcome. On success, `hash` is the new content_hash, ready to pass into the next
   * `saveIfMatch` call with no extra fetch needed to learn it.
   */
  saveIfMatch?(
    userId: string,
    cryptoHandle: CryptoHandle,
    data: T,
    expectedHash: string | null,
  ): Promise<{ ok: boolean; hash: string | null }>;
}

export interface BlobStoreDef<T> {
  /** Collection/table = the `table` value in the AAD. Never change it for existing data. */
  name: string;
  version: number;
  /** Value returned when the record doesn't exist (or isn't encrypted). */
  empty: T;
  migrators?: BlobMigrator[];
  /**
   * For PORTING an existing table only — omit entirely for a brand-new store. See
   * `StoreDef.legacyAAD` in `store.ts` for the full contract (read-old-if-needed,
   * always-write-canonical, never masks a real error).
   */
  legacyAAD?: (cryptoHandle: CryptoHandle) => FieldAAD;
  /**
   * Set `true` if this table has a `content_hash` column — DataCloak computes it
   * internally (SHA-256 of the plaintext envelope, see `core/contentHash.ts`), no
   * app-supplied function needed: hashing JSON is fully generic, unlike
   * `StorageAdapter`/`KeyProvider` which genuinely need app-specific knowledge.
   * Omit (or `false`) for tables without the column — writing a hash the schema
   * doesn't have a column for would fail at the storage layer. Enables `loadWithHash`.
   */
  contentHash?: boolean;
  /**
   * Requires `contentHash: true`. Enables `saveIfMatch` — a conditional write
   * that rejects (returns `{ok:false}`, never throws) instead of silently
   * overwriting a row that changed since it was last read. See README's
   * "Optimistic locking" section for the multi-tab conflict this prevents.
   */
  optimisticLock?: boolean;
}

export function defineBlobStore<T>(def: BlobStoreDef<T>): BlobStore<T> {
  if (def.optimisticLock && !def.contentHash) {
    throw new Error(
      `defineBlobStore(${def.name}): optimisticLock requires contentHash: true — the lock compares against that column.`,
    );
  }
  const migrators = def.migrators ?? [];

  async function save(
    userId: string,
    cryptoHandle: CryptoHandle,
    data: T,
  ): Promise<void> {
    const { storage } = getSecureStoreConfig();
    await saveRow(
      cryptoHandle,
      (record) => storage.put(def.name, userId, [], record),
      canonicalAAD(cryptoHandle, def.name),
      data,
      def.version,
      def.contentHash,
    );
  }

  async function loadInternal(
    userId: string,
    cryptoHandle: CryptoHandle,
  ): Promise<{ data: T; hash: string | null }> {
    const { storage } = getSecureStoreConfig();
    return loadRow(
      cryptoHandle,
      {
        get: () => storage.get(def.name, userId, []),
        put: (record) => storage.put(def.name, userId, [], record),
      },
      canonicalAAD(cryptoHandle, def.name),
      {
        storeName: def.name,
        rowLabel: "",
        version: def.version,
        migrators,
        empty: def.empty,
        legacyAAD: def.legacyAAD?.(cryptoHandle),
      },
      (data) => save(userId, cryptoHandle, data),
    );
  }

  async function load(userId: string, cryptoHandle: CryptoHandle): Promise<T> {
    return (await loadInternal(userId, cryptoHandle)).data;
  }

  const store: BlobStore<T> = {
    name: def.name,
    version: def.version,
    load,
    save,
  };

  if (def.contentHash) {
    store.loadWithHash = (userId, cryptoHandle) =>
      loadInternal(userId, cryptoHandle);
  }

  if (def.optimisticLock) {
    store.saveIfMatch = async (userId, cryptoHandle, data, expectedHash) => {
      const { storage } = getSecureStoreConfig();
      return saveRowIfMatch(
        cryptoHandle,
        storage.putIfMatch
          ? (record, hash) =>
              storage.putIfMatch!(def.name, userId, [], record, hash)
          : undefined,
        canonicalAAD(cryptoHandle, def.name),
        data,
        def.version,
        expectedHash,
        `defineBlobStore(${def.name}): the configured adapter doesn't support optimistic locking (putIfMatch missing).`,
      );
    };
  }

  return store;
}
