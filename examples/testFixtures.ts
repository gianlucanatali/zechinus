/**
 * FAKE port implementations — examples/tests only, NOT code to copy into your project.
 *
 * `basic-usage.ts` needs a `StorageAdapter`, a `KeyProvider`, and a `CacheAdapter` to
 * run at all, but a real backing store/browser session isn't available in this
 * standalone script. The three fixtures below exist ONLY to satisfy those ports well
 * enough for the examples to compile and execute in isolation.
 *
 * A real app implements each of these ports EXACTLY ONCE for the whole app — not once
 * per store or aggregation. See the host app's real implementation for reference:
 * `src/lib/secureStore.ts`. Do not treat `memoryAdapter`, `memoryCache`, or
 * `fixedKeyProvider` as a pattern to replicate per-store; they are throwaway
 * in-memory stand-ins for a database, a subscribable cache, and an already-unlocked
 * key session, respectively.
 */

import type {
  StorageAdapter,
  BlobRecord,
  CacheAdapter,
  CryptoHandle,
  KeyProvider,
} from "../index.ts";

/**
 * Minimal in-memory adapter, supports all 3 cardinalities. Examples/tests only.
 * `get`/`put` cover BOTH perUser (`extraKeys: []`) and perKey (`extraKeys: [key]`)
 * — same row-address, one map, keyed by however many extra columns were given.
 */
export function memoryAdapter(): StorageAdapter {
  const rows = new Map<string, BlobRecord>();
  const many = new Map<string, BlobRecord>();
  const rowKey = (
    collection: string,
    userId: string,
    extraKeys: { value: string }[],
  ) => [collection, userId, ...extraKeys.map((k) => k.value)].join(":");
  return {
    async get(collection, userId, extraKeys) {
      return rows.get(rowKey(collection, userId, extraKeys)) ?? null;
    },
    async put(collection, userId, extraKeys, record) {
      rows.set(rowKey(collection, userId, extraKeys), record);
    },
    async putIfMatch(collection, userId, extraKeys, record, expectedHash) {
      const key = rowKey(collection, userId, extraKeys);
      const current = rows.get(key) ?? null;
      if (expectedHash === null) {
        if (current) return false; // row already exists — caller's belief was stale
        rows.set(key, record);
        return true;
      }
      if (!current || current.contentHash !== expectedHash) return false;
      rows.set(key, record);
      return true;
    },
    async list(collection, userId) {
      const prefix = `${collection}:${userId}:`;
      return [...many]
        .filter(([key]) => key.startsWith(prefix))
        .map(([key, record]) => ({
          id: key.slice(prefix.length),
          record,
          plain: {},
        }));
    },
    async insert(collection, userId, id, record) {
      many.set(`${collection}:${userId}:${id}`, record);
    },
    async updateById(collection, userId, id, record) {
      many.set(`${collection}:${userId}:${id}`, record);
    },
    async deleteById(collection, userId, id) {
      many.delete(`${collection}:${userId}:${id}`);
    },
    async insertMany(collection, userId, entries) {
      for (const { extraKeys } of entries) {
        const key = rowKey(collection, userId, extraKeys);
        if (rows.has(key)) throw new Error(`insertMany: ${key} already exists`);
      }
      for (const { extraKeys, record } of entries) {
        rows.set(rowKey(collection, userId, extraKeys), record);
      }
    },
  };
}

/** Real subscribable in-memory CacheAdapter — required by `defineAggregation` (it
 * detects a source write through this port, not by re-fetching every source on every
 * read). See `zechinus/tests/aggregation.test.ts`'s identical fixture. */
export function memoryCache(): CacheAdapter {
  const data = new Map<string, unknown>();
  const subs = new Map<string, Set<() => void>>();
  return {
    get: (key) => data.get(key) as never,
    set: (key, value) => {
      data.set(key, value);
      for (const cb of subs.get(key) ?? []) cb();
    },
    subscribe: (key, cb) => {
      if (!subs.has(key)) subs.set(key, new Set());
      subs.get(key)!.add(cb);
      return () => subs.get(key)?.delete(cb);
    },
    clear: () => {
      data.clear();
      for (const set of subs.values()) for (const cb of set) cb();
    },
  };
}

// Ambient calls (`get`/`set`/`mutate`/`createMany`) resolve the CryptoHandle from
// a configured `KeyProvider` instead of taking it as a parameter — this fixed
// provider mirrors a single already-unlocked session, like a real app's bridge
// to its passkey/DEK controller.
export const fixedKeyProvider = (cryptoHandle: CryptoHandle): KeyProvider => ({
  getCryptoHandle: () => cryptoHandle,
  getUserId: () => "u1",
  subscribe: () => () => {},
});
