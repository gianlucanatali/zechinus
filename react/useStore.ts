/**
 * React binding for `perUser` stores — a free function (`useStore(store)`), not a
 * method on the store object, so `core/` stays React-free. Requires `keys` and
 * `cache` in `configureSecureStore` (throws an explicit error otherwise).
 *
 * What it hides from the caller: cryptoHandle+userId gating, cache read/subscribe, the
 * initial `store.load()` fetch, and optimistic write-through with rollback on
 * `save()` failure. Wipe-on-lock is centralized in `core/config.ts`, not here — one
 * subscription for the whole app, not one per mounted `useStore()` call.
 *
 * When the store has `optimisticLock: true`, `save()` transparently uses
 * `saveIfMatch` — the cache slot holds `{data, hash}` internally so the caller never
 * passes a hash by hand; a conflict throws `OptimisticLockConflictError` instead of
 * silently overwriting someone else's write.
 */
import { useCallback, useEffect, useState, useSyncExternalStore } from "react";
import { getSecureStoreConfig } from "../core/config.ts";
import type { Store } from "../core/store.ts";
import { OptimisticLockConflictError } from "./errors.ts";

interface CacheEntry<T> {
  data: T;
  hash: string | null;
}

/**
 * In-flight fetch registry, keyed by `key` (`${store.name}:${userId}`) — shared
 * across every `useStore` instance in the app (module-level, not per-hook-call).
 * Without it, two globally-mounted components reading the SAME perUser store
 * (e.g. UserContext's own load + a direct usePortfolio() call elsewhere) each
 * see an empty cache slot and independently fetch — a real, observed
 * regression (duplicate network round-trips). Same pattern as
 * useKeyedStore/useKeyedStoreRange's in-flight dedup registries.
 */
const inflightFetches = new Map<string, Promise<CacheEntry<unknown>>>();

function fetchDeduped<T>(
  key: string,
  fetcher: () => Promise<CacheEntry<T>>,
): Promise<CacheEntry<T>> {
  const existing = inflightFetches.get(key);
  if (existing) return existing as Promise<CacheEntry<T>>;
  const promise = fetcher().finally(() => {
    inflightFetches.delete(key);
  });
  inflightFetches.set(key, promise as Promise<CacheEntry<unknown>>);
  return promise;
}

export interface UseStoreResult<T> {
  data: T | undefined;
  loading: boolean;
  locked: boolean;
  error: Error | null;
  save: (data: T) => Promise<void>;
  /**
   * Forces a fresh fetch and refreshes the cache slot — for callers that wrote
   * through a path OUTSIDE this hook's own `save()` (e.g. a backend endpoint that
   * persisted directly, not an ambient `store.mutate()`/`.set()` call in this
   * browser tab), where no cache-aware write-through ever ran to pick it up.
   */
  reload: () => Promise<void>;
}

export function useStore<T>(store: Store<T>): UseStoreResult<T> {
  const { keys, cache } = getSecureStoreConfig();
  if (!keys) {
    throw new Error(
      `${store.name}.use(): no KeyProvider configured — pass 'keys' to configureSecureStore()`,
    );
  }
  if (!cache) {
    throw new Error(
      `${store.name}.use(): no CacheAdapter configured — pass 'cache' to configureSecureStore()`,
    );
  }

  const cryptoHandle = useSyncExternalStore(
    keys.subscribe,
    keys.getCryptoHandle,
  );
  const userId = useSyncExternalStore(keys.subscribe, keys.getUserId);
  const key = `${store.name}:${userId ?? ""}`;

  const subscribeToKey = useCallback(
    (cb: () => void) => cache.subscribe(key, cb),
    [cache, key],
  );
  const cached = useSyncExternalStore(subscribeToKey, () =>
    cache.get<CacheEntry<T>>(key),
  );

  const [error, setError] = useState<Error | null>(null);

  useEffect(() => {
    setError(null);
    if (!cryptoHandle || !userId) return;
    if (cache.get<CacheEntry<T>>(key) !== undefined) return;
    let cancelled = false;
    const fetch = fetchDeduped(key, () =>
      store.loadWithHash
        ? store.loadWithHash(userId, cryptoHandle)
        : store
            .load(userId, cryptoHandle)
            .then((data) => ({ data, hash: null })),
    );
    fetch
      .then((entry) => {
        if (!cancelled) cache.set(key, entry);
      })
      .catch((e: unknown) => {
        if (!cancelled) setError(e instanceof Error ? e : new Error(String(e)));
      });
    return () => {
      cancelled = true;
    };
  }, [cryptoHandle, userId, key, cache, store]);

  const save = useCallback(
    async (data: T) => {
      if (!cryptoHandle || !userId) {
        throw new Error(
          `${store.name}.use().save(): called while locked (no cryptoHandle/userId)`,
        );
      }
      const previous = cache.get<CacheEntry<T>>(key);
      cache.set(key, { data, hash: previous?.hash ?? null });
      try {
        if (store.saveIfMatch) {
          const result = await store.saveIfMatch(
            userId,
            cryptoHandle,
            data,
            previous?.hash ?? null,
          );
          if (!result.ok) throw new OptimisticLockConflictError(store.name);
          cache.set(key, { data, hash: result.hash });
        } else {
          await store.save(userId, cryptoHandle, data);
          cache.set(key, { data, hash: null });
        }
      } catch (e) {
        if (previous !== undefined) cache.set(key, previous);
        throw e;
      }
    },
    [cryptoHandle, userId, key, cache, store],
  );

  const reload = useCallback(async () => {
    if (!cryptoHandle || !userId) return;
    const entry = store.loadWithHash
      ? await store.loadWithHash(userId, cryptoHandle)
      : { data: await store.load(userId, cryptoHandle), hash: null };
    // Re-check identity AFTER the await: if a lock (or a switch to a different
    // user) happened while this fetch was in flight, never let decrypted
    // content from a superseded session repopulate the cache — same principle
    // as useKeyedStoreRange's previousRef-cleared-on-lock guard.
    if (keys.getCryptoHandle() === null || keys.getUserId() !== userId) return;
    cache.set(key, entry);
  }, [cryptoHandle, userId, key, cache, store, keys]);

  return {
    data: cached?.data,
    loading:
      !!cryptoHandle && !!userId && cached === undefined && error === null,
    locked: !cryptoHandle || !userId,
    error,
    save,
    reload,
  };
}
