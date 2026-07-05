/**
 * React binding for `perKey` stores — mirrors `useStore` exactly, plus the domain
 * key as an explicit argument (each key is an independent cache slot, e.g. one
 * `useKeyedStore(store, "2026-06")` per month rendered).
 *
 * Same hash-threading as `useStore`: when the store has `optimisticLock: true`,
 * `save()` transparently uses `saveIfMatch`, and a conflict throws
 * `OptimisticLockConflictError`.
 */
import { useCallback, useEffect, useState, useSyncExternalStore } from "react";
import { getSecureStoreConfig } from "../core/config.ts";
import type { KeyedStore } from "../core/store.ts";
import { OptimisticLockConflictError } from "./errors.ts";

interface CacheEntry<T> {
  data: T;
  hash: string | null;
}

export interface UseKeyedStoreResult<T> {
  data: T | undefined;
  loading: boolean;
  locked: boolean;
  error: Error | null;
  save: (data: T) => Promise<void>;
}

export function useKeyedStore<T>(
  store: KeyedStore<T>,
  key: string,
): UseKeyedStoreResult<T> {
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
  const cacheKey = `${store.name}:${userId ?? ""}:${key}`;

  const subscribeToKey = useCallback(
    (cb: () => void) => cache.subscribe(cacheKey, cb),
    [cache, cacheKey],
  );
  const cached = useSyncExternalStore(subscribeToKey, () =>
    cache.get<CacheEntry<T>>(cacheKey),
  );

  const [error, setError] = useState<Error | null>(null);

  useEffect(() => {
    setError(null);
    if (!cryptoHandle || !userId) return;
    if (cache.get<CacheEntry<T>>(cacheKey) !== undefined) return;
    let cancelled = false;
    const fetch = store.loadWithHash
      ? store.loadWithHash(userId, cryptoHandle, key)
      : store
          .load(userId, cryptoHandle, key)
          .then((data) => ({ data, hash: null }));
    fetch
      .then((entry) => {
        if (!cancelled) cache.set(cacheKey, entry);
      })
      .catch((e: unknown) => {
        if (!cancelled) setError(e instanceof Error ? e : new Error(String(e)));
      });
    return () => {
      cancelled = true;
    };
  }, [cryptoHandle, userId, key, cacheKey, cache, store]);

  const save = useCallback(
    async (data: T) => {
      if (!cryptoHandle || !userId) {
        throw new Error(
          `${store.name}.use().save(): called while locked (no cryptoHandle/userId)`,
        );
      }
      const previous = cache.get<CacheEntry<T>>(cacheKey);
      cache.set(cacheKey, { data, hash: previous?.hash ?? null });
      try {
        if (store.saveIfMatch) {
          const result = await store.saveIfMatch(
            userId,
            cryptoHandle,
            key,
            data,
            previous?.hash ?? null,
          );
          if (!result.ok) throw new OptimisticLockConflictError(store.name);
          cache.set(cacheKey, { data, hash: result.hash });
        } else {
          await store.save(userId, cryptoHandle, key, data);
          cache.set(cacheKey, { data, hash: null });
        }
      } catch (e) {
        if (previous !== undefined) cache.set(cacheKey, previous);
        throw e;
      }
    },
    [cryptoHandle, userId, key, cacheKey, cache, store],
  );

  return {
    data: cached?.data,
    loading:
      !!cryptoHandle && !!userId && cached === undefined && error === null,
    locked: !cryptoHandle || !userId,
    error,
    save,
  };
}
