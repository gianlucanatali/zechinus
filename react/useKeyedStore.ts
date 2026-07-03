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

  const dek = useSyncExternalStore(keys.subscribe, keys.getDek);
  const userId = useSyncExternalStore(keys.subscribe, keys.getUserId);
  const cacheKey = `${store.name}:${userId ?? ""}:${key}`;

  const subscribeToKey = useCallback(
    (cb: () => void) => cache.subscribe(cacheKey, cb),
    [cache, cacheKey],
  );
  const cached = useSyncExternalStore(subscribeToKey, () =>
    cache.getQueryData<CacheEntry<T>>(cacheKey),
  );

  const [error, setError] = useState<Error | null>(null);

  useEffect(() => {
    setError(null);
    if (!dek || !userId) return;
    if (cache.getQueryData<CacheEntry<T>>(cacheKey) !== undefined) return;
    let cancelled = false;
    const fetch = store.loadWithHash
      ? store.loadWithHash(userId, dek, key)
      : store.load(userId, dek, key).then((data) => ({ data, hash: null }));
    fetch
      .then((entry) => {
        if (!cancelled) cache.setQueryData(cacheKey, entry);
      })
      .catch((e: unknown) => {
        if (!cancelled) setError(e instanceof Error ? e : new Error(String(e)));
      });
    return () => {
      cancelled = true;
    };
  }, [dek, userId, key, cacheKey, cache, store]);

  const save = useCallback(
    async (data: T) => {
      if (!dek || !userId) {
        throw new Error(
          `${store.name}.use().save(): called while locked (no dek/userId)`,
        );
      }
      const previous = cache.getQueryData<CacheEntry<T>>(cacheKey);
      cache.setQueryData(cacheKey, { data, hash: previous?.hash ?? null });
      try {
        if (store.saveIfMatch) {
          const result = await store.saveIfMatch(
            userId,
            dek,
            key,
            data,
            previous?.hash ?? null,
          );
          if (!result.ok) throw new OptimisticLockConflictError(store.name);
          cache.setQueryData(cacheKey, { data, hash: result.hash });
        } else {
          await store.save(userId, dek, key, data);
          cache.setQueryData(cacheKey, { data, hash: null });
        }
      } catch (e) {
        if (previous !== undefined) cache.setQueryData(cacheKey, previous);
        throw e;
      }
    },
    [dek, userId, key, cacheKey, cache, store],
  );

  return {
    data: cached?.data,
    loading: !!dek && !!userId && cached === undefined && error === null,
    locked: !dek || !userId,
    error,
    save,
  };
}
