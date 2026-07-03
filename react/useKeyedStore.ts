/**
 * React binding for `perKey` stores — mirrors `useStore` exactly, plus the domain
 * key as an explicit argument (each key is an independent cache slot, e.g. one
 * `useKeyedStore(store, "2026-06")` per month rendered).
 */
import { useCallback, useEffect, useState, useSyncExternalStore } from "react";
import { getSecureStoreConfig } from "../core/config.ts";
import type { KeyedStore } from "../core/store.ts";

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
    cache.getQueryData<T>(cacheKey),
  );

  const [error, setError] = useState<Error | null>(null);

  useEffect(() => {
    setError(null);
    if (!dek || !userId) return;
    if (cache.getQueryData<T>(cacheKey) !== undefined) return;
    let cancelled = false;
    store
      .load(userId, dek, key)
      .then((data) => {
        if (!cancelled) cache.setQueryData(cacheKey, data);
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
      const previous = cache.getQueryData<T>(cacheKey);
      cache.setQueryData(cacheKey, data);
      try {
        await store.save(userId, dek, key, data);
      } catch (e) {
        cache.setQueryData(cacheKey, previous as T);
        throw e;
      }
    },
    [dek, userId, key, cacheKey, cache, store],
  );

  return {
    data: cached,
    loading: !!dek && !!userId && cached === undefined && error === null,
    locked: !dek || !userId,
    error,
    save,
  };
}
