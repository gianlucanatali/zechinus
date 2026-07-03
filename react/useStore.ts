/**
 * React binding for `perUser` stores — a free function (`useStore(store)`), not a
 * method on the store object, so `core/` stays React-free. Requires `keys` and
 * `cache` in `configureSecureStore` (throws an explicit error otherwise).
 *
 * What it hides from the caller: dek+userId gating, cache read/subscribe, the
 * initial `store.load()` fetch, and optimistic write-through with rollback on
 * `save()` failure. Wipe-on-lock is centralized in `core/config.ts`, not here — one
 * subscription for the whole app, not one per mounted `useStore()` call.
 */
import { useCallback, useEffect, useState, useSyncExternalStore } from "react";
import { getSecureStoreConfig } from "../core/config.ts";
import type { Store } from "../core/store.ts";

export interface UseStoreResult<T> {
  data: T | undefined;
  loading: boolean;
  locked: boolean;
  error: Error | null;
  save: (data: T) => Promise<void>;
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

  const dek = useSyncExternalStore(keys.subscribe, keys.getDek);
  const userId = useSyncExternalStore(keys.subscribe, keys.getUserId);
  const key = `${store.name}:${userId ?? ""}`;

  const subscribeToKey = useCallback(
    (cb: () => void) => cache.subscribe(key, cb),
    [cache, key],
  );
  const cached = useSyncExternalStore(subscribeToKey, () =>
    cache.getQueryData<T>(key),
  );

  const [error, setError] = useState<Error | null>(null);

  useEffect(() => {
    setError(null);
    if (!dek || !userId) return;
    if (cache.getQueryData<T>(key) !== undefined) return;
    let cancelled = false;
    store
      .load(userId, dek)
      .then((data) => {
        if (!cancelled) cache.setQueryData(key, data);
      })
      .catch((e: unknown) => {
        if (!cancelled) setError(e instanceof Error ? e : new Error(String(e)));
      });
    return () => {
      cancelled = true;
    };
  }, [dek, userId, key, cache, store]);

  const save = useCallback(
    async (data: T) => {
      if (!dek || !userId) {
        throw new Error(
          `${store.name}.use().save(): called while locked (no dek/userId)`,
        );
      }
      const previous = cache.getQueryData<T>(key);
      cache.setQueryData(key, data);
      try {
        await store.save(userId, dek, data);
      } catch (e) {
        cache.setQueryData(key, previous as T);
        throw e;
      }
    },
    [dek, userId, key, cache, store],
  );

  return {
    data: cached,
    loading: !!dek && !!userId && cached === undefined && error === null,
    locked: !dek || !userId,
    error,
    save,
  };
}
