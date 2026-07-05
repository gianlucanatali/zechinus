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
    const fetch = store.loadWithHash
      ? store.loadWithHash(userId, cryptoHandle)
      : store.load(userId, cryptoHandle).then((data) => ({ data, hash: null }));
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

  return {
    data: cached?.data,
    loading:
      !!cryptoHandle && !!userId && cached === undefined && error === null,
    locked: !cryptoHandle || !userId,
    error,
    save,
  };
}
