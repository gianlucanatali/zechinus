/**
 * React binding for `many` (`CollectionStore`) — same gating/cache/optimistic-write
 * pattern as `useStore`/`useKeyedStore`, but the cache slot holds the WHOLE list
 * (`Array<{ id, data, hash }>`), since `many` has no single "current value" —
 * `create`/`update`/`remove` each read-modify-write that array optimistically.
 *
 * `update()` transparently uses `updateIfMatch` when the store has
 * `optimisticLock: true`, threading each row's own hash from the cached list — a
 * conflict throws `OptimisticLockConflictError`. `create`/`remove` don't need it:
 * there's no prior state to protect (a new id can't conflict; delete is idempotent
 * at the framework level, "already gone" isn't a data-loss risk the way a silently
 * overwritten edit is).
 */
import { useCallback, useEffect, useState, useSyncExternalStore } from "react";
import { getSecureStoreConfig } from "../core/config.ts";
import type { CollectionStore } from "../core/store.ts";
import { OptimisticLockConflictError } from "./errors.ts";

export interface UseCollectionStoreResult<T> {
  items: Array<{ id: string; data: T; hash: string | null }>;
  loading: boolean;
  locked: boolean;
  error: Error | null;
  create: (data: T) => Promise<string>;
  update: (id: string, data: T) => Promise<void>;
  remove: (id: string) => Promise<void>;
}

export function useCollectionStore<T>(
  store: CollectionStore<T>,
): UseCollectionStoreResult<T> {
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

  type Items = Array<{ id: string; data: T; hash: string | null }>;

  const dek = useSyncExternalStore(keys.subscribe, keys.getDek);
  const userId = useSyncExternalStore(keys.subscribe, keys.getUserId);
  const cacheKey = `${store.name}:${userId ?? ""}`;

  const subscribeToKey = useCallback(
    (cb: () => void) => cache.subscribe(cacheKey, cb),
    [cache, cacheKey],
  );
  const cached = useSyncExternalStore(subscribeToKey, () =>
    cache.get<Items>(cacheKey),
  );

  const [error, setError] = useState<Error | null>(null);

  useEffect(() => {
    setError(null);
    if (!dek || !userId) return;
    if (cache.get<Items>(cacheKey) !== undefined) return;
    let cancelled = false;
    store
      .list(userId, dek)
      .then((items) => {
        if (!cancelled) cache.set(cacheKey, items);
      })
      .catch((e: unknown) => {
        if (!cancelled) setError(e instanceof Error ? e : new Error(String(e)));
      });
    return () => {
      cancelled = true;
    };
  }, [dek, userId, cacheKey, cache, store]);

  const requireUnlocked = useCallback(
    (op: string) => {
      if (!dek || !userId) {
        throw new Error(
          `${store.name}.use().${op}(): called while locked (no dek/userId)`,
        );
      }
      return { dek, userId };
    },
    [dek, userId, store.name],
  );

  const create = useCallback(
    async (data: T): Promise<string> => {
      const { dek, userId } = requireUnlocked("create");
      const previous = cache.get<Items>(cacheKey) ?? [];
      try {
        const id = await store.create(userId, dek, data);
        cache.set(cacheKey, [...previous, { id, data, hash: null }]);
        return id;
      } catch (e) {
        cache.set(cacheKey, previous);
        throw e;
      }
    },
    [requireUnlocked, cache, cacheKey, store],
  );

  const update = useCallback(
    async (id: string, data: T): Promise<void> => {
      const { dek, userId } = requireUnlocked("update");
      const previous = cache.get<Items>(cacheKey) ?? [];
      const currentHash = previous.find((item) => item.id === id)?.hash ?? null;
      cache.set(
        cacheKey,
        previous.map((item) =>
          item.id === id ? { id, data, hash: currentHash } : item,
        ),
      );
      try {
        if (store.updateIfMatch) {
          const result = await store.updateIfMatch(
            userId,
            dek,
            id,
            data,
            currentHash,
          );
          if (!result.ok) throw new OptimisticLockConflictError(store.name);
          cache.set(
            cacheKey,
            previous.map((item) =>
              item.id === id ? { id, data, hash: result.hash } : item,
            ),
          );
        } else {
          await store.update(userId, dek, id, data);
          cache.set(
            cacheKey,
            previous.map((item) =>
              item.id === id ? { id, data, hash: null } : item,
            ),
          );
        }
      } catch (e) {
        cache.set(cacheKey, previous);
        throw e;
      }
    },
    [requireUnlocked, cache, cacheKey, store],
  );

  const remove = useCallback(
    async (id: string): Promise<void> => {
      const { dek, userId } = requireUnlocked("remove");
      const previous = cache.get<Items>(cacheKey) ?? [];
      cache.set(
        cacheKey,
        previous.filter((item) => item.id !== id),
      );
      try {
        await store.remove(userId, dek, id);
      } catch (e) {
        cache.set(cacheKey, previous);
        throw e;
      }
    },
    [requireUnlocked, cache, cacheKey, store],
  );

  return {
    items: cached ?? [],
    loading: !!dek && !!userId && cached === undefined && error === null,
    locked: !dek || !userId,
    error,
    create,
    update,
    remove,
  };
}
