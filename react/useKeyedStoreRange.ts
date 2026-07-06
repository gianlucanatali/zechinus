/**
 * React binding for a `perKey` store's RANGE query (`store.getRange()`/`list()`) —
 * e.g. all months in `[from, to]`. Unlike `useKeyedStore` (one independent cache slot
 * per key), a range has no single key to subscribe to on the `CacheAdapter`, and a
 * write to ANY key inside `[from, to]` (via `buildKeyedStore`'s ambient `set()`/
 * `mutate()`) must still invalidate it. The simplest correct signal for that is the
 * per-`(store,user)` write counter `buildKeyedStore` bumps on every keyed write —
 * see `keyedRangeEpochCacheKey` in `core/store.ts`. The combined range result is
 * cached under one slot, tagged with the epoch it was fetched at; a mount whose
 * cached epoch already matches the current one skips the re-fetch.
 */
import { useCallback, useEffect, useState, useSyncExternalStore } from "react";
import { getSecureStoreConfig } from "../core/config.ts";
import { keyedRangeEpochCacheKey, type KeyedStore } from "../core/store.ts";

interface RangeCacheEntry<T> {
  rows: Array<{ key: string; data: T }>;
  epoch: number;
}

export interface UseKeyedStoreRangeResult<T> {
  data: Array<{ key: string; data: T }> | undefined;
  loading: boolean;
  locked: boolean;
  error: Error | null;
}

export function useKeyedStoreRange<T>(
  store: KeyedStore<T>,
  range: { from: string; to: string },
): UseKeyedStoreRangeResult<T> {
  const { keys, cache } = getSecureStoreConfig();
  if (!keys) {
    throw new Error(
      `${store.name}.useRange(): no KeyProvider configured — pass 'keys' to configureSecureStore()`,
    );
  }
  if (!cache) {
    throw new Error(
      `${store.name}.useRange(): no CacheAdapter configured — pass 'cache' to configureSecureStore()`,
    );
  }

  const cryptoHandle = useSyncExternalStore(
    keys.subscribe,
    keys.getCryptoHandle,
  );
  const userId = useSyncExternalStore(keys.subscribe, keys.getUserId);
  const rangeCacheKey = `${store.name}:${userId ?? ""}:range:${range.from}:${range.to}`;
  const epochKey = keyedRangeEpochCacheKey(store.name, userId ?? "");

  const subscribeToRange = useCallback(
    (onStoreChange: () => void) => {
      const unsubRange = cache.subscribe(rangeCacheKey, onStoreChange);
      const unsubEpoch = cache.subscribe(epochKey, onStoreChange);
      return () => {
        unsubRange();
        unsubEpoch();
      };
    },
    [cache, rangeCacheKey, epochKey],
  );

  const epoch = useSyncExternalStore(
    subscribeToRange,
    () => cache.get<number>(epochKey) ?? 0,
  );
  const cached = useSyncExternalStore(subscribeToRange, () =>
    cache.get<RangeCacheEntry<T>>(rangeCacheKey),
  );

  const [error, setError] = useState<Error | null>(null);

  useEffect(() => {
    setError(null);
    if (!cryptoHandle || !userId) return;
    const existing = cache.get<RangeCacheEntry<T>>(rangeCacheKey);
    if (existing !== undefined && existing.epoch === epoch) return;
    let cancelled = false;
    store
      .list(userId, cryptoHandle, range)
      .then((rows) => {
        if (!cancelled) cache.set(rangeCacheKey, { rows, epoch });
      })
      .catch((e: unknown) => {
        if (!cancelled) setError(e instanceof Error ? e : new Error(String(e)));
      });
    return () => {
      cancelled = true;
    };
  }, [
    cryptoHandle,
    userId,
    rangeCacheKey,
    cache,
    store,
    range.from,
    range.to,
    epoch,
  ]);

  return {
    data: cached?.rows,
    loading:
      !!cryptoHandle && !!userId && cached === undefined && error === null,
    locked: !cryptoHandle || !userId,
    error,
  };
}
