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
import {
  useCallback,
  useEffect,
  useRef,
  useState,
  useSyncExternalStore,
} from "react";
import { getSecureStoreConfig } from "../core/config.ts";
import { keyedRangeEpochCacheKey, type KeyedStore } from "../core/store.ts";

interface RangeCacheEntry<T> {
  rows: Array<{ key: string; data: T }>;
  epoch: number;
}

/**
 * In-flight fetch registry, keyed by `rangeCacheKey` — shared across every
 * `useKeyedStoreRange` instance in the app (module-level, not per-hook-call).
 * Without it, two components mounting the SAME range in the same tick (e.g. an
 * account register + a summary panel both querying the same month window) each
 * see an empty cache slot and independently call `store.list()` — a real,
 * observed regression (duplicate network round-trips). Whoever calls first
 * registers the promise; latecomers for the same key await that same promise
 * instead of starting their own fetch.
 */
const inflightRangeFetches = new Map<
  string,
  Promise<Array<{ key: string; data: unknown }>>
>();

function fetchRangeDeduped<T>(
  cacheKey: string,
  fetcher: () => Promise<Array<{ key: string; data: T }>>,
): Promise<Array<{ key: string; data: T }>> {
  const existing = inflightRangeFetches.get(cacheKey);
  if (existing) {
    return existing as Promise<Array<{ key: string; data: T }>>;
  }
  const promise = fetcher().finally(() => {
    inflightRangeFetches.delete(cacheKey);
  });
  inflightRangeFetches.set(
    cacheKey,
    promise as Promise<Array<{ key: string; data: unknown }>>,
  );
  return promise;
}

export interface UseKeyedStoreRangeResult<T> {
  data: Array<{ key: string; data: T }> | undefined;
  loading: boolean;
  /**
   * `true` when `data` is stale placeholder data from a PREVIOUSLY fetched range
   * (e.g. the caller just widened `from`/`to`), served while this exact range is
   * being fetched — mirrors TanStack's `placeholderData: keepPreviousData`. Never
   * true while `locked` (no stale decrypted content survives a lock).
   */
  isPlaceholderData: boolean;
  locked: boolean;
  error: Error | null;
  /**
   * Forces a fresh `list()` fetch, bypassing the cached-epoch skip — resolves once
   * the refreshed rows are in cache. For callers that need a synchronous "the write
   * I just made is now reflected" guarantee beyond the automatic epoch invalidation
   * (e.g. before reading `data` again in the same function).
   */
  reload: () => Promise<void>;
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
  const locked = !cryptoHandle || !userId;

  const previousRef = useRef<Array<{ key: string; data: T }> | null>(null);
  useEffect(() => {
    if (locked) {
      previousRef.current = null;
    } else if (cached !== undefined) {
      previousRef.current = cached.rows;
    }
  }, [locked, cached]);

  const isPlaceholderData =
    !locked && cached === undefined && previousRef.current !== null;
  const data = locked
    ? undefined
    : (cached?.rows ?? (isPlaceholderData ? previousRef.current! : undefined));

  useEffect(() => {
    setError(null);
    if (!cryptoHandle || !userId) return;
    const existing = cache.get<RangeCacheEntry<T>>(rangeCacheKey);
    if (existing !== undefined && existing.epoch === epoch) return;
    let cancelled = false;
    fetchRangeDeduped(rangeCacheKey, () =>
      store.list(userId, cryptoHandle, range),
    )
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

  const reload = useCallback(async () => {
    if (!cryptoHandle || !userId) return;
    const rows = await store.list(userId, cryptoHandle, range);
    // Re-check identity AFTER the await: if a lock (or a switch to a different
    // user) happened while this fetch was in flight, never let decrypted
    // content from a superseded session repopulate the cache.
    if (keys.getCryptoHandle() === null || keys.getUserId() !== userId) return;
    cache.set(rangeCacheKey, {
      rows,
      epoch: cache.get<number>(epochKey) ?? 0,
    });
  }, [
    cryptoHandle,
    userId,
    store,
    range.from,
    range.to,
    cache,
    rangeCacheKey,
    epochKey,
    keys,
  ]);

  return {
    data,
    loading: !!cryptoHandle && !!userId && data === undefined && error === null,
    isPlaceholderData,
    locked,
    error,
    reload,
  };
}
