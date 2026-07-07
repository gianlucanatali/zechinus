/**
 * React binding for `Aggregation<T>` (`defineAggregation`, `datacloak/core/aggregation.ts`)
 * — paints the last PERSISTED value immediately (`data`), while a stale or never-computed
 * aggregate recomputes in the background (`computing`/`stale`), the exact non-blocking
 * contract `Aggregation.get()` already has.
 *
 * Follows the SAME plain get/subscribe + `useSyncExternalStore` pattern every other binding
 * here uses (`useStore`, `useKeyedStore`, `useCollectionStore`) — this hook reads the
 * aggregation's state through the CacheAdapter, at the key convention
 * `aggregationStateCacheKey` publishes to (`${agg.name}:react:${userId}`), never through a
 * bespoke per-hook subscription of its own. There is no per-hook fetch/compute to dedup:
 * `defineAggregation()` returns ONE singleton instance per aggregation (its own closure IS
 * its state, single-flight-guarded already) — several `useAggregation(sameAgg)` mounts all
 * read/write the SAME CacheAdapter slot and share the SAME underlying compute.
 *
 * This is a READ binding only: an explicit `refresh()` is exposed for retry-after-error,
 * but there is no "write" — the aggregate's own `compute()` is the only thing that ever
 * produces its data.
 *
 * Lock discipline: while locked (no CryptoHandle/userId), this hook never calls
 * `agg.get()`/`agg.refresh()` — same as every other binding here. `configureSecureStore`'s
 * wipe-on-lock already clears the CacheAdapter (hence this hook's cache slot) the instant a
 * lock happens, so a component reading `data` while locked sees `null`, never stale
 * decrypted content. `defineAggregation`'s own `computeAndPersist` re-checks the ambient
 * identity after every await, so an in-flight compute that outlives a lock never persists
 * or re-publishes to this slot either (see that module's own doc comment on the guard).
 */
import { useCallback, useEffect, useSyncExternalStore } from "react";
import { getSecureStoreConfig } from "../core/config.ts";
import {
  aggregationStateCacheKey,
  type Aggregation,
  type AggregationState,
} from "../core/aggregation.ts";

export interface UseAggregationResult<T> {
  /** Last PERSISTED value, or `null` if this aggregate has never been computed yet. */
  data: T | null;
  /** A recompute (initial, source-triggered, or explicit `refresh()`) is in flight. */
  computing: boolean;
  /** The shown `data` no longer matches the sources' current fingerprints (or nothing has
   * been computed yet). */
  stale: boolean;
  /** The error from the most recent failed compute, if any — the previous `data` is still
   * shown alongside it. */
  error: Error | null;
  /** Forces an explicit recompute now (e.g. retry after `error`). Fire-and-forget — the
   * result surfaces through `data`/`error` above, not through this call's return value.
   * Throws synchronously if called while locked (no cryptoHandle/userId), same discipline
   * every other binding's write method uses (see `useStore`'s `save()`). */
  refresh: () => void;
}

export function useAggregation<T>(
  agg: Aggregation<T>,
): UseAggregationResult<T> {
  const { keys, cache } = getSecureStoreConfig();
  if (!keys) {
    throw new Error(
      `${agg.name}.useAggregation(): no KeyProvider configured — pass 'keys' to configureSecureStore()`,
    );
  }
  if (!cache) {
    throw new Error(
      `${agg.name}.useAggregation(): no CacheAdapter configured — pass 'cache' to configureSecureStore()`,
    );
  }

  const cryptoHandle = useSyncExternalStore(
    keys.subscribe,
    keys.getCryptoHandle,
  );
  const userId = useSyncExternalStore(keys.subscribe, keys.getUserId);
  const cacheKey = userId ? aggregationStateCacheKey(agg.name, userId) : null;

  const subscribeToKey = useCallback(
    (cb: () => void) => (cacheKey ? cache.subscribe(cacheKey, cb) : () => {}),
    [cache, cacheKey],
  );
  const cached = useSyncExternalStore(subscribeToKey, () =>
    cacheKey ? cache.get<AggregationState<T>>(cacheKey) : undefined,
  );

  useEffect(() => {
    if (!cryptoHandle || !userId) return;
    let cancelled = false;
    // Mirrors `useStore`'s mount effect (fetch when the cache slot is empty): `agg.get()`
    // itself decides whether anything needs to fetch/recompute (fingerprint-gated) — this
    // effect just guarantees it's asked at least once per mount, per identity.
    agg.get().catch((e: unknown) => {
      if (!cancelled) {
        console.error(`${agg.name}.useAggregation(): get() failed:`, e);
      }
    });
    return () => {
      cancelled = true;
    };
  }, [cryptoHandle, userId, agg]);

  const refresh = useCallback(() => {
    if (!cryptoHandle || !userId) {
      throw new Error(
        `${agg.name}.useAggregation().refresh(): called while locked (no cryptoHandle/userId)`,
      );
    }
    agg.refresh().catch((e: unknown) => {
      // Not swallowed silently: also logged here, on top of surfacing via `error` above
      // (the same `lastError` `defineAggregation` publishes through the state port).
      console.error(`${agg.name}.useAggregation().refresh(): failed:`, e);
    });
  }, [cryptoHandle, userId, agg]);

  const state: AggregationState<T> = cached ?? {
    data: null,
    computing: !!cryptoHandle && !!userId,
    stale: true,
    error: null,
  };

  return {
    data: state.data,
    computing: state.computing,
    stale: state.stale,
    error: state.error,
    refresh,
  };
}
