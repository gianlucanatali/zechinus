/**
 * Cross-store "is anything loading right now" signal, shared by `useKeyedStore`
 * (single-key fetches) AND `useKeyedStoreRange` (range fetches) — both are the
 * same family of concern ("a `perKey` store's data isn't in cache yet, fetch
 * it"), just addressed differently (one key vs a `[from,to]` window). A single
 * counter covering both means a caller waiting for "every keyed-store-family
 * fetch triggered so far has settled" doesn't need to know which variant a
 * given component happens to use.
 *
 * Mirrors `isAnyAggregationComputing()`/`subscribeGlobalAggregationActivity()`
 * (`core/aggregation.ts`): a plain module-level counter + callback set, no
 * React dependency here so either hook file can call into it directly.
 */
let inFlightCount = 0;
const listeners = new Set<() => void>();

function notify(): void {
  for (const cb of listeners) cb();
}

/** Call when a fetch (key or range) starts. Pair with exactly one `markKeyedFetchEnd()`. */
export function markKeyedFetchStart(): void {
  const wasIdle = inFlightCount === 0;
  inFlightCount++;
  if (wasIdle) notify();
}

/** Call when that same fetch settles (success or failure). */
export function markKeyedFetchEnd(): void {
  inFlightCount--;
  notify();
}

/** True if at least one `useKeyedStore`/`useKeyedStoreRange` fetch, anywhere in the app, is in flight. */
export function isAnyKeyedStoreLoading(): boolean {
  return inFlightCount > 0;
}

/** Subscribes to every transition of `isAnyKeyedStoreLoading()`'s value. Returns an
 * unsubscribe function — same contract as `subscribeGlobalAggregationActivity`. */
export function subscribeGlobalKeyedStoreActivity(cb: () => void): () => void {
  listeners.add(cb);
  return () => listeners.delete(cb);
}

/** Test-only reset — mirrors `__resetGlobalAggregationActivity`'s naming/purpose. */
export function __resetGlobalKeyedStoreActivity(): void {
  inFlightCount = 0;
  listeners.clear();
}
