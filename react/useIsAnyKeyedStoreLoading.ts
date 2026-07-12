/**
 * React binding for `isAnyKeyedStoreLoading()`/`subscribeGlobalKeyedStoreActivity()`
 * (`useKeyedStore.ts`) — the cross-store "is any keyed-store fetch in flight right now"
 * signal, narrowed to a boolean the same way `useIsAnyAggregationComputing` narrows
 * aggregation activity. Intended for a host app to render ONCE (e.g. a hidden DOM node)
 * so an E2E test can wait for "every keyed-store fetch has settled" — typically right
 * after a DEK unlock — without knowing which stores/keys are mounted.
 */
import { useSyncExternalStore } from "react";
import {
  isAnyKeyedStoreLoading,
  subscribeGlobalKeyedStoreActivity,
} from "./useKeyedStore.ts";

export function useIsAnyKeyedStoreLoading(): boolean {
  return useSyncExternalStore(
    subscribeGlobalKeyedStoreActivity,
    isAnyKeyedStoreLoading,
  );
}
