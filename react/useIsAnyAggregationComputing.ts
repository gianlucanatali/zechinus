/**
 * React binding for `isAnyAggregationComputing()`/`subscribeGlobalAggregationActivity()`
 * (`core/aggregation.ts`) — the cross-aggregation "is anything computing right now"
 * signal, narrowed to a boolean the same way `useIsUnlocked` narrows lock state. Intended
 * for a host app to render ONCE (e.g. a hidden DOM node) so an E2E test can wait for
 * "everything settled" after a write, without knowing which aggregations exist.
 */
import { useSyncExternalStore } from "react";
import {
  isAnyAggregationComputing,
  subscribeGlobalAggregationActivity,
} from "../core/aggregation.ts";

export function useIsAnyAggregationComputing(): boolean {
  return useSyncExternalStore(
    subscribeGlobalAggregationActivity,
    isAnyAggregationComputing,
  );
}
