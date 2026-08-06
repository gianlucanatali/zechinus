/**
 * `CacheAdapter` backed by a real TanStack Query `QueryClient` — the reference
 * implementation for `useStore` (React binding). Zechinus owns key construction
 * (plain strings, `<storeName>:<userId>`); this adapter maps each to a single-element
 * TanStack query key (`[key]`) and subscribes via `QueryCache` events rather than
 * the `useQuery` hook, since the port itself must stay hook-free (see `core/types.ts`).
 *
 * Because nothing here ever mounts a real `useQuery` observer, every `Query` this
 * adapter creates has zero observers for its entire life. TanStack schedules that
 * Query's garbage collection unconditionally at creation time (a separate axis from
 * `staleTime`) and evicts it once `gcTime` elapses — regardless of how many times it
 * was written to in the meantime. A finite `gcTime` silently loses cached (decrypted)
 * data after that many minutes of the consuming app sitting idle, with no error: the
 * `CacheAdapter` contract has no "refetch" concept, so callers have no way to notice
 * or recover. The constructor guard below turns that into a loud failure at wiring
 * time instead of a real user's idle session — see `tests/tanstackAdapter.test.ts`.
 */
import type { QueryClient } from "@tanstack/react-query";
import type { CacheAdapter } from "../../core/types.ts";

export function tanstackAdapter(queryClient: QueryClient): CacheAdapter {
  const gcTime = queryClient.getDefaultOptions().queries?.gcTime;
  if (gcTime !== Infinity) {
    throw new Error(
      `tanstackAdapter(): queryClient must be configured with ` +
        `defaultOptions.queries.gcTime: Infinity (got ${String(gcTime)}). ` +
        `Without it, TanStack garbage-collects every entry this adapter writes ` +
        `after the default 5 minutes, since it never has a real useQuery observer ` +
        `keeping it alive — data silently disappears from any Zechinus-backed hook ` +
        `(useStore/useKeyedStore/useAggregation/...) after that long, with no error.`,
    );
  }

  return {
    get<T>(key: string): T | undefined {
      return queryClient.getQueryData<T>([key]);
    },
    set<T>(key: string, data: T): void {
      queryClient.setQueryData<T>([key], data);
    },
    subscribe(key: string, callback: () => void): () => void {
      return queryClient.getQueryCache().subscribe((event) => {
        // A brand-new key fires both 'added' (query created) and 'updated' (data set)
        // for the same set() call — filter to 'updated' so the callback fires
        // once per logical write, not twice on first write.
        if (event.type !== "updated") return;
        const queryKey = event.query.queryKey;
        if (queryKey.length === 1 && queryKey[0] === key) callback();
      });
    },
    clear(): void {
      queryClient.clear();
    },
  };
}
