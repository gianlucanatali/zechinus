/**
 * `CacheAdapter` backed by a real TanStack Query `QueryClient` — the reference
 * implementation for `useStore` (React binding). DataCloak owns key construction
 * (plain strings, `<storeName>:<userId>`); this adapter maps each to a single-element
 * TanStack query key (`[key]`) and subscribes via `QueryCache` events rather than
 * the `useQuery` hook, since the port itself must stay hook-free (see `core/types.ts`).
 */
import type { QueryClient } from "@tanstack/react-query";
import type { CacheAdapter } from "../core/types.ts";

export function tanstackAdapter(queryClient: QueryClient): CacheAdapter {
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
