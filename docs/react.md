# React binding — one hook per cardinality

Read this to wire Zechinus stores and aggregations into React: `useStore`,
`useKeyedStore`, `useKeyedStoreRange`, `useCollectionStore`, `useAggregation`, the
`KeyProvider`/`CacheAdapter` wiring, and the caching/dedup behavior underneath them. Back
to [README.md](../README.md).

```tsx
import {
  useStore,
  useKeyedStore,
  useKeyedStoreRange,
  useCollectionStore,
} from "zechinus/react";

function PortfolioPanel() {
  const { data, loading, locked, error, save } = useStore(portfolioStore); // perUser

  if (locked) return <UnlockScreen />;
  if (loading) return <Spinner />;
  return <PortfolioView data={data} onSave={save} />;
}

function TransactionsForMonth({ month }: { month: string }) {
  const { data, save } = useKeyedStore(transactionStore, month); // perKey
  // ...
}

function TransactionsForYear() {
  const { data, loading } = useKeyedStoreRange(transactionStore, {
    from: "2026-01",
    to: "2026-12",
  }); // perKey range — read-only, no save() (write a single key via useKeyedStore/mutate)
  // data: Array<{ key: string; data: T }> | undefined
}

function RebalanceSimulations() {
  const { items, create, update, remove } = useCollectionStore(simulationStore); // many
  // ...
}
```

All three hide the same things from the caller: cryptoHandle+userId gating (`locked`), the initial
fetch, cache read/subscribe, and optimistic write-through with automatic rollback if the
underlying persist fails (`useCollectionStore` rolls back the whole list on `update`/
`remove` failure — read-modify-write, not per-field patching). Wipe-on-lock is centralized
once in `configureSecureStore` (not per hook call) — see `core/config.ts`.

**If the store has `optimisticLock: true`, the hash is threaded automatically — no
`expectedHash`/`saveIfMatch` in sight.** Each hook's cache slot holds `{data, hash}`
internally (`useCollectionStore`'s `items` exposes `hash` per row, since a consumer may
want it for a "someone else edited this" hint); `save`/`update` use `saveIfMatch`/
`updateIfMatch` transparently when available, reading the hash from the cache and writing
the new one back on success — the same `save(data)`/`update(id, data)` call site works
whether or not the store has the lock configured (see
[docs/content-hash-and-locking.md](content-hash-and-locking.md)). On conflict, the hook
rolls back the optimistic update and throws `OptimisticLockConflictError` (from
`zechinus/react`) — catch it separately from a generic save failure to show "someone else
edited this, reload" instead of a generic error:

```tsx
try {
  await save(newData);
} catch (e) {
  if (e instanceof OptimisticLockConflictError) {
    // reload and let the user re-apply their change, don't just retry blindly
  } else {
    // generic save failure (network, validation, ...)
  }
}
```

Requires `keys` (a `KeyProvider`) and `cache` (a `CacheAdapter`) in
`configureSecureStore`:

```ts
import { tanstackAdapter } from "zechinus/react";

configureSecureStore({
  storage: supabaseStorageAdapter(getSupabaseClient),
  cache: tanstackAdapter(queryClient),     // requires queryClient's defaultOptions.queries.gcTime: Infinity — see below
  keys: {                                  // KeyProvider: plain subscribable snapshot,
    getCryptoHandle: () => /* your app's current key handle | null — only needs to satisfy CryptoHandle: { pid, encryptJson, decryptJson } */,
    getUserId: () => /* your app's current userId | null */,
    subscribe: (cb) => /* subscribe to changes, return an unsubscribe fn */,
  },
});
```

`KeyProvider` is deliberately **not** hook-shaped (no `useCryptoHandle()`) — a plain
get/subscribe snapshot, read via `useSyncExternalStore` inside each hook, so the port
itself isn't subject to the Rules of Hooks. Since your app's crypto handle/userId almost
always live inside a React context (not a plain external store), bridge them with a small
invisible component that calls your context's hooks and forwards their values into a
module-level `KeyProvider` — see the host app's own
`src/lib/zechinusKeyProvider.ts` + `src/components/ZechinusKeyBridge.tsx` for a
concrete, working reference (bridges `PasskeyContext`/`UserContext`).

**`tanstackAdapter`'s `queryClient` must set `defaultOptions.queries.gcTime: Infinity`
— the adapter throws immediately at construction if it doesn't.** This adapter writes
via `setQueryData`/`getQueryData` and never mounts a real `useQuery` observer, so every
entry it creates has zero observers for its whole life; TanStack schedules that entry's
garbage collection unconditionally at creation time (a separate axis from `staleTime`)
and evicts it once `gcTime` elapses, no matter how many times it was refreshed in
between. With the default 5-minute `gcTime`, cached decrypted data would silently
disappear from every Zechinus-backed hook after that long of the app sitting idle —
with no error, since the `CacheAdapter` contract has no "refetch" concept for a caller to
notice or recover from. `staleTime: Infinity` alone does **not** cover this — it only
stops automatic refetch, not garbage collection. Bounded lifetime still comes from your
app calling `queryClient.clear()` on logout/lock, same as today. See
[docs/adapters.md](adapters.md) for the enforcement mechanism and what to apply if you
write your own `CacheAdapter`.

**Ambient writes (`store.set()`/`store.mutate()`, called directly from a service —
not through a hook's `save()`) are cache-aware too:** after a successful persist,
`set()`/`mutate()` (perUser and perKey) push the fresh `{data, hash}` into the
configured `CacheAdapter` themselves, under the exact same key `useStore`/
`useKeyedStore` read from. A service calling `.mutate()` directly (e.g.
`patchPortfolioTransaction`) now keeps every mounted hook for that store in sync,
same as if the write had gone through the hook's own `save()`.

**Deliberate exclusion: `CollectionStore.add()`/`.update()`/`.discard()` (`many`
cardinality) do NOT write through to the cache.** Only `perUser`/`perKey`
ambient writes (`set()`/`mutate()` above) do. Safe today because the only
consumer is `useCollectionStore` itself, which already applies its own
optimistic write-through before calling `add()`/`update()` — but the first
service that calls `add()`/`update()`/`discard()` ambiently (bypassing the
hook, the same way `patchPortfolioTransaction` calls `.mutate()` directly)
will silently desync every other mounted `useCollectionStore` for that store
until a manual refetch. If you add such a caller, either write through the
cache the same way `perUser`/`perKey` do, or document why not — `discard()`'s
first consumer (an account-deletion cleanup service) documents why not: the
rows it removes belong to an entity no UI can select anymore, so there is
nothing left to desync.

**In-flight fetch deduplication:** all three React bindings (`useStore`,
`useKeyedStore`, `useKeyedStoreRange`) keep a module-level `Map<key, Promise>`
registry — when two components mount at once and both need the SAME cache slot
(same store, same user, same key/range), only the FIRST one actually calls
`store.load*()`; the second awaits that same in-flight promise instead of
firing its own fetch. Without this, two globally-mounted components reading
the same `perUser`/`perKey` slot (e.g. a copilot widget and an import provider
both reading the `budget_categories` label dict on every page) each see an
empty cache and independently hit the network — a real regression, found via
HAR analysis of a full-app tour (see `docs/PERFORMANCE_HAR_ANALYSIS.md` in the
main repo) and fixed the same night `useKeyedStoreRange`'s own range-level
dedup (`inflightRangeFetches`) was already covering the range case. Tests:
"dedupes concurrent fetches across independent hook instances" in
`useStore.test.tsx`/`useKeyedStore.test.tsx`/`useKeyedStoreRange.test.tsx`.

**`useKeyedStoreRange(store, {from, to})`** is the range counterpart of
`useKeyedStore` — read-only (no `save`), for showing several keys at once (e.g. a
year of monthly batches). A `CacheAdapter` has no notion of "subscribe to every key
in `[from, to]`", so the range result is cached as one slot, invalidated via a
per-`(store, user)` write counter that `set()`/`mutate()` bump on every keyed write
(regardless of which key changed) — simple and always correct, at the cost of an
occasional refetch for a write outside the mounted range. `list`/`getRange` need
`listByKeyRange` on the adapter, same requirement as `KeyedStore.list()`.

Verified, runnable usage (including optimistic-rollback and lock-clears-cache behavior)
lives in `zechinus/tests/useStore.test.tsx`, `useKeyedStore.test.tsx`,
`useKeyedStoreRange.test.tsx`, `useCollectionStore.test.tsx`,
`cacheAwareWrites.test.ts` — read them before writing a `KeyProvider` for a new
consumer.

**If a component only needs a boolean lock/unlock gate — never the data or the
`save()` — use `useIsUnlocked()` instead of one of the three hooks above.** It only
needs `keys` (no `cache`), and never exposes the `CryptoHandle` to the caller. See
`zechinus/tests/useIsUnlocked.test.tsx`.

<a id="useaggregation-binding"></a>

## `useAggregation` binding

Same plain get/subscribe + `useSyncExternalStore` pattern as `useStore`/`useKeyedStore`,
reading through the CacheAdapter slot `defineAggregation` publishes to
(`aggregationStateCacheKey`) — never a bespoke subscription of its own. Real usage,
`src/hooks/usePortfolioHistory.ts`:

```tsx
import { useAggregation } from "zechinus/react";

export function usePortfolioHistory({ range, portfolioId, enabled }) {
  const { data, computing, error, refresh } =
    useAggregation(portfolioSeriesAgg);
  // data: T | null · computing: boolean · stale: boolean · error: Error | null
  // refresh(opts?): forces a recompute now — see bypassExternalsTtl below
  const forceRefresh = () => refresh({ bypassExternalsTtl: true });
  // ...
}
```

`{ data, computing, stale, error, refresh }` — `data` is the last PERSISTED value (`null`
if never computed), painted immediately; `computing`/`stale` reflect a background
recompute in flight, the same non-blocking contract `Aggregation.get()` has. This is a
READ binding only — an aggregate's `compute()` is the only thing that ever produces its
data, `refresh()` exists for an explicit retry/force, not a write path. See
[docs/aggregations.md](aggregations.md) for what `defineAggregation` itself does.

**`refresh({ bypassExternalsTtl: true })`** clears the aggregation's in-memory external
cache before recomputing, forcing a real refetch even within the external's own `ttlMs` —
distinct from a plain `refresh()`, which still respects each external's TTL (it forces the
recompute, not a refetch of data that's still fresh by the external's own clock). The one
real consumer, `usePortfolioHistory` above: the price-history worker just wrote new market
data, and the caller — not the TTL clock — knows it's time to see it now. A plain
`refresh()` there would still serve the 15-minute-old cached `marketData` external,
showing stale prices right after an explicit "refresh". One-shot: only that ONE recompute's
external fetches are forced; the refreshed value re-enters the normal TTL-gated cache
afterward.
