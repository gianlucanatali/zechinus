# Aggregations: building a read model from several stores

Read this to build a persisted, declarative read-model derived from one or more stores —
`defineAggregation`, sources (stores, keyed stores, other aggregates), the declarative
operator kit, cross-aggregation activity signals, external-data invalidation, and when
NOT to reach for this. For the React hook, see [docs/react.md](react.md#useaggregation-binding).
Back to [README.md](../README.md).

**A `defineAggregation` is a persisted, declarative read-model derived from one or more
stores — never a value the app computes and writes itself.** Where `defineStore` owns a
row the app writes directly, `defineAggregation` owns a row the FRAMEWORK writes, by
calling the app's `compute()` whenever a source changes or an external's TTL expires. The
persisted result goes through the exact same encrypted envelope/AAD/versioning machinery
`defineStore` already provides (an aggregation is, internally, one `defineStore` the
framework builds and drives) — this section documents the layer on top: source
fingerprinting, debounced recompute, and the extra wire-format guarantees the persisted
envelope makes (see [docs/wire-format.md#aggregation-envelope-wire-format](wire-format.md#aggregation-envelope-wire-format)).

## `defineAggregation` — perUser only

Real read-model from this branch, trimmed for length (`src/services/dashboardAggregation.ts`):

```ts
import { defineAggregation, keyedSource } from "zechinus";

export const dashboardAgg = defineAggregation({
  version: 1,
  schema: DashboardSummarySchema,
  schemaFingerprint: "62df50f2",
  // Same physical row `dashboardSummaryStore` used before this branch (zero migration).
  // `keyColumn: "year_month"` because `account_snapshot_blobs`'s sentinel column is
  // called that, not "key" — see "storage.keyColumn" below.
  storage: {
    table: "account_snapshot_blobs",
    key: "__dashboard__",
    keyColumn: "year_month",
  },
  sources: {
    assets: assetStore,
    accountMeta: keyedSource(accountMetaStore, ACCOUNT_META_KEY),
    snapshots: keyedSource(snapshotStore, STORE_KEY),
    portfolioSeries: portfolioSeriesAgg, // an Aggregation used as a Source — see below
    netWorthSeries: netWorthSeriesAgg, //   same
  },
  externals: {
    currentPortfolio: {
      load: loadCurrentPortfolioMetrics,
      ttlMs: 5 * 60 * 1000,
    },
    existingAccountIds: { load: loadExistingAccountIds, ttlMs: 5 * 60 * 1000 },
  },
  compute: computeDashboardSummary, // a plain function here — see "declarative operator kit" below for the other form
});
```

`version`/`schema`/`schemaFingerprint` follow the exact same discipline as `defineStore`
(a mismatch between `schema` and `schemaFingerprint` throws at definition time — see
[docs/guardrails.md](guardrails.md) § "Guardrail: versioning is mandatory"). The
difference: an aggregation never needs a `BlobMigrator` — a shape or `version` change just
means "recompute from sources", there is no old ciphertext to migrate in place, since
nothing but the framework ever wrote that row.

`storage.table` is a `defineStore` `name` (a real backing table); `storage.key` is the
sentinel row identifier within it. Several aggregations commonly share ONE physical table
via distinct `key` values (`dashboardAgg`/`netWorthSeriesAgg` above both live in
`account_snapshot_blobs`, alongside the real per-month snapshot rows) — the same "generic
domain key column" convention `snapshotStore` itself already uses.

**`storage.keyColumn`** (optional, defaults to `"key"`): the DB column name backing that
sentinel key. Set it when wiring an aggregation onto a PRE-EXISTING table whose sentinel
column has a different name — `account_snapshot_blobs.year_month` above, not `key` — so
reusing an already-shipped table costs zero DB migration. Omit it for a table that only
ever exists for aggregations (this module's own convention, `"key"`).

## Sources: stores, keyed stores, and other aggregates

A `sources` entry can be any of three things (`Source` in `core/aggregation.ts`):

- **A `perUser` `Store`** — passed directly, e.g. `assets: assetStore` above.
- **`keyedSource(store, key)`** — wraps a `perKey` `KeyedStore` read through ONE fixed
  key, for the two real cases in this branch where a `perKey` store is always read
  through a single sentinel key per user, never a real range: `snapshotStore` and
  `accountMetaStore` (`accountMeta: keyedSource(accountMetaStore, ACCOUNT_META_KEY)`,
  `snapshots: keyedSource(snapshotStore, STORE_KEY)` above). A `KeyedStore` can't be
  passed as a `Source` directly — `perKey` reads/writes always need a key, there's no
  key-less signature to fall back to the way a `perUser` `Store` has one. Deliberately
  fixed-key-only: reading a range or the whole collection of a `KeyedStore` as a single
  aggregation input isn't supported (no real caller needs it).
- **Another `Aggregation`** — "aggregate-as-source", below.

**Aggregate-as-source.** A `sources` entry can itself be an `Aggregation` — a downstream
aggregate reads the upstream one's PERSISTED value via its own `.get()`, never
duplicating its `compute`/`externals` logic. Real example, `src/services/netWorthSeriesAggregation.ts`:

```ts
export const netWorthSeriesAgg = defineAggregation({
  version: 1,
  schema: NetWorthSeriesSchema,
  schemaFingerprint: "2d5aa43a",
  storage: {
    table: "account_snapshot_blobs",
    key: "__net_worth_series__",
    keyColumn: "year_month",
  },
  sources: {
    assets: assetStore,
    accountMeta: keyedSource(accountMetaStore, ACCOUNT_META_KEY),
    snapshots: keyedSource(snapshotStore, STORE_KEY),
    portfolioSeries: portfolioSeriesAgg, // aggregate-as-source
  },
  compute: ({ sources }) => {
    const portfolioHistory =
      sources.portfolioSeries.byPortfolio[ALL_PORTFOLIOS_KEY]?.Max ?? [];
    return buildRetroactiveHistoryClient(/* ... */ portfolioHistory /* ... */);
  },
});
```

The product motivation is avoiding a double fetch: `portfolioSeriesAgg` (Task 5, point A)
computes an expensive time series against live market data behind an `ExternalInput`
TTL. Without aggregate-as-source, both `netWorthSeriesAgg` and `dashboardAgg` (which ALSO
lists `portfolioSeries: portfolioSeriesAgg` in its own `sources`, above) would each need
their own copy of that fetch/compute logic — instead both read the SAME persisted series,
computed once. A change in `portfolioSeriesAgg` still propagates: its own fingerprint
(see [docs/wire-format.md#aggregation-envelope-wire-format](wire-format.md#aggregation-envelope-wire-format))
flows into every aggregation that sources it, marking them stale through the exact same
`ensureSubscribed`/`isFresh` machinery a `Store` source already uses — no special-casing
needed for the aggregate-as-source case.

**Gotcha: a cold aggregate-as-source throws, then self-heals — it never blocks or waits.**
An aggregation never waits on another aggregation's very first compute — if the upstream
source (e.g. `portfolioSeriesAgg` above) has never itself persisted a value in this
session, `computeAndPersist` throws immediately (`"source aggregation ... has no
persisted value yet"`). Reading that source (`source.get()`) is what kicks off the
upstream's OWN background compute as a side effect, though — so once it finishes and
publishes, the downstream aggregation (already `ensureSubscribed` to it like any other
source) reacts exactly like it would to any other source write, and recomputes
successfully. In practice this means: the FIRST page load of a session that reads a
multi-level aggregation DAG (e.g. a dashboard sourcing three other lazy aggregates) can
throw once and settle a moment later — usually well under a second, but a UI that only
destructures `data` from `useAggregation` and ignores `computing`/`error` will show its
"nothing here yet" empty state during that window even when real data exists and just
hasn't finished computing. See "Cross-aggregation activity signal" below for how a test
(E2E or otherwise) waits this out deterministically instead of guessing with a fixed
timeout, and make sure any UI reading such an aggregation treats `data === null` as
"unknown yet", not "confirmed empty" (`src/pages/Dashboard.tsx`'s `isCompletelyEmpty`
is the reference fix for this exact gotcha). This is expected behavior, not a bug to
"fix" with a retry loop.

This cold-start throw is logged via `console.warn` (message only, no `Error` object/stack)
rather than `console.error` — `logBackgroundFailure` (`core/aggregation.ts`) special-cases
`ColdAggregationSourceError` specifically, since it is expected and self-healing, not a
failure an operator needs to chase down. Every other background-recompute failure still
goes to `console.error` with the full `Error` object (stack included).

## Declarative operator kit — `zechinus/aggregate`

A second, declarative form for `compute`, alongside the plain-function form used by every
real aggregation wired in this branch so far (`dashboardAgg`/`netWorthSeriesAgg` above
both use plain functions, because their math already lives in `shared/domain/*` — see
`aggregate/index.ts`'s own header comment for the target shape):

```ts
import * as agg from "zechinus/aggregate";

defineAggregation({
  // ...
  compute: {
    liquidita: agg.sum("banche", "saldo"),
    immobili: agg.sum("assets", "valore", { where: { tipo: "immobile" } }),
    totaleAttivi: agg.expr((f) => f.liquidita + f.immobili),
    varEur: agg.lastDelta("storicoPatrimonio", "valore"),
    effScore: agg.custom((f, src) => computeEffScore(f)),
  },
});
```

Verified, compiling usage lives in `zechinus/examples/basic-usage.ts`'s
`aggregationExample()` (`compute: { total: agg.sum("invoices", "amount") }`) and
`zechinus/tests/aggregateOperators.test.ts`. `defineAggregation` compiles a
`FieldOperators` record into the exact same function shape ONCE, at definition time
(`compileFieldOperators`, `aggregate/compile.ts`) — nothing downstream of that point knows
a declarative form exists.

The five operators, deliberately ONLY these five (YAGNI — no `avg`/`count`/`min`/`max`/
`groupBy`, however tempting in the abstract):

| Operator                       | Does                                                                                                                       |
| ------------------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| `sum(source, field, {where})`  | Sums `field` across every row of `source`, optionally filtered by exact match                                              |
| `sumWith(source, fn, {where})` | Like `sum`, but the per-row value is `fn(row)` — for reductions with real logic (typically calling into `shared/domain/*`) |
| `expr(fn)`                     | `fn` reads the aggregate's OTHER already-computed fields; dependency order resolved automatically, cycles fail loud        |
| `lastDelta(source, field)`     | Reads `field` off the LAST row of `source` (an ordered time series)                                                        |
| `custom(fn)`                   | Escape hatch — `fn(fields, sources)` sees everything else already computed, plus the raw sources                           |

Prefer the declarative form when every output field is expressible as one of the five
operators over array/collection sources — no domain logic belongs in the operators
themselves (`sumWith`/`custom`'s `fn` is always the caller's own function, e.g. from
`shared/domain/*`). Prefer the plain-function form (as every real aggregate in this branch
does today) when the computation is a single existing pure function you're reusing as-is
(`calculateDashboardMetrics`, `buildRetroactiveHistoryClient`) — wrapping an
already-correct, already-tested function in five operator calls would be pure overhead for
no readability gain.

## Cross-aggregation activity signal — `isAnyAggregationComputing()`

`useAggregation(agg).computing` tells you whether ONE specific aggregation is mid-recompute
— useful when a component already knows which aggregation it cares about. Sometimes a
caller doesn't: an E2E test that just wrote data (created an account, imported a
transaction, added an investment) doesn't know — and shouldn't need to know — which
aggregation(s) that write marks stale, only that it should wait for ALL of them to settle
before asserting on the resulting UI (see the "cold aggregate-as-source throws, then
self-heals" gotcha above — a fixed `sleep()` before asserting is exactly the wrong tool
here, since it's either too short, racing a real recompute, or an arbitrary guess that's
too long).

`isAnyAggregationComputing()` (plus `subscribeGlobalAggregationActivity(cb)` to react to
changes) is a single counter, incremented while ANY aggregation defined anywhere in the
process has a compute in flight and decremented when it settles — not per-aggregation-name,
so a caller never needs to enumerate which aggregations exist:

```ts
import {
  isAnyAggregationComputing,
  subscribeGlobalAggregationActivity,
} from "zechinus";
import { useIsAnyAggregationComputing } from "zechinus/react";

// React: reactive boolean, same useSyncExternalStore pattern as useIsUnlocked.
const computing = useIsAnyAggregationComputing();
```

The intended shape for a host app: render the React binding once, in a hidden DOM node
somewhere always-mounted (the host app's `src/components/AggregationActivityIndicator.tsx`
— `data-testid="aggregations-status"` + `data-computing="true"|"false"`), then have an E2E
helper poll that attribute (the host app's `tests/e2e/_helpers.ts`,
`waitForAggregationsIdle(page)`) after any write that could trigger a recompute, before
asserting on the downstream effect. Deliberately NOT a per-aggregation registry: a caller
that already knows which aggregation to wait on already has `useAggregation(agg).computing`
directly — this primitive is for the "I don't know or care which ones, just tell me when
it's quiet" case only.

**`useIsAnyKeyedStoreLoading()`** (`react/useIsAnyKeyedStoreLoading.ts`) is the exact same
pattern, one layer down: a cross-`KeyedStore` "is any keyed-store fetch in flight right
now" signal (`isAnyKeyedStoreLoading()`/`subscribeGlobalKeyedStoreActivity()`, both in
`react/useKeyedStore.ts`, also exported standalone from `zechinus/react`). Aggregation
recomputes settle via the signal above; a plain keyed-store `load`/`mutate` in flight
(no aggregation involved) has nothing that marks it — this fills that gap, typically for an
E2E test waiting right after a DEK unlock, before any aggregation has even started
computing.

## `invalidateOn` / `invalidateChannel` — externals sourced from non-Store data

An `external` can depend on data that lives entirely OUTSIDE any Zechinus `Store` — a
plaintext table read via a plain REST call, e.g. "which account ids currently exist"
(`src/services/dashboardAggregation.ts`'s `existingAccountIds`). No `source` ever changes
when that data changes, so nothing naturally marks the aggregation stale before its `ttlMs`
expires — a `refresh({ bypassExternalsTtl: true })` call from the app is the only way to
force freshness, and every call site that mutates the underlying data would otherwise need
to remember to make it.

`invalidateOn` names the channel(s) an external depends on; `invalidateChannel(name)` (also
exported from `zechinus`) is called ONCE, at the single place the underlying mutation
actually happens — every aggregation with a matching `invalidateOn` entry has THAT
external's cache cleared and a recompute forced immediately, without the caller needing to
know which aggregation(s), if any, depend on it:

```ts
// dashboardAggregation.ts — declare the dependency once, where the external is defined.
externals: {
  existingAccountIds: {
    load: loadExistingAccountIds,
    ttlMs: 5 * 60 * 1000,
    invalidateOn: ["accounts-changed"],
  },
},
```

```ts
// appApi.ts — emit the event once, at the single choke point that mutates `accounts`.
import { invalidateChannel } from "zechinus";

export async function createManualAccount(input: unknown) {
  const result = await appApiRequest("/accounts/manual", {
    method: "POST",
    body: input,
  });
  invalidateChannel("accounts-changed");
  return result;
}
```

Scoped to just the ONE external that declared the channel — an unrelated external on the
same aggregation, or one with no `invalidateOn` at all, is never refetched by it. A channel
nobody subscribed to is a safe no-op.

## Cold-session freshness verification

`isFresh()` normally trusts the persisted envelope for any source never OBSERVED live
this session (`currentSourceFingerprints.get(name) === undefined` → "no signal, assume
unchanged") — correct if the source genuinely hasn't changed, wrong if it changed via a
path this session's live subscriptions never saw (a previous session's recompute
interrupted after a source write landed but before persisting, or another device/tab
writing while this one was closed/idle).

`.get()` now verifies every such never-observed source against the REAL current hash
before trusting the envelope, the first time a fresh identity subscribes — a no-op (zero
network calls) once every source has a real tracked value, which converges after the
first check. `KeyedSourceRef` sources sharing one physical table (e.g. `dashboardAgg`'s
`snapshots`/`portfolioSeries`-as-source/`netWorthSeries`-as-source/
`currentPortfolioMetrics`-as-source, all in `account_snapshot_blobs`) are verified with
ONE batched call via the adapter's optional `getHashesByKeys`, not one `getHash` per
source. `Aggregation` sources delegate to the upstream's own `.get()` (recursing its own
cold check if it's also cold) and compare via the same `aggregationSourceFingerprint`
`computeAndPersist` already persists — no new fingerprint convention.

This closes the "did a change I never observed live get missed" gap for a NEW session
(a page reload/reopen self-heals reliably now) — it does NOT make an already-open,
idle tab reactively pick up a write from a different tab/device without a fresh `.get()`
call (no server push/polling loop; `CacheAdapter` is in-memory, per tab/process, and
`ensureSubscribed`'s check happens once per identity, not on every `.get()`). Adapters
without `getHashesByKeys` (or without `getHash`/`loadWithHash` at all) fall back to more
round trips, never break correctness — see `StorageAdapter.getHashesByKeys`'s doc comment.

## Write-reaction — `onSourceWrite`

**A different primitive from `defineAggregation`, not a variant of it.** An aggregation
persists a DERIVED value the framework owns end-to-end; `onSourceWrite` instead reacts to
writes on a `KeyedStore` by calling an arbitrary app-supplied `handler` that itself
read/mutates a DIFFERENT store — one with its OWN, independent `optimisticLock` semantics
(see [docs/content-hash-and-locking.md](content-hash-and-locking.md)). Wrapping that in
`defineAggregation`'s internal store (hardcoded `optimisticLock: false`, see below) would
silently throw away a real cross-writer conflict. `onSourceWrite` never persists anything
itself; it only observes writes and invokes `handler`.

The one real consumer, `src/lib/secureStore.ts` (registered once, at bootstrap, right
after `configureSecureStore`):

```ts
import { onSourceWrite } from "zechinus";

onSourceWrite(
  txStore,
  async ({ keys }) => {
    if (!keys.length) return;
    const sorted = [...keys].sort();
    await rebuildMonths(monthRange(sorted[0], sorted[sorted.length - 1]));
  },
  { debounceMs: 500, coalesce: true },
);
```

Every ambient write on `txStore` (import, row edit, delete, recurring-transaction
materialization, demo seed) debounces/coalesces into ONE `handler({ keys })` call carrying
the union of touched months, replacing 6 manual `rebuildMonths` call sites that used to be
scattered across the app. `rebuildMonths` writes `snapshotStore`
(`optimisticLock: true`) — a real cross-writer conflict there (two tabs rebuilding
overlapping months) throws `OptimisticLockConflictError`, and `onSourceWrite` retries that
failure automatically with exponential backoff (default: 5 attempts, 1s base delay,
doubling, capped at 30s) instead of silently dropping the failed months. The current
unresolved failure (if retries haven't succeeded yet) is inspectable via
`handle.getLastError()` on the handle `onSourceWrite` returns.

**`handle.flush()`** forces whatever is currently pending (a debounced write still waiting
out `debounceMs`, or a scheduled backoff retry) to run NOW, and awaits it — including any
single-flight rerun a write arriving mid-run queues. For a caller that just finished a known
batch (e.g. an import that wrote N months) and needs the reaction's effect visible before it
proceeds, without knowing which keys were touched or duplicating `handler`'s own logic at the
call site, and without waiting out the debounce window. Real consumer,
`src/lib/secureStore.ts` exports a thin wrapper around it:

```ts
const txSnapshotRebuildHandle = onSourceWrite(txStore, handler, {
  debounceMs: 500,
});

export function flushTxSnapshotRebuild(): Promise<void> {
  return txSnapshotRebuildHandle.flush();
}
```

`AccountsRegister.tsx`'s post-import reconcile modal calls this before reading
`conto.saldoContabile`, instead of racing the 500ms debounce. Never rejects — a `handler`
failure is already surfaced via `getLastError()`/`console.error`; resolves immediately if
nothing is pending or in flight.

**Known architectural limit (documented, not hidden):** a `handler` call already in flight
that crosses a same-tab session/identity switch can still persist under the wrong
identity — `rebuildMonths`'s own `mutate()` call resolves the ambient identity fresh at
its own invocation, not pinned to whichever identity was active when `handler` was
dispatched. `onSourceWrite` isolates its OWN bookkeeping (`lastError`, scheduled retries)
from a stale identity correctly, but it cannot retroactively stop `rebuildMonths`'s
`mutate()` from resolving a NEW identity mid-flight — a pre-existing gap in how
`rebuildMonths` resolves ambient identity, not introduced by this module. See
`zechinus/core/onSourceWrite.ts`'s own doc comment for the exact scope of this gap.

## `optimisticLock`: materialized store vs. derived aggregate

**`optimisticLock: true` belongs to materialized stores with partial update, where two
writers can legitimately conflict** — e.g. `snapshotStore`, updated incrementally by
`rebuildMonths` from potentially two tabs at once. **`optimisticLock: false` belongs to
derived read-models** — a clobber there just rewrites the same result (or gets
invalidated by fingerprints on the next read), never a real conflict.

This isn't a per-call decision for `defineAggregation`: `AggregationDef` has no
`optimisticLock` field at all — the internal store `defineAggregation` builds hardcodes
`optimisticLock: false` (`core/aggregation.ts`). Every aggregation in this branch (A/C/D —
`portfolioSeriesAgg`/`netWorthSeriesAgg`/`dashboardAgg`) gets this for free, by
construction, never by a choice a caller makes.

The choice a future developer actually faces is upstream of that: **is what I'm building a
derived read-model, or a materialized store someone partially updates?** If it's the
former, use `defineAggregation` — the framework already made the right call.
If a "read model" ever seems to need `optimisticLock: true`, that's the signal the shape
isn't a derived aggregate at all: build it as a real `defineStore` (like `snapshotStore`)
updated by a `onSourceWrite` reaction (like `rebuildMonths`), not as a `defineAggregation`.

## Anti-sprawl: when NOT to persist an aggregation

Not every derived value belongs in `defineAggregation`. If a computation is a pure
`useMemo` over data that's already cache-resident from a SINGLE store, with no remote I/O
and no cumulative-over-time logic, it stays a plain function in the view — persisting it
would add a DB row, a fingerprint subscription, and a debounce timer for something that
already recomputes for free on every render.

Reference case, explicitly excluded from this branch's plan: `src/hooks/useBudgetAggregation.ts`.
It calls `buildReportAggregation` inside a `useMemo` over `useTransactions`'s already
TanStack-cached data — no persistence, no framework involvement:

```ts
const aggregation = useMemo(
  () =>
    buildReportAggregation({
      transazioni,
      period,
      budgetCategorie: resolvedBudgetCategorie,
      budgetGruppi: resolvedBudgetGruppi,
      ...(today ? { today } : {}),
    }),
  [transazioni, period, resolvedBudgetCategorie, resolvedBudgetGruppi, today],
);
```

The signal that something DOES belong in `defineAggregation` instead: a remote fetch
(`ExternalInput`), a cumulative-over-time computation that would otherwise re-scan every
month on every render (`buildRetroactiveHistoryClient`'s net-worth history), or a value
several independent views need to agree on byte-for-byte (`dashboardAgg`'s consistency
with `Investimenti.tsx`'s portfolio metrics). Absent those, keep it a `useMemo`.
