# Aggregation extras: `flush()`, `invalidateOn`/`invalidateChannel`, cold-session check

Read this when working with `defineAggregation` (a persisted, declarative read-model
derived from one or more stores) — not needed for plain `defineStore` work.

Three capabilities layered on top of the core `defineAggregation`/`onSourceWrite`
mechanics — full rationale and code examples in `README.md`'s own sections (same
headings), this is just "when do I reach for which":

- **`OnSourceWriteHandle.flush()`** (`core/onSourceWrite.ts`) — a caller that just
  finished a known batch of writes (an import, a bulk edit) and needs the reaction's
  effect (a derived snapshot) visible RIGHT NOW, without waiting out `debounceMs` or
  duplicating the reaction's own logic at the call site. Never build a second "rebuild"
  call site in app code for this — that's exactly what `flush()` replaces.
- **`ExternalInput.invalidateOn` / `invalidateChannel(name)`** (`core/aggregation.ts`) —
  an `external` whose data lives OUTSIDE any Zechinus `Store` (a plaintext table read
  via plain REST, e.g. "which account ids exist") has no write-interception hook at all;
  nothing marks the aggregation stale until the external's own `ttlMs` expires. Declare
  the channel(s) the external depends on, then call `invalidateChannel(name)` ONCE, at
  the single app-level place the underlying mutation happens (never scattered across
  every caller of that mutation).
- **Cold-session hash verification** — automatic, nothing to configure. `.get()` verifies
  every source never observed live THIS session against the real current hash before
  trusting the persisted envelope, the first time a fresh identity subscribes. Batches
  `KeyedSourceRef` sources sharing one physical table into one `getHashesByKeys` call.
  Know its real limit: it closes the "a write I never saw live gets missed on a NEW
  session" gap (a reload self-heals) — it does NOT make an already-open idle tab pick up
  another tab/device's write without a fresh `.get()` call (no server push/polling; the
  `CacheAdapter` is in-memory, per tab/process).
- **`isAnyAggregationComputing()` / `subscribeGlobalAggregationActivity(cb)`** — a single
  cross-aggregation "is anything computing right now" counter, for a caller that doesn't
  know or care WHICH aggregation(s) a write affects (typically an E2E test, or a host app's
  hidden DOM indicator that test waits on — see README's own section for the exact wiring).
  Do not reach for this when the caller already knows the specific aggregation — that's
  `useAggregation(agg).computing` directly.

**⚠️ Aggregate-as-source cold start throws once, then self-heals — this is expected, not a
bug to "fix" with a retry loop.** A downstream aggregation reading an upstream one that has
never itself computed in this session gets `data === null` and the downstream's compute
throws (`computeAndPersist`, `core/aggregation.ts`) — it never waits on another
aggregation's first compute. Reading the source is what kicks off ITS OWN background
compute as a side effect, though; once that persists, the downstream (already subscribed to
it like any other source) reacts and recomputes successfully, usually well under a second.
**Consequence for any UI reading such an aggregation:** treat `data === null` as "not known
yet", never as "confirmed empty" — a component that derives an empty/onboarding state from
zero-valued fields without checking `data !== null` first will flash that empty state on
every cold session, even when real data exists (`src/pages/Dashboard.tsx`'s
`isCompletelyEmpty` is the reference fix). **Consequence for tests
(E2E, tutorial recordings, anything driving a real browser):** after a write that could
mark an aggregation stale, wait for `isAnyAggregationComputing()` to go false (or the app's
hidden DOM indicator built on it) before asserting/screenshotting — never a fixed `sleep()`,
which is either too short (races the recompute) or an arbitrary guess.

## `tanstackAdapter` requires `gcTime: Infinity` — enforced, not just documented

`tanstackAdapter` (`adapters/tanstackAdapter.ts`) writes via `setQueryData`/`getQueryData`
and never mounts a real `useQuery` observer — every entry it creates has zero observers
for its whole life. TanStack schedules that entry's garbage collection unconditionally at
creation time (a separate axis from `staleTime`) and evicts it once `gcTime` elapses, no
matter how many times it was refreshed in between. With the default 5-minute `gcTime`,
cached decrypted data silently disappears from every Zechinus-backed hook after that long
of the consuming app sitting idle — no error, since `CacheAdapter` has no "refetch" concept
for a caller to notice or recover from. This is a real bug that shipped once (the host app's
Dashboard going blank after ~5 minutes idle, filling again only on remount).

Following the same idiom as the encryption guardrail (`defineStore` throwing on a missing
`encrypt` declaration): **`tanstackAdapter` throws immediately at construction** if
`queryClient.getDefaultOptions().queries?.gcTime !== Infinity`. Documentation alone (a
README note nobody reads before it bites them 5 minutes into a real session) was judged
insufficient — the fix must fail loud at wiring time (app boot / `configureSecureStore`
call), not silently at 3am in a real user's idle tab. If you extend or replace this
adapter, or write a new `CacheAdapter` backed by anything with its own eviction/TTL
concept, apply the same principle: assert the safe configuration at construction, don't
just document it.
