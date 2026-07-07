/**
 * defineAggregation — persisted, declarative aggregates over DataCloak stores.
 *
 * The app declares WHAT to compute (a pure `compute()` over `sources`/`externals`) and
 * WHERE it persists (`storage: { table, key }`); the framework owns WHEN to recompute
 * (fingerprint-gated: only when a source actually changed or an external's TTL expired),
 * debouncing/coalescing bursts of source writes into a single recompute, and persisting
 * through the same encrypted envelope/AAD/versioning machinery `defineStore` already
 * provides — this module never touches those wire paths directly, it builds ONE internal
 * `perKey` store per aggregation and drives it.
 *
 * Scope of this file (v1, perUser aggregations only — see the plan's "aggregazioni
 * dichiarative persistite" for the full roadmap):
 *  - persistence via an internal store (`optimisticLock: false` — a derived value, a
 *    clobber just rewrites the same result, never a real conflict; `contentHash: true`)
 *  - source fingerprinting (via each source's own `contentHash`) + mark-stale on ambient
 *    writes (via the `CacheAdapter` write-through every `defineStore` ambient write
 *    already does — see `store.ts`'s `writeThroughCache`)
 *  - debounced, single-flight recompute
 *
 * Task 2 additions: an `Aggregation` may itself be a `sources` entry (see `Source` below,
 * `isAggregationSource`) — a downstream aggregation reads the upstream one's PERSISTED
 * value via its own `.get()` (never duplicating its compute/externals logic) and the
 * upstream's fingerprint propagates into the downstream's own `sourceFingerprints`, using
 * the exact same CacheAdapter push/subscribe convention a `Store` source already uses (see
 * `aggregationSourceFingerprint`) — no special-casing needed in `ensureSubscribed`/`isFresh`.
 *
 * Task 3 addition: `compute` may ALSO be the declarative `FieldOperators` record from
 * `../aggregate` (`sum`/`sumWith`/`expr`/`lastDelta`/`custom`) instead of a hand-written
 * function — see `ComputeFn`'s doc comment and `AggregationDef.compute`'s type below.
 * `compileFieldOperators` (imported from `../aggregate/compile.ts`) turns that record into
 * the exact same function shape at DEFINITION time, once, in `defineAggregation` itself —
 * everything below that point (`computeAndPersist` etc.) only ever calls the resulting
 * plain function and has no notion that a declarative form exists.
 *
 * NOT in this file (later tasks, see the plan): the React binding (Task 4), and
 * `onSourceWrite` (Task 6 — a different primitive, for a write-REACTION, not an
 * aggregate).
 */

import { z } from "zod";
import { defineStore, type Store, type KeyedStore } from "./store.ts";
import { getSecureStoreConfig } from "./config.ts";
import { fingerprintSchema } from "./schemaFingerprint.ts";
import { LockedSessionError } from "./errors.ts";
import type { CryptoHandle } from "./types.ts";
import {
  compileFieldOperators,
  type FieldOperators,
} from "../aggregate/compile.ts";

/**
 * A non-store input to `compute()` — e.g. a market-data API call — refreshed on its own
 * TTL rather than in reaction to a store write (there is no "write" to detect).
 */
export interface ExternalInput<T = unknown> {
  load: () => Promise<T>;
  ttlMs: number;
}

/**
 * What an aggregation can read from: a `perUser` `Store`, OR another `Aggregation`
 * (opt-in DAG composition — e.g. a dashboard aggregate sourcing an already-computed
 * portfolio-history aggregate, so the expensive fetch behind it never runs twice). See
 * `isAggregationSource` for how the two are told apart at runtime.
 */
export type Source = Store<any> | Aggregation<any>;

type SourceData<S> =
  S extends Store<infer D> ? D : S extends Aggregation<infer D> ? D : never;
/** The `sources` shape `compute()` receives: one field per `sources` entry, holding that
 * source's plain (decrypted) data — never the store object itself. */
export type DataOf<TSources extends Record<string, Source>> = {
  [K in keyof TSources]: SourceData<TSources[K]>;
};

type ExternalData<E> = E extends ExternalInput<infer D> ? D : never;
export type ExternalsOf<TExt extends Record<string, ExternalInput<any>>> = {
  [K in keyof TExt]: ExternalData<TExt[K]>;
};

/**
 * The pure-function form of `compute` — the ONLY form this type describes. `AggregationDef
 * .compute` below widens to `ComputeFn<...> | FieldOperators<...>`, the second member being
 * `../aggregate`'s declarative operator-record form (`sum`/`sumWith`/`expr`/`lastDelta`/
 * `custom`); both compile to (or already are) this exact shape before anything in this file
 * ever calls them — see `defineAggregation`'s `computeFn` local.
 */
export type ComputeFn<
  TSchema extends z.ZodType,
  TSources extends Record<string, Source>,
  TExt extends Record<string, ExternalInput<any>>,
> = (input: {
  sources: DataOf<TSources>;
  externals: ExternalsOf<TExt>;
}) => z.infer<TSchema> | Promise<z.infer<TSchema>>;

export interface AggregationDef<
  TSchema extends z.ZodType,
  TSources extends Record<string, Source>,
  TExt extends Record<string, ExternalInput<any>> = Record<string, never>,
> {
  version: number;
  /** Shape of the aggregate's OWN data — never the persisted envelope (framework-owned,
   * see `PersistedEnvelope` below, never surfaced to the caller). */
  schema: TSchema;
  /** Same discipline as `defineStore`'s `schemaFingerprint`: computed from `schema` via
   * `fingerprintSchema(schema, "all")`, checked at definition time. Unlike a store,
   * an aggregation never needs a migrator for a shape change — a mismatch (or a
   * `version` bump) just means "recompute from sources", there is no old ciphertext to
   * migrate in place. */
  schemaFingerprint: string;
  /**
   * Where the aggregate persists. `table` is a `defineStore` `name` (a real backing
   * table/collection); `key` is the sentinel row identifier within it — several
   * aggregations MAY share one physical table via distinct `key` values, the same
   * convention `snapshotStore`/`dashboardSummaryStore` already use with a generic
   * "domain key" column. The physical column backing this key must be named `"key"`
   * (this module's own convention for tables it fully owns) — wiring an aggregation
   * into a PRE-EXISTING table whose sentinel column has a different name (e.g.
   * `year_month`) needs an explicit follow-up, see this task's report.
   */
  storage: { table: string; key: string };
  sources: TSources;
  externals?: TExt;
  /** Either a hand-written pure function, OR the declarative operator-record form from
   * `../aggregate` (`agg.sum`/`agg.sumWith`/`agg.expr`/`agg.lastDelta`/`agg.custom`) — see
   * `ComputeFn`'s doc comment. `defineAggregation` compiles the latter to the former ONCE,
   * at definition time; every recompute after that calls the same plain function either
   * way. */
  compute:
    | ComputeFn<TSchema, TSources, TExt>
    | FieldOperators<TSchema, TSources, TExt>;
  /** Debounce window for a source-write-triggered recompute — several rapid writes
   * inside this window coalesce into exactly one `compute()` call. Default 500ms. */
  debounceMs?: number;
}

export interface AggregationState<T> {
  /** The last successfully persisted value, or `null` if this aggregate has never been
   * computed yet — a first-class state, never a sentinel object the caller has to know
   * to check for. */
  data: T | null;
  /** `true` while a recompute (initial, source-triggered, or explicit `refresh()`) is
   * in flight. */
  computing: boolean;
  /** `true` when `data` (if any) no longer matches the sources' current fingerprints, or
   * this is the very first read (nothing persisted yet) — a recompute has already been
   * scheduled/started by this same call. */
  stale: boolean;
  /** The error from the MOST RECENT failed compute, if any. The previous successful
   * `data` is still returned alongside it — a failure never corrupts or empties what was
   * already persisted (see `refresh()`). */
  error: Error | null;
}

export interface Aggregation<T> {
  readonly name: string;
  readonly version: number;
  /**
   * Ambient read (no `userId`/`CryptoHandle` — the same ambient session identity every
   * other `.get()` in this framework resolves from the configured `KeyProvider`). Returns
   * the current best-known state immediately; if nothing has ever been persisted, or the
   * persisted value is stale relative to its sources' current fingerprints (or an
   * external's TTL has expired), a recompute is kicked off in the background
   * (single-flight-guarded, debounce-free — this is an explicit read, not a
   * write-reaction) and `computing`/`stale` reflect that. This call never blocks on the
   * recompute settling.
   */
  get(): Promise<AggregationState<T>>;
  /**
   * Forces a recompute now, bypassing any pending debounce window. Shares an
   * already-in-flight compute rather than starting a second one in parallel (single
   * flight) — if one lands mid-flight, it re-runs once more right after, never
   * concurrently. Rejects with whatever `compute()` threw; the previously persisted
   * aggregate is left completely untouched (never partially written) — see scenario 8 in
   * this task's tests.
   */
  refresh(): Promise<T>;
}

/**
 * Framework-owned wrapper around the aggregate's own `data` — never exposed to the
 * developer calling `defineAggregation`. Wire-stable shape (plain JSON, no `undefined`,
 * key order irrelevant — see the plan's portability note for the full cross-language
 * spec, a later task's doc work).
 */
interface PersistedEnvelope<T> {
  v: number;
  computedAt: string;
  sourceFingerprints: Record<string, string | null>;
  externalsFetchedAt: Record<string, string>;
  data: T | null;
}

/**
 * Same ambient-identity resolution `store.ts`'s private `resolveAmbientIdentity` does —
 * duplicated here (a few lines) rather than imported, since that helper isn't part of
 * `store.ts`'s public surface (see its own doc comment: "NOT exported from the public
 * barrel"). Reaching into another module's private internals would be worse than this
 * small, intentional duplication.
 */
function resolveAmbientIdentity(name: string): {
  cryptoHandle: CryptoHandle;
  userId: string;
} {
  const { keys } = getSecureStoreConfig();
  if (!keys) {
    throw new Error(
      `defineAggregation(${name}): no KeyProvider configured — pass 'keys' to configureSecureStore()`,
    );
  }
  const cryptoHandle = keys.getCryptoHandle();
  const userId = keys.getUserId();
  if (!cryptoHandle || !userId) {
    throw new LockedSessionError(name);
  }
  return { cryptoHandle, userId };
}

/**
 * Runtime discriminator for the `Source` union. `Aggregation<T>` is the only member with
 * a `refresh()` method — no `Store`/`KeyedStore`/`CollectionStore` cardinality in
 * `store.ts` ever exposes one — so its presence is a safe, unambiguous tag, no extra
 * marker property needed on either shape.
 */
function isAggregationSource(source: Source): source is Aggregation<unknown> {
  return (
    typeof (source as Partial<Aggregation<unknown>>).refresh === "function"
  );
}

/**
 * An Aggregation source has no `contentHash` column of its own (it isn't a `Store`) — its
 * "fingerprint", for a DOWNSTREAM aggregation's freshness check, is a deterministic digest
 * of its own persisted `data`. Computed identically in the two places that must agree: (1)
 * `computeAndPersist` below publishes it to the shared CacheAdapter slot right after a
 * REAL (non-skip-write) persist, using the exact same `${name}:${userId}` convention a
 * Store source's ambient write already publishes to (`writeThroughCache` in store.ts) — so
 * `ensureSubscribed`/`isFresh` need ZERO special-casing to also work for an Aggregation
 * source; (2) a downstream aggregation computes the SAME digest live, from the value its
 * own `.get()` call just returned, when building ITS `sourceFingerprints`. If these ever
 * disagreed, `isFresh()` could get permanently stuck — the same class of bug the
 * "regression" test above caught for skip-writes.
 */
function aggregationSourceFingerprint(data: unknown): string {
  return JSON.stringify(data);
}

/**
 * Cache key convention for the React binding's read-side state port
 * (`datacloak/react/useAggregation.ts`) — same `${name}:${userId}` shape every other
 * binding's CacheAdapter key already uses (see `react/useStore.ts`'s
 * `${store.name}:${userId}`), with a `:react` segment so it never collides with THIS
 * aggregation's own source-fingerprint publish key (`${name}:${userId}`, used when this
 * aggregation is itself a `Source` for a downstream one — see
 * `aggregationSourceFingerprint`). Exported so the binding never hardcodes/duplicates the
 * convention — this module is the only writer, the binding is the only reader.
 */
export function aggregationStateCacheKey(name: string, userId: string): string {
  return `${name}:react:${userId}`;
}

export function defineAggregation<
  TSchema extends z.ZodType,
  TSources extends Record<string, Source>,
  TExt extends Record<string, ExternalInput<any>> = Record<string, never>,
>(def: AggregationDef<TSchema, TSources, TExt>): Aggregation<z.infer<TSchema>> {
  type T = z.infer<TSchema>;
  const name = `${def.storage.table}:${def.storage.key}`;
  const debounceMs = def.debounceMs ?? 500;

  // ── Guardrail: same discipline as defineStore's schemaFingerprint check — thrown at
  // definition time, not reactively on read. Aggregations never need a migrator: a
  // version bump or shape change just means "recompute from sources", there's no old
  // ciphertext to migrate in place (see the plan's "aggregati derivati → ricalcolo
  // sempre legittimo, niente migrator").
  const computedFingerprint = fingerprintSchema(def.schema, "all");
  if (def.schemaFingerprint !== computedFingerprint) {
    throw new Error(
      `defineAggregation(${name}): the schema shape doesn't match the declared schemaFingerprint ` +
        `(expected "${def.schemaFingerprint}", computed "${computedFingerprint}"). Just update ` +
        `schemaFingerprint to "${computedFingerprint}" — aggregations recompute from their sources ` +
        `on any shape/version change, they are never migrated in place.`,
    );
  }

  // ── `compute`'s declarative form (see `AggregationDef.compute`'s doc comment) compiles
  // to a plain function ONCE, here, at definition time — never per-recompute. From this
  // point on, `computeAndPersist` below only ever calls `computeFn`, exactly like it
  // called `def.compute` before Task 3; it has no notion that a second form exists.
  const computeFn: ComputeFn<TSchema, TSources, TExt> =
    typeof def.compute === "function"
      ? def.compute
      : compileFieldOperators<TSchema, TSources, TExt>(def.compute);

  // ── Internal persistence: a perKey store, framework-private (never returned to the
  // caller of defineAggregation). `optimisticLock: false` (a derived value — a clobber
  // just rewrites the same result, never a real conflict). `contentHash: true`, but this
  // module does its OWN identical-content comparison (see `computeAndPersist`) rather
  // than relying on this store's built-in skip-write: the outer envelope's `computedAt`
  // timestamp always differs between two computes, which would defeat a hash comparison
  // over the whole envelope every single time.
  const envelopeSchema = z.object({
    v: z.number().default(0),
    computedAt: z.string().default(""),
    sourceFingerprints: z.record(z.string(), z.string().nullable()).default({}),
    externalsFetchedAt: z.record(z.string(), z.string()).default({}),
    data: def.schema.nullable().default(null),
  });
  // Computed inline (not a frozen literal) deliberately, unlike the app-facing guardrail
  // above: this schema is built HERE, from the caller's OWN `def.schema` — there is no
  // independent "someone edited the schema without updating the fingerprint" moment to
  // catch, it can never drift from itself.
  const envelopeFingerprint = fingerprintSchema(envelopeSchema, "all");
  const internalStore = defineStore({
    name: def.storage.table,
    identity: { perKey: "key" },
    schema: envelopeSchema,
    version: 1,
    encrypt: "all",
    contentHash: true,
    optimisticLock: false,
    schemaFingerprint: envelopeFingerprint,
  }) as KeyedStore<PersistedEnvelope<T>>;

  // ── Recompute orchestration state — one `defineAggregation()` call is one singleton
  // instance (same pattern `defineStore()` itself uses), this closure IS its state. ────
  let inFlight: Promise<T> | null = null;
  let rerunRequested = false;
  let debounceTimer: ReturnType<typeof setTimeout> | null = null;
  let lastError: Error | null = null;
  let subscribedUserId: string | null = null;
  let unsubscribeFns: Array<() => void> = [];
  // Per-source fingerprint this instance has actually OBSERVED this session (via the
  // source's own CacheAdapter slot) — `undefined` means "never observed", distinct from
  // `null` ("observed, but that store has no real contentHash"). See `isFresh` below for
  // why `undefined` is treated as "no signal, assume unchanged" rather than "stale".
  const currentSourceFingerprints = new Map<
    string,
    string | null | undefined
  >();
  const externalCache = new Map<
    string,
    { value: unknown; fetchedAtMs: number; fetchedAtIso: string }
  >();
  // Last envelope this instance has actually read/persisted THIS session — `null` means
  // "never observed" (mirrors `currentSourceFingerprints`' `undefined` sentinel). This is
  // the ONLY state `notifyReactState`/`computeCurrentState` need to derive a synchronous
  // snapshot for the React binding without any I/O — see those two functions below.
  let lastEnvelope: PersistedEnvelope<T> | null = null;
  // In-flight read of this aggregation's OWN persisted envelope, deduped — mirrors
  // `react/useStore.ts`'s `inflightFetches`/`fetchDeduped` registry (same single-flight
  // pattern): N mounted `useAggregation(sameAgg)` instances each run their own effect ->
  // own `get()` call, which would otherwise each independently read/decrypt the SAME
  // envelope row before any of them resolves (Task 4 review finding — the `inFlight`
  // guard above only dedupes `compute()`, not this read). Unlike `useStore.ts`'s
  // registry — a module-level `Map` keyed by `${store.name}:${userId}`, since ONE hook
  // implementation serves many distinct stores — this closure is already scoped to a
  // single aggregation instance, so a single SLOT gives the identical single-flight
  // semantics without a `Map` that would only ever hold one entry. That slot still
  // carries the identity (`userId`/`cryptoHandle`) the read was started for, and is
  // only ever reused when a NEW caller asks for that exact same identity — a live
  // instance can see its ambient identity change mid-flight (user A logs out, user B
  // logs in, in the same tab; see `ensureSubscribed`'s own "re-subscribes if the
  // ambient identity changes" handling), and reusing user A's still-pending decrypted
  // envelope for user B's `get()` would leak A's data across the user boundary (a
  // second review finding on this exact fix — never repeat a bare, un-keyed single
  // variable here).
  let inflightRead: {
    userId: string;
    cryptoHandle: CryptoHandle;
    promise: Promise<{ data: PersistedEnvelope<T>; hash: string | null }>;
  } | null = null;

  function logBackgroundFailure(context: string, e: unknown): void {
    // Fire-and-forget background recomputes (debounce fire, initial-load kickoff, queued
    // rerun) still surface their failure — never a silent catch — mirroring the existing
    // `secure-store(...): ... lazy upgrade failed` pattern in store.ts. The error is ALSO
    // captured in `lastError` for a subsequent `get()`/binding to see.
    console.error(`defineAggregation(${name}): ${context}:`, e);
  }

  function scheduleDebouncedRecompute(): void {
    if (debounceTimer) clearTimeout(debounceTimer);
    debounceTimer = setTimeout(() => {
      debounceTimer = null;
      triggerRecompute().catch((e) =>
        logBackgroundFailure("source-triggered recompute failed", e),
      );
    }, debounceMs);
  }

  /**
   * Lazily (re)subscribes to each source's own CacheAdapter slot for the CURRENT ambient
   * userId — the same `${storeName}:${userId}` key convention `store.ts`'s ambient
   * writes and `react/useStore.ts` already share (not an internal reach-around: it's an
   * existing cross-module convention). A source write anywhere in the app (ambient
   * `set()`/`mutate()`) already pushes a fresh `{data,hash}` into that slot — this is the
   * "the core intercepts every write already" hook the plan calls out, no changes to
   * `store.ts` needed. Re-subscribes if the ambient identity changes (user switch).
   */
  function ensureSubscribed(userId: string): void {
    const { cache } = getSecureStoreConfig();
    if (!cache || subscribedUserId === userId) return;
    for (const unsub of unsubscribeFns) unsub();
    unsubscribeFns = [];
    currentSourceFingerprints.clear();
    subscribedUserId = userId;
    for (const [sourceName, source] of Object.entries(def.sources)) {
      const cacheKey = `${source.name}:${userId}`;
      const readHash = (): string | null | undefined =>
        cache.get<{ data: unknown; hash: string | null }>(cacheKey)?.hash;
      currentSourceFingerprints.set(sourceName, readHash());
      unsubscribeFns.push(
        cache.subscribe(cacheKey, () => {
          currentSourceFingerprints.set(sourceName, readHash());
          // Mark stale immediately (before the debounce even fires) so a mounted
          // `useAggregation` reflects the write right away, not only once the
          // debounced recompute settles — see Task 4's scenario 4.
          notifyReactState();
          scheduleDebouncedRecompute();
        }),
      );
    }
  }

  /** Freshness check using ONLY already-known fingerprints (no source fetch — the
   * mechanism a future binding needs for "fresh, no recompute necessary", see the
   * plan/brief; the OBSERVABLE behavior this enables is Task 4's scenario 3/4). */
  function isFresh(envelope: PersistedEnvelope<T>): boolean {
    if (envelope.v !== def.version) return false;
    for (const sourceName of Object.keys(def.sources)) {
      const current = currentSourceFingerprints.get(sourceName);
      // Never observed this session: no signal either way. A REAL change would have
      // gone through an ambient write, which fires the subscription above — so "never
      // observed" here means "unchanged since the last persisted compute", not "unknown".
      if (current === undefined) continue;
      if (current !== (envelope.sourceFingerprints[sourceName] ?? null)) {
        return false;
      }
    }
    const now = Date.now();
    for (const [extName, ext] of Object.entries(def.externals ?? {})) {
      const fetchedAtIso = envelope.externalsFetchedAt[extName];
      if (!fetchedAtIso || now - Date.parse(fetchedAtIso) >= ext.ttlMs) {
        return false;
      }
    }
    return true;
  }

  /** Pure, synchronous — never touches storage. The exact snapshot `notifyReactState`
   * publishes to the CacheAdapter for the React binding to read via
   * `useSyncExternalStore`. */
  function computeCurrentState(): AggregationState<T> {
    if (lastEnvelope === null) {
      return {
        data: null,
        computing: inFlight !== null,
        stale: true,
        error: lastError,
      };
    }
    return {
      data: lastEnvelope.data,
      computing: inFlight !== null,
      stale: !isFresh(lastEnvelope),
      error: lastError,
    };
  }

  /**
   * Publishes the current snapshot to the CacheAdapter, at the exact key
   * `aggregationStateCacheKey(name, userId)` computes — the "port" the React binding
   * (`datacloak/react/useAggregation.ts`) reads via plain `cache.get`/`cache.subscribe`,
   * same as every other binding here (see `react/useStore.ts`). Ambient-identity-based
   * (reads `keys.getUserId()`/`getCryptoHandle()` fresh, not a captured closure value) so
   * it naturally no-ops while locked — never publishes on behalf of a session that isn't
   * the CURRENT one, same discipline as the guard in `computeAndPersist` below.
   */
  function notifyReactState(): void {
    const { keys, cache } = getSecureStoreConfig();
    if (!keys || !cache) return;
    const userId = keys.getUserId();
    if (!userId || keys.getCryptoHandle() === null) return;
    cache.set(aggregationStateCacheKey(name, userId), computeCurrentState());
  }

  /**
   * Dedupes concurrent reads of this aggregation's OWN persisted envelope (see
   * `inflightRead`'s doc comment above for why) — but ONLY for the SAME identity the
   * in-flight read was started for. A request for a different `userId`/`cryptoHandle`
   * (the live-instance user-switch case) always starts its own fresh read rather than
   * awaiting someone else's in-flight promise. Cleared in `.finally()` so the NEXT call
   * for that identity after this one settles always does a real read again — this only
   * collapses calls that overlap in time for the SAME user, never caches the result past
   * the read that's actually in flight, and never past a user switch.
   */
  function loadEnvelopeDeduped(
    userId: string,
    cryptoHandle: CryptoHandle,
  ): Promise<{ data: PersistedEnvelope<T>; hash: string | null }> {
    if (
      inflightRead &&
      inflightRead.userId === userId &&
      inflightRead.cryptoHandle === cryptoHandle
    ) {
      return inflightRead.promise;
    }
    const promise = internalStore.loadWithHash!(
      userId,
      cryptoHandle,
      def.storage.key,
    ).finally(() => {
      if (inflightRead?.promise === promise) inflightRead = null;
    });
    inflightRead = { userId, cryptoHandle, promise };
    return promise;
  }

  async function computeAndPersist(): Promise<T> {
    const { cryptoHandle, userId } = resolveAmbientIdentity(name);

    const sourceEntries = await Promise.all(
      // Cast to `Record<string, Source>` (not the generic `TSources`) so the type guard
      // below actually narrows `source` in both branches — a type predicate can't reliably
      // exclude its type from a still-generic type parameter (a known TS limitation), only
      // from a concrete union like `Source`.
      Object.entries(def.sources as Record<string, Source>).map(
        async ([sourceName, source]) => {
          if (isAggregationSource(source)) {
            // Read the source aggregation's PERSISTED value via its own ambient `.get()`
            // — never its `compute()`/externals, never `.refresh()`. If it's stale,
            // `.get()` kicks off ITS OWN background recompute (its own independent
            // staleness pipeline) and still returns immediately with what's currently
            // persisted — exactly the "no double fetch" behavior scenario 9 requires.
            const state = await source.get();
            if (state.data === null) {
              throw new Error(
                `defineAggregation(${name}): source aggregation "${sourceName}" (${source.name}) ` +
                  `has no persisted value yet — call its own get()/refresh() at least once ` +
                  `before using it as a source for another aggregation.`,
              );
            }
            return [
              sourceName,
              state.data,
              aggregationSourceFingerprint(state.data),
            ] as const;
          }
          // Only a Store can reach here — `isAggregationSource` above already returned
          // false — but TS can't fully exclude `Aggregation<any>` from this branch on its
          // own (narrowing a union against a *generic* type predicate parameter has known
          // limitations), hence the explicit cast rather than relying on control-flow
          // narrowing alone.
          const storeSource = source as Store<any>;
          const { data, hash } = storeSource.loadWithHash
            ? await storeSource.loadWithHash(userId, cryptoHandle)
            : {
                data: await storeSource.load(userId, cryptoHandle),
                hash: null,
              };
          return [sourceName, data, hash] as const;
        },
      ),
    );
    const sourcesData = Object.fromEntries(
      sourceEntries.map(([sourceName, data]) => [sourceName, data]),
    ) as DataOf<TSources>;
    const sourceFingerprints: Record<string, string | null> =
      Object.fromEntries(
        sourceEntries.map(([sourceName, , hash]) => [sourceName, hash]),
      );

    const now = Date.now();
    const externalsData: Record<string, unknown> = {};
    const externalsFetchedAt: Record<string, string> = {};
    for (const [extName, ext] of Object.entries(def.externals ?? {})) {
      const cached = externalCache.get(extName);
      if (cached && now - cached.fetchedAtMs < ext.ttlMs) {
        externalsData[extName] = cached.value;
        externalsFetchedAt[extName] = cached.fetchedAtIso;
      } else {
        const value = await (ext as ExternalInput<unknown>).load();
        const fetchedAtIso = new Date(now).toISOString();
        externalCache.set(extName, { value, fetchedAtMs: now, fetchedAtIso });
        externalsData[extName] = value;
        externalsFetchedAt[extName] = fetchedAtIso;
      }
    }

    // Compute errors propagate as-is — nothing below this line runs, so the persisted
    // envelope (if any) is left completely untouched. Never caught/swallowed here.
    const rawResult = await computeFn({
      sources: sourcesData,
      externals: externalsData as ExternalsOf<TExt>,
    });
    const validated = def.schema.parse(rawResult) as T;

    const { data: currentEnvelope } = await internalStore.loadWithHash!(
      userId,
      cryptoHandle,
      def.storage.key,
    );
    // Skip-write (scenario 7) is about `data` only — but `isFresh()` gates on
    // `sourceFingerprints`/`externalsFetchedAt`, which are populated from THIS
    // recompute's live reads, not from `data`. A source can change (new fingerprint)
    // while still producing byte-identical `data` (e.g. a bucketing/rounding compute).
    // If we skip the write there too, the persisted envelope's fingerprints go stale
    // forever while `currentSourceFingerprints` (kept live via the cache subscription)
    // keeps moving — `isFresh()` would then never match again, forcing a background
    // `compute()` on every subsequent `get()` even though nothing has changed since this
    // recompute. So the write is skipped ONLY when data AND fingerprints AND external
    // fetch timestamps are all unchanged — never when just `data` happens to match.
    const dataUnchanged =
      currentEnvelope.data !== null &&
      JSON.stringify(currentEnvelope.data) === JSON.stringify(validated);
    const fingerprintsUnchanged =
      dataUnchanged &&
      JSON.stringify(currentEnvelope.sourceFingerprints) ===
        JSON.stringify(sourceFingerprints) &&
      JSON.stringify(currentEnvelope.externalsFetchedAt) ===
        JSON.stringify(externalsFetchedAt);

    // Fail-open (same discipline `react/useStore.ts`'s `reload()` already applies after
    // its own await boundary): if the app locked, or switched to a different user, while
    // any of the awaits above were in flight, never persist or publish content computed
    // under a session that's no longer the active one. `userId`/`cryptoHandle` above are
    // the ones captured at THIS call's start (`resolveAmbientIdentity`). This FIRST check
    // only catches a lock that happened during the awaits ABOVE this point (source reads,
    // externals, `compute()`, the `loadWithHash!` read of `currentEnvelope`) — it does
    // NOT cover a lock firing during `internalStore.save()`'s OWN internal awaits (encrypt
    // + storage `put`) just below; the SECOND check right after that await (Task 4 review
    // finding) is what closes that narrower race window. The read of `currentEnvelope`
    // above still used the stale identity, exactly like `reload()` performs its own read
    // before checking — harmless (never surfaced), just discarded here.
    const ambientIdentityStillMatches = (): boolean => {
      const { keys } = getSecureStoreConfig();
      return (
        !!keys && keys.getCryptoHandle() !== null && keys.getUserId() === userId
      );
    };
    if (!ambientIdentityStillMatches()) {
      return validated;
    }

    if (!fingerprintsUnchanged) {
      const envelope: PersistedEnvelope<T> = {
        v: def.version,
        computedAt: new Date().toISOString(),
        sourceFingerprints,
        externalsFetchedAt,
        data: validated,
      };
      await internalStore.save(userId, cryptoHandle, def.storage.key, envelope);
      // Re-check AGAIN, immediately before the synchronous state mutations/notify that
      // follow: a lock (or user switch) firing DURING save()'s own internal awaits isn't
      // caught by the check above, since that one already passed before this await even
      // started. Mirrors `reload()`'s guarantee that nothing can interleave between the
      // LAST identity check and the actual state mutation — not just the first check
      // before starting the I/O (Task 4 review finding).
      if (!ambientIdentityStillMatches()) {
        return validated;
      }
      lastEnvelope = envelope;
      // Publish this aggregation's OWN fingerprint under the exact same
      // `${name}:${userId}` convention a Store source's ambient write already uses (see
      // `writeThroughCache` in store.ts) — this is the ONLY hook a downstream aggregation
      // needs to treat this one as just another named `Source`: `ensureSubscribed`
      // already subscribes by `${source.name}:${userId}` for every source, generically.
      // Skipped on a skip-write (this branch), same as a store's own mutate() skips
      // writeThroughCache on an unchanged contentHash — nothing downstream needs to know
      // about a persist that changed nothing observable.
      const { cache } = getSecureStoreConfig();
      cache?.set(`${name}:${userId}`, {
        data: validated,
        hash: aggregationSourceFingerprint(validated),
      });
    } else {
      lastEnvelope = currentEnvelope;
    }
    return validated;
  }

  /** Debounced-recompute entry point: single-flight (a compute already running absorbs
   * a new trigger as "run me again once you're done" rather than starting a second one
   * in parallel) and the only place `inFlight`/`lastError` are mutated. */
  function triggerRecompute(): Promise<T> {
    if (inFlight) {
      rerunRequested = true;
      return inFlight;
    }
    const run = computeAndPersist()
      .then((result) => {
        lastError = null;
        return result;
      })
      .catch((e: unknown) => {
        lastError = e instanceof Error ? e : new Error(String(e));
        throw lastError;
      })
      .finally(() => {
        inFlight = null;
        // Publish the settled state (success or failure) BEFORE possibly kicking off a
        // queued rerun below — a listener must see `computing: false` at least once
        // between two back-to-back recomputes, never a flag that stays stuck at `true`.
        notifyReactState();
        if (rerunRequested) {
          rerunRequested = false;
          triggerRecompute().catch((e) =>
            logBackgroundFailure("queued recompute failed", e),
          );
        }
      });
    inFlight = run;
    // Publish `computing: true` right away — the React binding (Task 4) must reflect a
    // recompute starting immediately, not only once it settles.
    notifyReactState();
    return run;
  }

  return {
    name,
    version: def.version,
    async get() {
      const { cryptoHandle, userId } = resolveAmbientIdentity(name);
      const { cache } = getSecureStoreConfig();
      if (!cache) {
        throw new Error(
          `defineAggregation(${name}).get(): no CacheAdapter configured — pass 'cache' to ` +
            `configureSecureStore() (aggregations need it to detect source writes without ` +
            `re-fetching every source on every read).`,
        );
      }
      ensureSubscribed(userId);

      // Deduped (see `loadEnvelopeDeduped`'s doc comment): several concurrently-mounted
      // `useAggregation(sameAgg)` instances calling `get()` at once must share ONE read of
      // this row, not one each.
      const { data: envelope } = await loadEnvelopeDeduped(
        userId,
        cryptoHandle,
      );
      lastEnvelope = envelope;

      if (envelope.data === null) {
        if (!inFlight) {
          triggerRecompute().catch((e) =>
            logBackgroundFailure("initial compute failed", e),
          );
        }
        notifyReactState();
        return { data: null, computing: true, stale: true, error: lastError };
      }

      const fresh = isFresh(envelope);
      if (!fresh && !inFlight) {
        triggerRecompute().catch((e) =>
          logBackgroundFailure("background recompute failed", e),
        );
      }
      notifyReactState();
      return {
        data: envelope.data,
        computing: inFlight !== null,
        stale: !fresh,
        error: lastError,
      };
    },
    async refresh() {
      resolveAmbientIdentity(name);
      if (debounceTimer) {
        clearTimeout(debounceTimer);
        debounceTimer = null;
      }
      return triggerRecompute();
    },
  };
}
