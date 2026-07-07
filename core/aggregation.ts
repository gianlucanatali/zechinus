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
 * NOT in this file (later tasks, see the plan): an `Aggregation` as a `sources` entry
 * (Task 2 — `Source` below is deliberately widenable to accommodate it without a breaking
 * change), the declarative `FieldOperators` form of `compute` (Task 3 — `compute`'s type
 * here is only the pure-function form, see `ComputeFn`'s doc comment), the React binding
 * (Task 4), and `onSourceWrite` (Task 6 — a different primitive, for a write-REACTION,
 * not an aggregate).
 */

import { z } from "zod";
import { defineStore, type Store, type KeyedStore } from "./store.ts";
import { getSecureStoreConfig } from "./config.ts";
import { fingerprintSchema } from "./schemaFingerprint.ts";
import { LockedSessionError } from "./errors.ts";
import type { CryptoHandle } from "./types.ts";

/**
 * A non-store input to `compute()` — e.g. a market-data API call — refreshed on its own
 * TTL rather than in reaction to a store write (there is no "write" to detect).
 */
export interface ExternalInput<T = unknown> {
  load: () => Promise<T>;
  ttlMs: number;
}

/**
 * What an aggregation can read from. In this task, only a `perUser` `Store` — reading
 * from ANOTHER `Aggregation` (opt-in DAG composition, e.g. a dashboard aggregate sourcing
 * an already-computed portfolio-history aggregate) is Task 2. The generic constraint
 * below (`Record<string, Source>`) is what widens there — to
 * `Record<string, Store<any> | Aggregation<any>>` — without touching any existing caller.
 */
export type Source = Store<any>;

type SourceData<S> = S extends Store<infer D> ? D : never;
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
 * `compute`'s public type is deliberately ONLY the pure-function form for now. Task 3's
 * declarative operator kit (`sum`/`sumWith`/`expr`/`lastDelta`/`custom`) compiles down to
 * this exact same shape ("the core doesn't distinguish the two forms" — see the plan), so
 * widening this to a union (`ComputeFn<...> | FieldOperators<...>`) later is additive, not
 * a breaking change for anything written against this signature today.
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
  compute: ComputeFn<TSchema, TSources, TExt>;
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

  async function computeAndPersist(): Promise<T> {
    const { cryptoHandle, userId } = resolveAmbientIdentity(name);

    const sourceEntries = await Promise.all(
      Object.entries(def.sources).map(async ([sourceName, source]) => {
        const { data, hash } = source.loadWithHash
          ? await source.loadWithHash(userId, cryptoHandle)
          : { data: await source.load(userId, cryptoHandle), hash: null };
        return [sourceName, data, hash] as const;
      }),
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
    const rawResult = await def.compute({
      sources: sourcesData,
      externals: externalsData as ExternalsOf<TExt>,
    });
    const validated = def.schema.parse(rawResult) as T;

    const { data: currentEnvelope } = await internalStore.loadWithHash!(
      userId,
      cryptoHandle,
      def.storage.key,
    );
    const unchanged =
      currentEnvelope.data !== null &&
      JSON.stringify(currentEnvelope.data) === JSON.stringify(validated);
    if (!unchanged) {
      const envelope: PersistedEnvelope<T> = {
        v: def.version,
        computedAt: new Date().toISOString(),
        sourceFingerprints,
        externalsFetchedAt,
        data: validated,
      };
      await internalStore.save(userId, cryptoHandle, def.storage.key, envelope);
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
        if (rerunRequested) {
          rerunRequested = false;
          triggerRecompute().catch((e) =>
            logBackgroundFailure("queued recompute failed", e),
          );
        }
      });
    inFlight = run;
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

      const { data: envelope } = await internalStore.loadWithHash!(
        userId,
        cryptoHandle,
        def.storage.key,
      );

      if (envelope.data === null) {
        if (!inFlight) {
          triggerRecompute().catch((e) =>
            logBackgroundFailure("initial compute failed", e),
          );
        }
        return { data: null, computing: true, stale: true, error: lastError };
      }

      const fresh = isFresh(envelope);
      if (!fresh && !inFlight) {
        triggerRecompute().catch((e) =>
          logBackgroundFailure("background recompute failed", e),
        );
      }
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
