/**
 * onSourceWrite — a write-REACTION primitive, distinct from `defineAggregation`
 * (`./aggregation.ts`). See that file's own header for why: an aggregation
 * persists a DERIVED value (`optimisticLock: false` by design — a clobber just
 * rewrites the same result, never a real conflict). `onSourceWrite` instead
 * reacts to writes on a `KeyedStore` by calling an arbitrary app-supplied
 * `handler` that itself may read/mutate a DIFFERENT store with its OWN
 * `optimisticLock: true` semantics (e.g. `snapshotService.ts`'s monthly-snapshot
 * blob) — a real cross-writer conflict there is legitimate and MUST fail loud
 * (`OptimisticLockConflictError`), never be swallowed or silently retried away.
 * Wrapping that in `defineAggregation`'s internal `perKey` store would duplicate
 * persistence and throw away that lock. `onSourceWrite` never persists anything
 * itself — it only observes writes and invokes `handler`.
 *
 * Reuses the EXACT ambient-write interception `defineStore`'s `KeyedStore` already
 * has for `set()`/`mutate()`/`createMany()` — the `bumpRangeEpoch` call in
 * `store.ts` that every one of those three write paths already goes through for
 * `useKeyedStoreRange`'s cache invalidation. This module doesn't reinvent that
 * interception; it adds ONE more consumer of the exact same hook:
 * `keyedWriteKeysCacheKey` (`store.ts`), a `CacheAdapter` slot holding the domain
 * key(s) the MOST RECENT write touched, published by the same `bumpRangeEpoch`
 * call. See that function's doc comment for why "most recent" is safe (synchronous
 * subscriber notification).
 *
 * Debounce/coalesce (CT1): several writes to DIFFERENT keys inside `debounceMs`
 * accumulate into ONE `handler({ keys })` call carrying the union of keys, not one
 * call per write — e.g. an import batch touching 3 months schedules `handler`
 * once, not 3 times.
 *
 * Single-flight (CT2): a write arriving WHILE `handler` is still running for a
 * previous batch never starts a second concurrent `handler` call — its keys are
 * queued and `handler` runs exactly once more, with the queued keys, right after
 * the in-flight call settles (success OR failure). This is unconditional
 * (independent of `coalesce`): two concurrent `handler` invocations reacting to the
 * SAME store would risk exactly the self-inflicted optimistic-lock race this
 * module exists to avoid.
 *
 * Fail-loud (CT3): a rejected `handler` promise is NEVER caught-and-discarded here.
 * `onSourceWrite` runs `handler` in the background (there is no synchronous caller
 * to reject to — a write can happen anywhere, any time), so the ONLY place this
 * module ever touches a rejection is a single `.catch()` that logs the real Error
 * object loudly via `console.error` (never a stringified/truncated summary, never
 * a default value standing in for the failure) and otherwise lets it drop — the
 * exact same discipline `defineAggregation`'s `logBackgroundFailure` already
 * applies to ITS OWN background recomputes (Task 1). This is "rilancia, non
 * ingoiare silenziosamente" for a fire-and-forget reaction: the error is never
 * hidden, just not synchronously re-thrown to a caller that doesn't exist. State
 * (`inFlight`) is always cleared in `finally`, so the NEXT write (retry) always
 * starts a fresh `handler` call — never stuck because a previous one failed.
 *
 * IMPORTANT — call this AFTER `configureSecureStore()`, unlike `defineStore`/
 * `defineAggregation` (whose returned objects defer every config read to first
 * actual use — `.get()`/`.mutate()`/etc). `onSourceWrite` starts observing
 * immediately when called (there is no later "activate" call for an app to
 * trigger), so it needs `keys`/`cache` to already be wired. Register it once,
 * eagerly, at app bootstrap right after `configureSecureStore(...)` (see
 * `src/lib/secureStore.ts`) — calling it before that throws the same
 * "framework not configured" error `getSecureStoreConfig()` always throws.
 */
import { getSecureStoreConfig } from "./config.ts";
import { keyedWriteKeysCacheKey, type KeyedStore } from "./store.ts";

export type Unsubscribe = () => void;

export interface OnSourceWriteOptions {
  /** Coalescing window — see the file header's CT1 note. Default 500ms. */
  debounceMs?: number;
  /** `true` (default): debounce/coalesce writes inside `debounceMs` into one
   * `handler` call. `false`: dispatch `handler` immediately for every write
   * (still single-flight guarded — see the file header's CT2 note, which applies
   * regardless of this flag). */
  coalesce?: boolean;
}

export function onSourceWrite(
  store: KeyedStore<any>,
  handler: (ev: { keys: string[] }) => Promise<void>,
  opts?: OnSourceWriteOptions,
): Unsubscribe {
  const debounceMs = opts?.debounceMs ?? 500;
  const coalesce = opts?.coalesce ?? true;

  let pendingKeys = new Set<string>();
  let debounceTimer: ReturnType<typeof setTimeout> | null = null;
  let inFlight: Promise<void> | null = null;
  let rerunKeys: Set<string> | null = null;
  let subscribedUserId: string | null = null;
  let unsubCache: (() => void) | null = null;
  let disposed = false;

  function logFailure(context: string, e: unknown): void {
    // Never swallowed: the real Error (or thrown value) is always the second
    // argument, never re-stringified or replaced by a default — see the file
    // header's "Fail-loud (CT3)" note. Mirrors `defineAggregation`'s
    // `logBackgroundFailure` (Task 1), same package, same discipline.
    console.error(`onSourceWrite(${store.name}): ${context}:`, e);
  }

  /** Single-flight entry point (CT2) — the ONLY place `inFlight`/`rerunKeys` are
   * mutated. A call arriving while `inFlight` is set never starts a second
   * concurrent `handler` run; it merges its keys into `rerunKeys` and shares the
   * in-flight promise. Once that settles (success OR failure — `finally`), a
   * queued rerun fires exactly once more with the accumulated keys. */
  function runHandler(keys: string[]): Promise<void> {
    if (inFlight) {
      rerunKeys ??= new Set<string>();
      for (const k of keys) rerunKeys.add(k);
      return inFlight;
    }
    const run = handler({ keys }).finally(() => {
      inFlight = null;
      if (rerunKeys) {
        const next = [...rerunKeys];
        rerunKeys = null;
        runHandler(next).catch((e) => logFailure("queued rerun failed", e));
      }
    });
    inFlight = run;
    return run;
  }

  function dispatch(): void {
    const keys = [...pendingKeys];
    pendingKeys = new Set();
    if (!keys.length) return;
    runHandler(keys).catch((e) => logFailure("reaction failed", e));
  }

  function scheduleRun(): void {
    if (!coalesce) {
      dispatch();
      return;
    }
    if (debounceTimer) clearTimeout(debounceTimer);
    debounceTimer = setTimeout(() => {
      debounceTimer = null;
      dispatch();
    }, debounceMs);
  }

  /** (Re)subscribes to the CURRENT ambient user's write-keys slot — mirrors
   * `defineAggregation`'s `ensureSubscribed` re-subscribe-on-identity-change
   * handling (user switch/logout). `userId === null` (locked/logged out) just
   * tears down the previous subscription and observes nothing until a real
   * identity appears — no write can happen against this store while locked
   * anyway (every `KeyedStore` write resolves its own ambient identity and
   * throws `LockedSessionError` if it's missing), so there is nothing to miss. */
  function ensureSubscribed(userId: string | null): void {
    if (subscribedUserId === userId) return;
    unsubCache?.();
    unsubCache = null;
    subscribedUserId = userId;
    if (!userId) return;
    const { cache } = getSecureStoreConfig();
    if (!cache) return;
    const cacheKey = keyedWriteKeysCacheKey(store.name, userId);
    unsubCache = cache.subscribe(cacheKey, () => {
      if (disposed) return;
      const keys = cache.get<string[]>(cacheKey) ?? [];
      for (const k of keys) pendingKeys.add(k);
      scheduleRun();
    });
  }

  const { keys: keyProvider } = getSecureStoreConfig();
  if (!keyProvider) {
    throw new Error(
      `onSourceWrite(${store.name}): no KeyProvider configured — pass 'keys' to ` +
        `configureSecureStore() (this reaction needs the ambient identity to scope its ` +
        `write-keys cache subscription per user).`,
    );
  }
  ensureSubscribed(keyProvider.getUserId());
  const unsubIdentity = keyProvider.subscribe(() => {
    if (!disposed) ensureSubscribed(keyProvider.getUserId());
  });

  return () => {
    disposed = true;
    if (debounceTimer) clearTimeout(debounceTimer);
    debounceTimer = null;
    unsubCache?.();
    unsubCache = null;
    unsubIdentity();
  };
}
