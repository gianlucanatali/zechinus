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
 * Fail-loud + retry-with-backoff (CT3): a rejected `handler` promise is NEVER
 * caught-and-discarded here. `onSourceWrite` runs `handler` in the background
 * (there is no synchronous caller to reject to — a write can happen anywhere, any
 * time), so every rejection always reaches a `.catch()` that logs the real Error
 * object loudly via `console.error` (never a stringified/truncated summary, never
 * a default value standing in for the failure) — the exact same discipline
 * `defineAggregation`'s `logBackgroundFailure` already applies to ITS OWN
 * background recomputes (Task 1). Logging alone isn't enough for a genuine
 * cross-writer `OptimisticLockConflictError`, though: the months of THAT failed
 * call must not just wait for luck (some unrelated future write happening to
 * touch the same months again) — they are requeued automatically with
 * exponential backoff (`scheduleRetry`, default 1s/2s/4s/8s/16s capped at 30s, up
 * to 5 attempts before giving up — both configurable via `opts.retry`). The
 * failing months (and the real error) are also exposed via the returned handle's
 * `getLastError()` for the whole time they remain unresolved — mirroring
 * `defineAggregation`'s `AggregationState.error` (there is no React binding
 * requirement for this primitive, but a caller/test must still be able to observe
 * "the last reaction failed and these months are not yet in sync"). If a NEW
 * write on the store arrives before a scheduled retry fires, its months are
 * folded into the SAME call as the still-pending failed months (`foldFailedKeysIntoNewWrite`)
 * — a real external write is a fresh opportunity, so the auto-retry budget resets
 * at that point. If the retry budget is exhausted with no new write ever coming,
 * the failure simply stays parked in `getLastError()` — visible, never silently
 * dropped — until either a future write folds it back in or the process using
 * this reaction inspects and handles it. `inFlight` is always cleared in
 * `finally`, so the next write/retry always starts a fresh `handler` call — never
 * stuck because a previous one failed.
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

/** Retry policy for a failed `handler` call — see the file header's
 * "Fail-loud + retry-with-backoff (CT3)" note. All fields optional; defaults are
 * a reasonable production posture (a handful of attempts, seconds-to-tens-of-
 * seconds backoff), not a real-time SLA — this reacts to a background snapshot
 * rebuild, not a user-facing synchronous action. */
export interface OnSourceWriteRetryOptions {
  /** Max consecutive failed attempts (the initial call PLUS auto-retries) for
   * the SAME failing batch before giving up and leaving it parked in
   * `getLastError()` — e.g. `2` means: initial call fails, ONE auto-retry is
   * scheduled, and if that also fails no further retry is scheduled. Default
   * 5. */
  maxAttempts?: number;
  /** Backoff delay before the FIRST automatic retry. Doubles every subsequent
   * attempt (1x, 2x, 4x, ...), capped at `maxDelayMs`. Default 1000ms. */
  baseDelayMs?: number;
  /** Upper bound for the exponential backoff delay. Default 30000ms. */
  maxDelayMs?: number;
}

export interface OnSourceWriteOptions {
  /** Coalescing window — see the file header's CT1 note. Default 500ms. */
  debounceMs?: number;
  /** `true` (default): debounce/coalesce writes inside `debounceMs` into one
   * `handler` call. `false`: dispatch `handler` immediately for every write
   * (still single-flight guarded — see the file header's CT2 note, which applies
   * regardless of this flag). */
  coalesce?: boolean;
  /** Retry-with-backoff policy for a failed `handler` call — see
   * `OnSourceWriteRetryOptions` and the file header's CT3 note. */
  retry?: OnSourceWriteRetryOptions;
}

/** The most recent unresolved (or exhausted) `handler` failure — mirrors
 * `defineAggregation`'s `AggregationState.error`, the same "surface the real
 * failure, don't just log-and-forget" discipline applied to a write-reaction
 * that has no synchronous caller and no React binding of its own. */
export interface OnSourceWriteFailure {
  /** The keys (months) of the failed call that are pending retry — or parked,
   * unresolved, if `exhausted` is `true`. */
  readonly keys: string[];
  /** The REAL error thrown by `handler` (e.g. `OptimisticLockConflictError`) —
   * never stringified, truncated, or replaced by a generic stand-in. */
  readonly error: Error;
  /** How many consecutive automatic retry attempts have been made for this
   * failure. Resets to 0 whenever a genuinely NEW write on the store folds these
   * keys into a fresh call (see `foldFailedKeysIntoNewWrite`) — only the
   * module's OWN back-to-back auto-retries count against `maxAttempts`. */
  readonly attempt: number;
  /** `true` once `maxAttempts` auto-retries have been exhausted with no success
   * — no further backoff timer is scheduled, but the failure (and its keys)
   * stays here, consultable, until a future write on the store retries it. */
  readonly exhausted: boolean;
}

/** `onSourceWrite`'s return value: callable as `Unsubscribe` (`handle()` tears
 * down the subscription), plus `getLastError()` to consult the state described
 * by `OnSourceWriteFailure` above. A plain function with one extra method,
 * exactly like `Unsubscribe` everywhere else in this codebase — no new
 * lifecycle, no React dependency. */
export interface OnSourceWriteHandle {
  (): void;
  /** The current pending-or-exhausted failure, if any — `null` once the
   * affected months have been successfully recomputed. */
  getLastError(): OnSourceWriteFailure | null;
}

const DEFAULT_MAX_RETRY_ATTEMPTS = 5;
const DEFAULT_RETRY_BASE_MS = 1_000;
const DEFAULT_RETRY_MAX_MS = 30_000;

export function onSourceWrite(
  store: KeyedStore<any>,
  handler: (ev: { keys: string[] }) => Promise<void>,
  opts?: OnSourceWriteOptions,
): OnSourceWriteHandle {
  const debounceMs = opts?.debounceMs ?? 500;
  const coalesce = opts?.coalesce ?? true;
  const maxRetryAttempts =
    opts?.retry?.maxAttempts ?? DEFAULT_MAX_RETRY_ATTEMPTS;
  const retryBaseMs = opts?.retry?.baseDelayMs ?? DEFAULT_RETRY_BASE_MS;
  const retryMaxMs = opts?.retry?.maxDelayMs ?? DEFAULT_RETRY_MAX_MS;

  let pendingKeys = new Set<string>();
  let debounceTimer: ReturnType<typeof setTimeout> | null = null;
  let inFlight: Promise<void> | null = null;
  let rerunKeys: Set<string> | null = null;
  let subscribedUserId: string | null = null;
  let unsubCache: (() => void) | null = null;
  let disposed = false;

  // ── Retry-with-backoff bookkeeping (CT3 fix) ──
  /** Months from the MOST RECENT failed `handler` call that have not yet been
   * successfully recomputed — requeued either by the scheduled `retryTimer` or
   * by folding into the next genuinely new write (`foldFailedKeysIntoNewWrite`).
   * Never silently dropped: cleared only on a successful `handler` run that
   * included them. */
  let failedKeys: Set<string> | null = null;
  /** Consecutive auto-retry attempts for the current `failedKeys` lineage. Reset
   * to 0 whenever a new write folds them into a fresh call (a real external
   * event, not our own backoff, is now driving the next attempt). */
  let retryAttempt = 0;
  let retryTimer: ReturnType<typeof setTimeout> | null = null;
  let lastError: OnSourceWriteFailure | null = null;

  function logFailure(context: string, e: unknown): void {
    // Never swallowed: the real Error (or thrown value) is always the second
    // argument, never re-stringified or replaced by a default — see the file
    // header's "Fail-loud + retry-with-backoff (CT3)" note. Mirrors
    // `defineAggregation`'s `logBackgroundFailure` (Task 1), same package, same
    // discipline.
    console.error(`onSourceWrite(${store.name}): ${context}:`, e);
  }

  /** Cancels any pending backoff timer and folds any still-unresolved failed
   * months into `target` (a fresh batch about to run right now because of a
   * REAL new write — not our own scheduled retry). This is a fresh opportunity,
   * so the auto-retry attempt budget resets: only back-to-back failures of the
   * module's OWN unattended backoff retries should count against
   * `maxAttempts`, not a failure that a genuine new write happens to also hit. */
  function foldFailedKeysIntoNewWrite(target: Set<string>): void {
    if (retryTimer) {
      clearTimeout(retryTimer);
      retryTimer = null;
    }
    if (!failedKeys) return;
    for (const k of failedKeys) target.add(k);
    failedKeys = null;
    retryAttempt = 0;
  }

  /** Records a failed `handler({keys})` call and schedules an automatic retry
   * with exponential backoff, unless `maxRetryAttempts` is already exhausted —
   * in which case the failure stays in `lastError`/`failedKeys` (consultable,
   * eligible to be folded into a future real write) but no further timer is
   * scheduled. Called from `runHandler`'s `.catch()`, so `keys` is exactly the
   * batch that just failed (already inclusive of any previously-failed months
   * folded in earlier — see `foldFailedKeysIntoNewWrite`, and the retry timer
   * below which drains `failedKeys` directly for a self-scheduled attempt). */
  function scheduleRetry(keys: string[], error: Error): void {
    failedKeys = new Set(keys);
    retryAttempt += 1;
    // `retryAttempt` counts this failure too (the very first call counts as
    // attempt 1) — `maxAttempts` is the total number of failed attempts
    // tolerated (initial + auto-retries) before giving up, so exhaustion is
    // reached once that many failures have happened, not one past it.
    const exhausted = retryAttempt >= maxRetryAttempts;
    lastError = {
      keys: [...failedKeys],
      error,
      attempt: retryAttempt,
      exhausted,
    };
    if (exhausted) {
      logFailure(
        `giving up automatic retry after ${maxRetryAttempts} attempts for ` +
          `months [${keys.join(", ")}] — these months remain UNSYNCED; the ` +
          `failure stays available via getLastError() until a future write on ` +
          `this store retries them`,
        error,
      );
      return;
    }
    if (disposed) return; // torn down mid-flight — nothing left to schedule for
    const delay = Math.min(retryBaseMs * 2 ** (retryAttempt - 1), retryMaxMs);
    retryTimer = setTimeout(() => {
      retryTimer = null;
      if (disposed || !failedKeys) return;
      const keysToRetry = [...failedKeys];
      failedKeys = null;
      runHandler(keysToRetry).catch((e) =>
        logFailure("scheduled retry failed", e),
      );
    }, delay);
  }

  /** Single-flight entry point (CT2) — the ONLY place `inFlight`/`rerunKeys` are
   * mutated. A call arriving while `inFlight` is set never starts a second
   * concurrent `handler` run; it merges its keys into `rerunKeys` and shares the
   * in-flight promise. Once that settles (success OR failure — `finally`), a
   * queued rerun fires exactly once more with the accumulated keys (folding in
   * any still-pending failed months first — CT3 fix).
   *
   * Cross-user isolation (reviewer finding, post-`c4b1530a`): `handler` resolves
   * its OWN ambient identity fresh at call time (e.g. `rebuildMonths` in
   * `src/lib/secureStore.ts` reads `KeyProvider.getUserId()` when it actually
   * runs, not when it was scheduled). Because JS is single-threaded, a
   * SCHEDULED `retryTimer`/`debounceTimer` is reliably cancelled by
   * `ensureSubscribed` the instant a genuine identity switch is observed (see
   * below) — it can never fire after the switch. The one case that survives a
   * switch regardless is a `handler` call that was ALREADY in flight
   * (awaiting inside `handler({keys})`) when the switch happened: its
   * `.then()`/`.catch()` only run once `handler`'s own promise settles, which
   * can be well after `ensureSubscribed` already rebound everything to the
   * new user. `callUserId` captures which identity this specific call was
   * dispatched for, so that settling logic below can tell "this result belongs
   * to a user we've since switched away from" and refuse to let it write into
   * the CURRENT (different) user's retry/error bookkeeping — the keys it
   * carries are never retried against a different identity, and its success
   * never clears a failure that may legitimately belong to the new user. */
  function runHandler(keys: string[]): Promise<void> {
    if (inFlight) {
      rerunKeys ??= new Set<string>();
      for (const k of keys) rerunKeys.add(k);
      return inFlight;
    }
    const callUserId = subscribedUserId;
    const run = handler({ keys })
      .then(() => {
        if (callUserId !== subscribedUserId) {
          // Stale success from a call dispatched for a PREVIOUS identity,
          // settling after a genuine user switch — must not clear the (new)
          // current identity's own lastError, which this result knows nothing
          // about.
          logFailure(
            `an in-flight call for a previous identity succeeded after an ` +
              `identity switch — ignoring it for retry/error bookkeeping ` +
              `(months [${keys.join(", ")}] belonged to that previous identity)`,
            new Error("identity switched while handler call was in flight"),
          );
          return;
        }
        // A successful call always includes whatever failed months were folded
        // into it (see `foldFailedKeysIntoNewWrite`, and the retry timer above) —
        // so any success clears the last failure, exactly like
        // `defineAggregation`'s `triggerRecompute` clears its own `lastError`.
        lastError = null;
      })
      .catch((e: unknown) => {
        const error = e instanceof Error ? e : new Error(String(e));
        if (callUserId !== subscribedUserId) {
          // CRITICAL cross-user isolation guard: never schedule a retry for
          // months that belonged to a DIFFERENT, already-switched-away-from
          // identity. `scheduleRetry` would otherwise arm a timer that later
          // calls `handler({keys})` while today's ambient identity is a
          // different (real, logged-in) user — `handler` would resolve THAT
          // user's fresh identity and silently recompute their snapshot using
          // the previous user's failed months. Log and drop instead: this is
          // a legitimate cancellation, not a lost error — the previous
          // identity's own failure was already logged when it was cleared in
          // `ensureSubscribed`.
          logFailure(
            `discarding failed months [${keys.join(", ")}] — the ambient ` +
              `identity switched away before this call settled; never retried ` +
              `against a different user`,
            error,
          );
          throw error;
        }
        scheduleRetry(keys, error);
        throw error;
      })
      .finally(() => {
        inFlight = null;
        if (rerunKeys) {
          const next = rerunKeys;
          rerunKeys = null;
          foldFailedKeysIntoNewWrite(next);
          runHandler([...next]).catch((e) =>
            logFailure("queued rerun failed", e),
          );
        }
      });
    inFlight = run;
    return run;
  }

  function dispatch(): void {
    const keys = pendingKeys;
    pendingKeys = new Set();
    foldFailedKeysIntoNewWrite(keys);
    if (!keys.size) return;
    runHandler([...keys]).catch((e) => logFailure("reaction failed", e));
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
   * throws `LockedSessionError` if it's missing), so there is nothing to miss.
   *
   * Cross-user isolation (reviewer finding, post-`c4b1530a`): on a GENUINE
   * identity change (we were subscribed to a real, non-null user and the
   * ambient identity is now something else — a same-tab user switch/logout,
   * e.g. `logout()` in `UserContext.tsx` does a plain React state reset with
   * NO page reload, and demo-persona switching is an established same-tab
   * flow too) every piece of state that is scoped to the OLD identity must be
   * discarded here, synchronously, BEFORE the new subscription is wired up:
   * `pendingKeys` (months queued but not yet dispatched), `debounceTimer` and
   * `retryTimer` (both cancelled — a scheduled retry that fires later would
   * call `handler({keys})` with the OLD identity's months while `handler`
   * resolves the fresh, NEW ambient identity, corrupting the new user's
   * snapshot), and `failedKeys`/`retryAttempt`/`lastError` (the old identity's
   * retry/error bookkeeping — never carried over to the new user, who has no
   * such failure). `rerunKeys` is cleared too, for the same reason: those are
   * months queued to rerun once the currently in-flight call settles, and they
   * belong to the OLD identity. None of this is a silent drop — it's logged
   * via `logFailure` below so the cancellation is visible, not swallowed. An
   * in-flight `handler` call already running for the old identity can't be
   * cancelled here (JS can't abort a promise it doesn't own) — that case is
   * guarded separately in `runHandler`'s `.then()`/`.catch()` via
   * `callUserId`, so its eventual settlement can never write into the NEW
   * identity's bookkeeping either. */
  function ensureSubscribed(userId: string | null): void {
    if (subscribedUserId === userId) return;
    const isGenuineSwitch = subscribedUserId !== null;
    unsubCache?.();
    unsubCache = null;
    if (isGenuineSwitch) {
      pendingKeys = new Set();
      if (debounceTimer) {
        clearTimeout(debounceTimer);
        debounceTimer = null;
      }
      if (retryTimer) {
        clearTimeout(retryTimer);
        retryTimer = null;
      }
      if (failedKeys) {
        logFailure(
          `discarding pending retry state for identity "${subscribedUserId}" on ` +
            `switch to "${userId}" — months [${[...failedKeys].join(", ")}] were ` +
            `never recomputed for that identity and will NOT be retried against ` +
            `the new one`,
          lastError?.error ??
            new Error(
              `identity switched from "${subscribedUserId}" to "${userId}" before retry completed`,
            ),
        );
      }
      failedKeys = null;
      retryAttempt = 0;
      lastError = null;
      rerunKeys = null;
    }
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

  const unsubscribe = (): void => {
    disposed = true;
    if (debounceTimer) clearTimeout(debounceTimer);
    debounceTimer = null;
    if (retryTimer) clearTimeout(retryTimer);
    retryTimer = null;
    unsubCache?.();
    unsubCache = null;
    unsubIdentity();
  };
  const handle = unsubscribe as OnSourceWriteHandle;
  handle.getLastError = () => lastError;
  return handle;
}
