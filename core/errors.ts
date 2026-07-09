/**
 * Thrown when a `saveIfMatch`/`updateIfMatch`-backed write reports a conflict
 * (`ok:false` — someone else wrote first). A distinct error type (not a generic
 * `Error`) so callers can `catch` it separately from a network/validation
 * failure and show "someone else edited this, reload" instead of a generic
 * "save failed". Framework-agnostic (no React import) — `mutate()` throws it
 * from plain service code just as `useStore()`'s `save()` does from React.
 */
export class OptimisticLockConflictError extends Error {
  constructor(storeName: string) {
    super(
      `${storeName}: optimistic lock conflict — someone else saved first, reload before retrying`,
    );
    this.name = "OptimisticLockConflictError";
  }
}

/** Thrown when an ambient store is called with no active session (vault locked). */
export class LockedSessionError extends Error {
  constructor(storeName: string) {
    super(`${storeName}: no active session (locked)`);
    this.name = "LockedSessionError";
  }
}

/**
 * Thrown by `defineAggregation`'s `computeAndPersist` when a downstream
 * aggregation reads an upstream one (as a `Source`) that has never itself
 * computed anything yet. A distinct type — not a generic `Error` — so
 * `triggerRecompute`'s background-retry-with-backoff (`core/aggregation.ts`)
 * can recognize and SKIP scheduling a retry for it: this case already
 * self-heals reactively, near-instantly, once the upstream's own
 * side-effect-triggered background compute publishes (see
 * `datacloak/AGENTS.md`'s "Aggregate-as-source cold start throws once, then
 * self-heals — this is expected, not a bug to fix with a retry loop"). Retrying
 * it on the SAME timer-based backoff built for transient I/O failures would be
 * redundant at best, and at worst produces the exact "retry storm" (multiple
 * logged cold-start failures instead of exactly one per aggregation) the
 * cold-start regression test in `aggregation.test.ts` guards against.
 */
export class ColdAggregationSourceError extends Error {
  constructor(
    aggregationName: string,
    sourceName: string,
    sourceAggName: string,
  ) {
    super(
      `defineAggregation(${aggregationName}): source aggregation "${sourceName}" (${sourceAggName}) ` +
        `has no persisted value yet — call its own get()/refresh() at least once ` +
        `before using it as a source for another aggregation.`,
    );
    this.name = "ColdAggregationSourceError";
  }
}
