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
