/**
 * Thrown by `useStore`/`useKeyedStore`/`useCollectionStore`'s write methods when the
 * underlying `saveIfMatch`/`updateIfMatch` reports a conflict (`ok:false` — someone
 * else wrote first). A distinct error type (not a generic `Error`) so callers can
 * `catch` it separately from a network/validation failure and show "someone else
 * edited this, reload" instead of a generic "save failed".
 */
export class OptimisticLockConflictError extends Error {
  constructor(storeName: string) {
    super(
      `${storeName}: optimistic lock conflict — someone else saved first, reload before retrying`,
    );
    this.name = "OptimisticLockConflictError";
  }
}
