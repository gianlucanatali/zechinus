/**
 * Re-exported here (not just from `datacloak/core`) so existing React consumers
 * (`useStore`/`useKeyedStore`/`useCollectionStore`) keep importing from
 * `datacloak/react` — the class itself is framework-agnostic, see
 * `core/errors.ts` for why `mutate()` (no React involved) throws it too.
 */
export { OptimisticLockConflictError } from "../core/errors.ts";
