/**
 * Re-exported here (not just from `zechinus/core`) so existing React consumers
 * (`useStore`/`useKeyedStore`/`useCollectionStore`) keep importing from
 * `zechinus/react` — the class itself is framework-agnostic, see
 * `core/errors.ts` for why `mutate()` (no React involved) throws it too.
 */
export { OptimisticLockConflictError } from "../core/errors.ts";
