/**
 * DataCloak React binding — separate sub-entry (`datacloak/react`) so importing the
 * core (`datacloak`) never pulls React into a non-React consumer's module graph.
 */
export { useStore, type UseStoreResult } from "./useStore.ts";
export { useIsUnlocked } from "./useIsUnlocked.ts";
export { useKeyedStore, type UseKeyedStoreResult } from "./useKeyedStore.ts";
export {
  useCollectionStore,
  type UseCollectionStoreResult,
} from "./useCollectionStore.ts";
export { tanstackAdapter } from "../adapters/tanstackAdapter.ts";
export { OptimisticLockConflictError } from "./errors.ts";
export { usePasskeyDek, type UsePasskeyDekResult } from "./usePasskeyDek.ts";
export { useAutoLock } from "./useAutoLock.ts";
export {
  useDevDekInjection,
  type UseDevDekInjectionOptions,
} from "./useDevDekInjection.ts";
