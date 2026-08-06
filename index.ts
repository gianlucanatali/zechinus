/**
 * Zechinus secure-store framework — public entry point.
 *
 * This barrel is React-free by design — the React binding lives at `zechinus/react`
 * (`react/index.ts`), a separate sub-entry, so importing `zechinus` in a non-React
 * context (backend, Deno, a future non-React consumer) never pulls React into the
 * module graph. `KeyProvider`/`CacheAdapter` are plain interfaces (no React types),
 * so they stay exported here.
 *
 * See `docs/limitations.md` for current status and scope — the single source of truth
 * for gaps; this file header used to duplicate it and drifted out of sync, so it no
 * longer tries to.
 *
 * This barrel exports ONLY `core/` — zero adapters. Every adapter (`supabaseStorageAdapter`,
 * `pgStorageAdapter`, `webauthnKeyProvider`, `mnemonicRecovery`, `workerKeyHandle`,
 * `tanstackAdapter`) is optional and pulls in its own dependency (Supabase, a Postgres
 * driver, the WebAuthn browser API, TanStack Query) — importing `zechinus` for just
 * `defineStore` must never drag those into the module graph. Import an adapter from its
 * own file: `zechinus/adapters/storage/supabaseStorageAdapter.ts`,
 * `zechinus/adapters/storage/pgStorageAdapter.ts`, etc. See
 * `docs/key-management.md` § "Architecture: the ports".
 */

export {
  configureSecureStore,
  getSecureStoreConfig,
  __resetSecureStoreConfig,
  type SecureStoreConfig,
} from "./core/config.ts";

export {
  defineBlobStore,
  type BlobStore,
  type BlobStoreDef,
} from "./core/blobStore.ts";

export {
  defineStore,
  type Store,
  type KeyedStore,
  type CollectionStore,
  type StoreDef,
  type Identity,
} from "./core/store.ts";

export {
  LockedSessionError,
  OptimisticLockConflictError,
} from "./core/errors.ts";

export {
  enc,
  isEncryptedSchema,
  collectEncryptedKeys,
} from "./core/encryption.ts";

export { fingerprintSchema } from "./core/schemaFingerprint.ts";

export { canonicalAAD } from "./core/rowStore.ts";

export {
  migrateLegacyAAD,
  type LegacyMigrationResult,
} from "./core/legacyMigration.ts";

export {
  defineLabelDict,
  type LabelDict,
  type LabelDictDef,
} from "./core/defineLabelDict.ts";

export {
  defineAggregation,
  keyedSource,
  invalidateChannel,
  isAnyAggregationComputing,
  subscribeGlobalAggregationActivity,
  __resetGlobalAggregationActivity,
  type Aggregation,
  type AggregationDef,
  type AggregationState,
  type Source,
  type KeyedSourceRef,
  type ExternalInput,
  type DataOf,
  type ExternalsOf,
  type ComputeFn,
} from "./core/aggregation.ts";

export {
  onSourceWrite,
  type OnSourceWriteOptions,
  type OnSourceWriteRetryOptions,
  type OnSourceWriteFailure,
  type OnSourceWriteHandle,
  type Unsubscribe,
} from "./core/onSourceWrite.ts";

export type {
  StorageAdapter,
  BlobRecord,
  KeyProvider,
  CacheAdapter,
  CryptoHandle,
  FieldAAD,
  EncryptedField,
} from "./core/types.ts";

export { type BlobMigrator } from "./core/versioning.ts";

export {
  deriveKey,
  derivePID,
  wrapKey,
  unwrapKey,
  createKeyHandle,
  asRawDekBytes,
  bindKeyHandleFactory,
  type KeyHandle,
  type WrappedKey,
  type RawDekBytes,
} from "./core/keyDerivation.ts";

export { setGzipImpl, type GzipImpl } from "./core/gzip.ts";
