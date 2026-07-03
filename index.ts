/**
 * DataCloak secure-store framework — public entry point (initial slice).
 *
 * This barrel is React-free by design — the React binding lives at `@datacloak/react`
 * (`react/index.ts`), a separate sub-entry, so importing `@datacloak` in a non-React
 * context (backend, Deno, a future non-React consumer) never pulls React into the
 * module graph. `KeyProvider`/`CacheAdapter` are plain interfaces (no React types),
 * so they stay exported here.
 *
 * Status: blob mode + IoC config + StorageAdapter (Supabase + plain Postgres adapters) +
 * versioning (migrator count + schema fingerprint guardrails) + React binding
 * (`@datacloak/react`, perUser only so far). Coming: hub-and-spoke adapter, perKey/many
 * bindings, key lifecycle (passkey/PRF + recovery). See README.md.
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
  enc,
  isEncryptedSchema,
  collectEncryptedKeys,
} from "./core/encryption.ts";

export { fingerprintSchema } from "./core/schemaFingerprint.ts";

export {
  migrateLegacyAAD,
  type LegacyMigrationResult,
} from "./core/legacyMigration.ts";

export {
  defineLabelDict,
  type LabelDict,
  type LabelDictDef,
} from "./core/defineLabelDict.ts";

export type {
  StorageAdapter,
  BlobRecord,
  KeyProvider,
  CacheAdapter,
} from "./core/types.ts";

export {
  toEnvelope,
  fromEnvelope,
  runMigrations,
  type BlobMigrator,
  type BlobMigrationResult,
  type VersionedEnvelope,
} from "./core/versioning.ts";

export { supabaseStorageAdapter } from "./adapters/supabaseStorageAdapter.ts";
export {
  pgStorageAdapter,
  type PgClient,
} from "./adapters/pgStorageAdapter.ts";
