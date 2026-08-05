/**
 * Zechinus config singleton (IoC model, Spring-style).
 *
 * The app calls `configureSecureStore(...)` ONCE at bootstrap, wiring the concrete
 * adapters (storage, and later cache/keys). Stores fetch the config lazily at
 * runtime via `getSecureStoreConfig()` — not at definition time — so
 * `defineBlobStore()` can be called at import-time before bootstrap runs.
 */

import type { CacheAdapter, KeyProvider, StorageAdapter } from "./types.ts";

export interface SecureStoreConfig {
  storage: StorageAdapter;
  /** Required only to use the React binding (`store.use()`). */
  keys?: KeyProvider;
  /** Required only to use the React binding (`store.use()`). */
  cache?: CacheAdapter;
}

let current: SecureStoreConfig | null = null;
let lockUnsubscribe: (() => void) | null = null;

export function configureSecureStore(config: SecureStoreConfig): void {
  current = config;
  lockUnsubscribe?.();
  lockUnsubscribe = null;
  // Auto-wire "wipe cache on lock": whenever the crypto handle transitions to null,
  // clear the cache once, centrally — not per `.use()` call, which would mean N
  // redundant clears for N mounted stores. This is the framework's job, not the app's.
  if (config.keys && config.cache) {
    const { keys, cache } = config;
    let wasUnlocked = keys.getCryptoHandle() !== null;
    lockUnsubscribe = keys.subscribe(() => {
      const isUnlocked = keys.getCryptoHandle() !== null;
      if (wasUnlocked && !isUnlocked) cache.clear();
      wasUnlocked = isUnlocked;
    });
  }
}

export function getSecureStoreConfig(): SecureStoreConfig {
  if (!current) {
    throw new Error(
      "secure-store: framework not configured — call configureSecureStore({ storage }) at app bootstrap",
    );
  }
  return current;
}

/** Test-only: resets the config between test cases. */
export function __resetSecureStoreConfig(): void {
  current = null;
  lockUnsubscribe?.();
  lockUnsubscribe = null;
}
