import assert from "node:assert/strict";
import test from "node:test";
import {
  configureSecureStore,
  __resetSecureStoreConfig,
} from "../core/config.ts";
import type {
  CacheAdapter,
  KeyProvider,
  StorageAdapter,
} from "../core/types.ts";
import type { CryptoHandle } from "../index.ts";

function fakeStorage(): StorageAdapter {
  return {
    async get() {
      return null;
    },
    async put() {
      /* noop */
    },
  };
}

// Only presence/absence of the dek matters for these tests, never its crypto methods —
// a minimal `{ pid }` stand-in cast to CryptoHandle is safe here (no encrypt/decrypt call).
function fakeKeys(initialDek: { pid: string } | null) {
  let dek = initialDek as CryptoHandle | null;
  const subs = new Set<() => void>();
  const provider: KeyProvider = {
    getDek: () => dek,
    getUserId: () => (dek ? "u1" : null),
    subscribe(cb) {
      subs.add(cb);
      return () => subs.delete(cb);
    },
  };
  return {
    provider,
    setDek(next: { pid: string } | null) {
      dek = next as CryptoHandle | null;
      for (const cb of subs) cb();
    },
  };
}

function fakeCache() {
  let cleared = 0;
  const cache: CacheAdapter = {
    getQueryData: () => undefined,
    setQueryData: () => {},
    subscribe: () => () => {},
    clear: () => {
      cleared++;
    },
  };
  return { cache, clearedCount: () => cleared };
}

test("configureSecureStore: clears the cache exactly once when the DEK locks (non-null → null)", () => {
  const { provider, setDek } = fakeKeys({ pid: "p1" });
  const { cache, clearedCount } = fakeCache();

  configureSecureStore({ storage: fakeStorage(), keys: provider, cache });
  assert.equal(clearedCount(), 0);

  setDek(null);
  assert.equal(clearedCount(), 1);

  // further notifications while still locked don't clear again
  setDek(null);
  assert.equal(clearedCount(), 1);
});

test("configureSecureStore: unlocking (null → non-null) does NOT clear the cache", () => {
  const { provider, setDek } = fakeKeys(null);
  const { cache, clearedCount } = fakeCache();

  configureSecureStore({ storage: fakeStorage(), keys: provider, cache });
  setDek({ pid: "p1" });

  assert.equal(clearedCount(), 0);
});

test("configureSecureStore: without keys/cache, no subscription is attempted (no throw)", () => {
  assert.doesNotThrow(() => configureSecureStore({ storage: fakeStorage() }));
});

test("configureSecureStore: re-configuring unsubscribes the previous keys.subscribe", () => {
  const { provider: provider1, setDek: setDek1 } = fakeKeys({ pid: "p1" });
  const { cache: cache1, clearedCount: cleared1 } = fakeCache();
  configureSecureStore({
    storage: fakeStorage(),
    keys: provider1,
    cache: cache1,
  });

  // reconfigure with a totally different pair
  const { provider: provider2 } = fakeKeys({ pid: "p2" });
  const { cache: cache2 } = fakeCache();
  configureSecureStore({
    storage: fakeStorage(),
    keys: provider2,
    cache: cache2,
  });

  // the OLD provider locking must not affect the old cache anymore (unsubscribed)
  setDek1(null);
  assert.equal(cleared1(), 0);
});

test.after(() => __resetSecureStoreConfig());
