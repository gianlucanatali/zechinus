/**
 * Tests the React binding (`useIsUnlocked`). Needs jsdom + React rendering — runs
 * under Vitest (`npm run test:components`), unlike the rest of zechinus/'s tests
 * which run under plain `node --test` (see config/vitest.config.ts).
 */
import { describe, it, expect, afterEach } from "vitest";
import { cleanup, renderHook, act } from "@testing-library/react";
import { randomBytes } from "@noble/ciphers/utils.js";

import { createDekHandle } from "./testKeyHandle.ts";
import {
  configureSecureStore,
  __resetSecureStoreConfig,
  type CryptoHandle,
  type KeyProvider,
} from "../index.ts";
import { useIsUnlocked } from "../react/useIsUnlocked.ts";

function memoryStorage() {
  return {
    async get() {
      return null;
    },
    async put() {},
  };
}

function fakeKeys(initial: CryptoHandle | null) {
  let cryptoHandle = initial;
  const subs = new Set<() => void>();
  const provider: KeyProvider = {
    getCryptoHandle: () => cryptoHandle,
    getUserId: () => (cryptoHandle ? "u1" : null),
    subscribe(cb) {
      subs.add(cb);
      return () => subs.delete(cb);
    },
  };
  return {
    provider,
    setDek(next: CryptoHandle | null) {
      cryptoHandle = next;
      for (const cb of subs) cb();
    },
  };
}

describe("useIsUnlocked", () => {
  afterEach(() => {
    cleanup();
    __resetSecureStoreConfig();
  });

  it("throws when no KeyProvider is configured", () => {
    configureSecureStore({ storage: memoryStorage() });
    expect(() => renderHook(() => useIsUnlocked())).toThrow(/KeyProvider/);
  });

  it("returns false when keys.getCryptoHandle() is null", () => {
    const { provider } = fakeKeys(null);
    configureSecureStore({ storage: memoryStorage(), keys: provider });

    const { result } = renderHook(() => useIsUnlocked());

    expect(result.current).toBe(false);
  });

  it("returns true when there is a crypto handle", () => {
    const cryptoHandle = createDekHandle(randomBytes(32));
    const { provider } = fakeKeys(cryptoHandle);
    configureSecureStore({ storage: memoryStorage(), keys: provider });

    const { result } = renderHook(() => useIsUnlocked());

    expect(result.current).toBe(true);
  });

  it("updates reactively when the KeyProvider notifies a change via subscribe", () => {
    const { provider, setDek } = fakeKeys(null);
    configureSecureStore({ storage: memoryStorage(), keys: provider });

    const { result } = renderHook(() => useIsUnlocked());
    expect(result.current).toBe(false);

    act(() => {
      setDek(createDekHandle(randomBytes(32)));
    });
    expect(result.current).toBe(true);

    act(() => {
      setDek(null);
    });
    expect(result.current).toBe(false);
  });
});
