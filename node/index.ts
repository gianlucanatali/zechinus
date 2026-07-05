/**
 * AsyncLocalStorage-based `KeyProvider` for Node scripts/services that must handle
 * MULTIPLE users concurrently — `configureSecureStore`'s ambient identity is a single
 * module-level variable, which is safe for a browser tab (exactly one user per tab)
 * but NOT safe for a Node process running, say, `Promise.all` over per-user jobs:
 * every ambient `store.get()`/`store.set()` call would see whichever identity was
 * configured last, across every in-flight promise chain.
 *
 * `withIdentity(userId, cryptoHandle, fn)` binds an identity to the current
 * `AsyncLocalStorage` context for the lifetime of `fn` — including every `await`
 * inside it and any promise chain it spawns. Each concurrent chain gets its own
 * isolated context, so two `withIdentity` calls run under `Promise.all` never see
 * each other's identity. Outside any `withIdentity` scope, `alsKeyProvider`'s getters
 * return `null`, so an ambient store call fails loud ("no active session (locked)")
 * instead of silently picking up a stale or foreign identity.
 *
 * CRITICAL packaging constraint: `node:async_hooks` must never reach the browser
 * bundle. This is a standalone entry point (`datacloak/node`) — never import it from
 * `datacloak/index.ts` or `datacloak/react/index.ts`.
 */
import { AsyncLocalStorage } from "node:async_hooks";
import type { CryptoHandle, KeyProvider } from "../core/types.ts";

interface AmbientIdentity {
  userId: string;
  cryptoHandle: CryptoHandle;
}

const als = new AsyncLocalStorage<AmbientIdentity>();

/** `KeyProvider` backed by `AsyncLocalStorage` — see the module doc comment above. */
export const alsKeyProvider: KeyProvider = {
  getCryptoHandle: () => als.getStore()?.cryptoHandle ?? null,
  getUserId: () => als.getStore()?.userId ?? null,
  // Identity is scope-bound for the lifetime of withIdentity() — it never "changes"
  // mid-scope, so there is nothing for a subscriber to be notified about.
  subscribe: () => () => {},
};

/**
 * Runs `fn` with `(userId, cryptoHandle)` bound as the ambient identity for every
 * `defineStore` call made inside it, isolated per promise chain — see the module
 * doc comment above for the concurrency guarantee this gives under `Promise.all`.
 */
export function withIdentity<T>(
  userId: string,
  cryptoHandle: CryptoHandle,
  fn: () => T,
): T {
  return als.run({ userId, cryptoHandle }, fn);
}
