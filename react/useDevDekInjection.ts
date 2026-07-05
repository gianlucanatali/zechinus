/**
 * Dev/E2E DEK injection — any app doing zero-knowledge E2E encryption with a
 * ceremony that needs a real device (WebAuthn passkey) hits the same wall in
 * headless test runners: there is no passkey to authenticate with. The standard
 * escape hatch is a dev-only global that lets a test set the raw key material
 * directly, bypassing the ceremony entirely — this hook is that escape hatch,
 * generalized so every app doesn't reinvent it.
 *
 * Exposes `window.<setName>(hexKey)` / `window.<clearName>()` while `enabled`,
 * and persists the injected bytes in `sessionStorage` so a full page navigation
 * (common in E2E flows) doesn't lose the test DEK — restored automatically on
 * mount if no real dek is active yet.
 */
import { useEffect } from "react";
import { asRawDekBytes, type KeyHandle } from "../core/keyDerivation.ts";
import type { PasskeyDekController } from "../adapters/passkeyDekController.ts";

const STORAGE_KEY = "__testDek__";

export interface UseDevDekInjectionOptions {
  /** Gate — the caller decides what "dev mode" means (e.g. `import.meta.env.DEV`). Default `false`. */
  enabled?: boolean;
  /** window property name for injection. Default `"__setTestDek"`. */
  setName?: string;
  /** window property name for clearing. Default `"__clearTestDek"`. */
  clearName?: string;
  /** Called after `__clearTestDek` runs, e.g. to also clear an app-level cache. */
  onLock?: () => void;
}

function hexToBytes(hex: string): Uint8Array {
  const pairs = hex.match(/.{1,2}/g);
  if (!pairs) throw new Error(`useDevDekInjection: invalid hex key "${hex}"`);
  return new Uint8Array(pairs.map((byte) => parseInt(byte, 16)));
}

export function useDevDekInjection(
  controller: PasskeyDekController,
  userId: string | null,
  cryptoHandle: KeyHandle | null,
  {
    enabled = false,
    setName = "__setTestDek",
    clearName = "__clearTestDek",
    onLock,
  }: UseDevDekInjectionOptions = {},
): void {
  useEffect(() => {
    if (!enabled) return;
    const w = window as unknown as Record<string, unknown>;
    w[setName] = async (hexKey: string) => {
      if (!userId)
        throw new Error(`${setName}: no active user id to inject a DEK for`);
      const bytes = hexToBytes(hexKey);
      // Persisted BEFORE setDek: a Worker-isolated createHandle wipes the raw
      // bytes as soon as the handoff completes, so this is the last safe point.
      sessionStorage.setItem(STORAGE_KEY, JSON.stringify([...bytes]));
      await controller.setDek(userId, asRawDekBytes(bytes));
    };
    w[clearName] = () => {
      controller.lock();
      sessionStorage.removeItem(STORAGE_KEY);
      onLock?.();
    };
    return () => {
      delete w[setName];
      delete w[clearName];
    };
  }, [enabled, setName, clearName, userId, controller, onLock]);

  useEffect(() => {
    if (!enabled) return;
    if (cryptoHandle) return;
    if (!userId) return;
    const stored = sessionStorage.getItem(STORAGE_KEY);
    if (!stored) return;
    const bytes = new Uint8Array(JSON.parse(stored));
    controller.setDek(userId, asRawDekBytes(bytes)).catch(console.error);
  }, [enabled, userId, cryptoHandle, controller]);
}
