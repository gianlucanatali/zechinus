/**
 * React binding exposing ONLY the boolean unlocked/locked state, never the
 * `CryptoHandle` itself — for the (common) case where a caller needs to gate on
 * lock state but never touches the key material. Same source of truth as
 * `useStore`/`usePasskeyDek` (`keys.getCryptoHandle()`/`keys.subscribe`), just
 * narrowed to a boolean so consumers never see a handle they don't need.
 */
import { useSyncExternalStore } from "react";
import { getSecureStoreConfig } from "../core/config.ts";

export function useIsUnlocked(): boolean {
  const { keys } = getSecureStoreConfig();
  if (!keys) {
    throw new Error(
      "useIsUnlocked(): no KeyProvider configured — pass 'keys' to configureSecureStore()",
    );
  }
  return useSyncExternalStore(
    keys.subscribe,
    () => keys.getCryptoHandle() !== null,
  );
}
