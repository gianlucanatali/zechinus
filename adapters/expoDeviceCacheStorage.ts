/**
 * The REAL `DeviceKeyStore`/`DeviceBlobStore` ports backing
 * `mobilePersistentCacheAdapter` on Expo/React Native, plus the convenience factory
 * `expoPersistentCacheAdapter()` that wires them together into a `CacheAdapter` ready
 * for `configureSecureStore({ cache })`.
 *
 * RN-ONLY FILE — imports `expo-secure-store`/`expo-file-system`, packages that only
 * exist in the `mobile/` workspace's own `node_modules` (npm workspace hoisting
 * placed them there, not at the repo root — `zechinus/`'s own module resolution
 * can't see them). This is why `mobilePersistentCacheAdapter.ts` itself has ZERO
 * RN dependencies and is fully Node-testable: this file is the thin, untested-by-
 * `node --test` glue on top of it, the same "ports tested with fakes, real adapter
 * wired separately" split `webauthnKeyProvider.ts` uses for `navigator.credentials`
 * (see that file's test doc comment for the same reasoning).
 *
 * Deliberately excluded from `zechinus/tsconfig.json` (see that file's `exclude`)
 * for the same reason it can't be imported from `zechinus/tests/`: `tsc -p
 * zechinus/tsconfig.json` runs from the repo root, which can't resolve
 * `expo-secure-store`/`expo-file-system` either. Real typecheck coverage for this
 * file happens once `mobile/`'s own bootstrap imports it (a later milestone task —
 * see the mobile plan's F0.5 entry) and `cd mobile && npx tsc --noEmit` picks it up
 * through mobile's own `node_modules`. Until then, verify manually against the
 * installed Expo SDK's real `.d.ts` files (as this implementation was written) —
 * never against training-data assumptions about the API shape (see `mobile/AGENTS.md`).
 *
 * SecureStore is used ONLY for the small device-local symmetric key (base64, ~44
 * chars) — well within its per-item size limit. The (potentially large) encrypted
 * cache entries themselves go to `expo-file-system`, one file per cache key, under
 * the app's document directory. Neither SecureStore nor these files are readable
 * without this specific device's Keychain/Keystore — see
 * `mobilePersistentCacheAdapter.ts`'s file-level doc comment for why this
 * device-local encryption exists on top of Zechinus's own E2E encryption.
 */
import * as SecureStore from "expo-secure-store";
import { Directory, File, Paths } from "expo-file-system";
import {
  mobilePersistentCacheAdapter,
  type DeviceKeyStore,
  type DeviceBlobStore,
  type MobilePersistentCacheAdapter,
} from "./mobilePersistentCacheAdapter.ts";

/** SecureStore key name for the device-local symmetric cache-encryption key. */
const SECURE_STORE_KEY_NAME = "zechinus_mobile_cache_dek_v1";

/** Directory (under the app's document directory) holding one file per cache entry. */
const CACHE_DIR_NAME = "zechinus-persistent-cache";

function cacheDirectory(): Directory {
  return new Directory(Paths.document, CACHE_DIR_NAME);
}

/**
 * Cache keys are opaque strings Zechinus's core constructs (`<storeName>:<userId>`)
 * — hex-encode them into filesystem-safe filenames rather than assuming `:`/other
 * characters are safe on every platform/filesystem.
 */
function encodeFileName(cacheKey: string): string {
  const bytes = new TextEncoder().encode(cacheKey);
  let hex = "";
  for (const byte of bytes) hex += byte.toString(16).padStart(2, "0");
  return `${hex}.bin`;
}

function decodeFileName(fileName: string): string {
  const hex = fileName.endsWith(".bin") ? fileName.slice(0, -4) : fileName;
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return new TextDecoder().decode(bytes);
}

const expoSecureStoreKeyStore: DeviceKeyStore = {
  async getKey() {
    return (await SecureStore.getItemAsync(SECURE_STORE_KEY_NAME)) ?? null;
  },
  async setKey(base64Key: string) {
    await SecureStore.setItemAsync(SECURE_STORE_KEY_NAME, base64Key);
  },
  async deleteKey() {
    await SecureStore.deleteItemAsync(SECURE_STORE_KEY_NAME);
  },
};

const expoFileBlobStore: DeviceBlobStore = {
  async readAll() {
    const dir = cacheDirectory();
    if (!dir.exists) return {};
    const entries: Record<string, string> = {};
    for (const item of dir.list()) {
      if (item instanceof File) {
        entries[decodeFileName(item.name)] = await item.text();
      }
    }
    return entries;
  },
  async write(cacheKey: string, ciphertextBase64: string) {
    const dir = cacheDirectory();
    if (!dir.exists) dir.create({ intermediates: true, idempotent: true });
    const file = new File(dir, encodeFileName(cacheKey));
    file.write(ciphertextBase64);
  },
  async clear() {
    const dir = cacheDirectory();
    if (dir.exists) dir.delete();
  },
};

/**
 * Ready-to-use `CacheAdapter` for `configureSecureStore({ cache })` on Expo/React
 * Native — Expo-backed `DeviceKeyStore`/`DeviceBlobStore` wired into
 * `mobilePersistentCacheAdapter`. NOT wired into any mobile bootstrap yet (that's a
 * later milestone task, per the mobile plan's F0.5 entry) — this factory is the
 * finished, ready-to-import piece for when that wiring happens.
 */
export function expoPersistentCacheAdapter(): MobilePersistentCacheAdapter {
  return mobilePersistentCacheAdapter({
    keyStore: expoSecureStoreKeyStore,
    blobStore: expoFileBlobStore,
    onPersistError: (error) => {
      // Loud, never silent (AGENTS.md's "never swallow" rule) — console.error is the
      // right sink for a fire-and-forget failure here: it surfaces in Metro/device
      // logs (and to whatever crash reporter is wired later), without blocking or
      // crashing the synchronous CacheAdapter caller.
      console.error(error);
    },
  });
}
