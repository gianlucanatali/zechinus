/**
 * Persistent `CacheAdapter` for the mobile workspace (Expo/React Native) — the
 * offline-read counterpart to `tanstackAdapter` (in-memory only, web). `get`/`set`
 * stay synchronous (the `CacheAdapter` contract, `core/types.ts`), backed by an
 * in-memory `Map` exactly like `tanstackAdapter`; on top of that mirror, every
 * `set()` fires an asynchronous, encrypted write-through to device-local storage
 * (fire-and-forget — it must never block the synchronous caller), and construction
 * kicks off an asynchronous hydration pass that repopulates the in-memory mirror
 * from whatever was persisted in a previous session, so a cold app launch can paint
 * from last-known data before any network round trip completes.
 *
 * IMPORTANT — this is a DEVICE-LOCAL encryption layer, orthogonal to DataCloak's own
 * E2E encryption (the per-user DEK / AAD machinery in `core/crypto.ts`). The cache
 * already holds DECRYPTED (plaintext) values by the time `store.ts` calls
 * `cache.set()` (see `core/store.ts`'s `loadRevalidated`) — persisting that to disk
 * as-is would leak plaintext to the filesystem. This adapter re-encrypts each entry
 * under a symmetric key that itself lives only on this device (never transmitted,
 * never derived from the user's real DEK), so the on-disk cache is unreadable
 * without physical/OS-level access to this specific device's secure key storage.
 * Losing/rotating that device key (see `clear()`) makes every persisted entry
 * permanently undecryptable — exactly the property `clear()` needs at lock time.
 *
 * Deliberately port-based (`DeviceKeyStore`/`DeviceBlobStore`), the same
 * ports-not-concrete-APIs shape as `StorageAdapter`/`KeyProvider` elsewhere in this
 * package: the actual `expo-secure-store`/`expo-file-system` calls live in a
 * separate RN-only file, `expoDeviceCacheStorage.ts`, so THIS file has zero RN
 * dependencies and runs under plain `node --test` with in-memory fakes — see
 * `tests/mobilePersistentCacheAdapter.test.ts`.
 */
import { gcm } from "@noble/ciphers/aes.js";
import { randomBytes, clean } from "@noble/ciphers/utils.js";
import type { CacheAdapter } from "../core/types.ts";

/**
 * Where the device-local symmetric key (base64, 32 raw bytes) lives. The real
 * implementation is `expo-secure-store` (Keychain/Keystore-backed) — see
 * `expoDeviceCacheStorage.ts`. `getKey() === null` is a legitimate "not yet
 * provisioned" state (first launch), never an error.
 */
export interface DeviceKeyStore {
  getKey(): Promise<string | null>;
  setKey(base64Key: string): Promise<void>;
  deleteKey(): Promise<void>;
}

/**
 * Where the encrypted cache entries live on disk. The real implementation is
 * `expo-file-system` (SecureStore alone has a per-item size limit unsuited to
 * arbitrary decrypted payloads — see `expoDeviceCacheStorage.ts`). Ciphertext is
 * opaque to this port: it never sees the plaintext cache key's semantics, only the
 * opaque string DataCloak's core already constructs (`<storeName>:<userId>`).
 * `readAll()` returning `{}` is a legitimate "nothing persisted yet" state, never
 * an error.
 */
export interface DeviceBlobStore {
  readAll(): Promise<Record<string, string>>;
  write(cacheKey: string, ciphertextBase64: string): Promise<void>;
  clear(): Promise<void>;
}

export interface MobilePersistentCacheAdapterOptions {
  keyStore: DeviceKeyStore;
  blobStore: DeviceBlobStore;
  /**
   * Called whenever an async persistence operation (hydration, key setup,
   * write-through, clear) fails unexpectedly. Never silent — see AGENTS.md's rule
   * against swallowed errors. Defaults to `console.error`, which is the right sink
   * for a fire-and-forget failure in a mobile app (surfaces in Metro/device logs).
   * A single failure during key setup or hydration permanently disables further
   * persistence for this adapter instance (falls back to memory-only, like
   * `tanstackAdapter`) rather than retrying on every `set()` — the next app launch
   * (a fresh adapter instance) tries again from scratch.
   */
  onPersistError?: (error: Error) => void;
}

export interface MobilePersistentCacheAdapter extends CacheAdapter {
  /**
   * Resolves once the initial hydration pass (reading + decrypting whatever was
   * persisted last session) has settled — successfully or by falling back to
   * memory-only. NOT part of the `CacheAdapter` contract (callers never need to
   * await it: `get()` correctly returns `undefined` for any key not yet hydrated,
   * same as a real cache miss) — exposed for deterministic tests/bootstrap only.
   */
  ready: Promise<void>;
  /**
   * Resolves once every persistence operation in flight AT THE TIME OF THE CALL
   * (write-throughs, clear-cleanup) has settled. Test-only determinism helper — the
   * real app never needs to await a fire-and-forget write.
   */
  flush(): Promise<void>;
}

const ENCODER = new TextEncoder();
const DECODER = new TextDecoder("utf-8", { fatal: true });

function toBase64(bytes: Uint8Array): string {
  let out = "";
  for (const byte of bytes) out += String.fromCharCode(byte);
  return btoa(out);
}

function fromBase64(b64: string): Uint8Array {
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
}

/** Fixed nonce-carrying envelope: `nonce (12 bytes) || ciphertext`, base64-encoded. */
function encryptEntry(key: Uint8Array, plaintext: string): string {
  const nonce = randomBytes(12);
  try {
    const cipher = gcm(key, nonce);
    const ciphertext = cipher.encrypt(ENCODER.encode(plaintext));
    const envelope = new Uint8Array(nonce.length + ciphertext.length);
    envelope.set(nonce, 0);
    envelope.set(ciphertext, nonce.length);
    return toBase64(envelope);
  } finally {
    clean(nonce);
  }
}

function decryptEntry(key: Uint8Array, envelopeBase64: string): string {
  const envelope = fromBase64(envelopeBase64);
  if (envelope.length < 13) {
    throw new Error(
      `mobilePersistentCacheAdapter: envelope too short (${envelope.length} bytes)`,
    );
  }
  const nonce = envelope.subarray(0, 12);
  const ciphertext = envelope.subarray(12);
  const cipher = gcm(key, nonce);
  return DECODER.decode(cipher.decrypt(ciphertext));
}

export function mobilePersistentCacheAdapter(
  options: MobilePersistentCacheAdapterOptions,
): MobilePersistentCacheAdapter {
  const { keyStore, blobStore } = options;
  const onPersistError =
    options.onPersistError ?? ((error: Error) => console.error(error));

  const memory = new Map<string, unknown>();
  const subscribers = new Map<string, Set<() => void>>();
  let persistenceDisabled = false;
  let dekPromise: Promise<Uint8Array> | null = null;
  // Tail of the fire-and-forget persistence chain — flush() awaits whatever is
  // in flight at call time. Every link reports its own failure (never a silent
  // catch) so one failed write never poisons the chain for subsequent writes.
  let pending: Promise<void> = Promise.resolve();

  function notify(key: string): void {
    for (const cb of subscribers.get(key) ?? []) cb();
  }

  /** Loads the device-local key, generating+persisting one on first use. */
  async function getOrCreateDek(): Promise<Uint8Array> {
    if (!dekPromise) {
      dekPromise = (async () => {
        const existing = await keyStore.getKey(); // null = legitimate, not an error
        if (existing) return fromBase64(existing);
        const fresh = randomBytes(32);
        await keyStore.setKey(toBase64(fresh));
        return fresh;
      })();
    }
    return dekPromise;
  }

  async function hydrate(): Promise<void> {
    let dek: Uint8Array;
    try {
      dek = await getOrCreateDek();
    } catch (error) {
      onPersistError(
        new Error(
          `mobilePersistentCacheAdapter.hydrate: device key setup failed, ` +
            `falling back to memory-only for this session: ${String(error)}`,
        ),
      );
      persistenceDisabled = true;
      return;
    }

    let persisted: Record<string, string>;
    try {
      persisted = await blobStore.readAll(); // {} = legitimate, nothing persisted yet
    } catch (error) {
      onPersistError(
        new Error(
          `mobilePersistentCacheAdapter.hydrate: reading persisted entries failed, ` +
            `falling back to memory-only for this session: ${String(error)}`,
        ),
      );
      persistenceDisabled = true;
      return;
    }

    for (const [key, ciphertextBase64] of Object.entries(persisted)) {
      try {
        const plaintext = decryptEntry(dek, ciphertextBase64);
        memory.set(key, JSON.parse(plaintext));
        notify(key);
      } catch (error) {
        // One corrupted/undecryptable entry (tampered file, stale key after a
        // partial clear) must not abort hydrating every other entry.
        onPersistError(
          new Error(
            `mobilePersistentCacheAdapter.hydrate: skipping unreadable entry ` +
              `"${key}": ${String(error)}`,
          ),
        );
      }
    }
  }

  const ready = hydrate();

  function persistWriteThrough(key: string, data: unknown): void {
    if (persistenceDisabled) return;
    pending = pending
      .then(async () => {
        const dek = await getOrCreateDek();
        if (persistenceDisabled) return; // became disabled while awaiting the key
        const ciphertext = encryptEntry(dek, JSON.stringify(data));
        await blobStore.write(key, ciphertext);
      })
      .catch((error) => {
        onPersistError(
          new Error(
            `mobilePersistentCacheAdapter.set("${key}"): write-through to device ` +
              `storage failed: ${String(error)}`,
          ),
        );
      });
  }

  function persistClear(): void {
    if (persistenceDisabled) return;
    pending = pending
      .then(async () => {
        await blobStore.clear();
        await keyStore.deleteKey();
        dekPromise = null; // next write provisions a fresh key
      })
      .catch((error) => {
        onPersistError(
          new Error(
            `mobilePersistentCacheAdapter.clear(): wiping device storage failed: ${String(error)}`,
          ),
        );
      });
  }

  return {
    ready,

    get<T>(key: string): T | undefined {
      return memory.get(key) as T | undefined;
    },

    set<T>(key: string, data: T): void {
      memory.set(key, data);
      notify(key);
      persistWriteThrough(key, data);
    },

    subscribe(key: string, callback: () => void): () => void {
      let set = subscribers.get(key);
      if (!set) {
        set = new Set();
        subscribers.set(key, set);
      }
      set.add(callback);
      return () => set!.delete(callback);
    },

    clear(): void {
      memory.clear();
      persistClear();
    },

    flush(): Promise<void> {
      return pending;
    },
  };
}
