/**
 * Device-bound key material for multi-device DEK delivery (key-custody roadmap Fase
 * 2.3) — derived DETERMINISTICALLY from the passkey's KEK, never generated randomly
 * and never persisted anywhere. An earlier version of this file generated a random
 * WebCrypto RSA-OAEP keypair and persisted it in IndexedDB so it would survive
 * reloads. That was the wrong design: a persisted private key, even non-extractable,
 * is a standing secret a compromised script in this origin can USE at any time —
 * including while the app is fully locked/closed — since WebCrypto has no per-use
 * gate (unlike a passkey ceremony, which requires a visible, user-gesture-gated
 * WebAuthn prompt every time). Deriving the device key from the KEK instead means
 * there is nothing to persist: the "device private key" only exists for as long as
 * the KEK does — in memory, for the duration of an unlock — exactly like the
 * DEK/KEK themselves. Same KEK in, same device public key out, every time.
 *
 * Derived from the KEK, not the DEK: the KEK is tied to the passkey credential and
 * stays stable across a DEK rotation (a "graceful" rotation keeps the same passkey,
 * only the DEK changes) — deriving from the DEK would make the device's own public
 * key go stale at the exact moment a rotation needs to address it.
 *
 * The wrap itself is an ephemeral-static X25519 ECDH (`@noble/curves`, same trusted
 * family as `@noble/ciphers`/`@noble/hashes` already used here): the sender generates
 * a one-off ephemeral keypair, computes a shared secret against the recipient's
 * (derived) device public key, HKDF-derives a wrapping key from it, and reuses the
 * existing `wrapKey`/`unwrapKey` (AES-GCM) — no new AEAD implementation needed.
 * `getSharedSecret` rejects low-order peer public keys by default (verified against
 * `@noble/curves`'s own source, not assumed) — a malicious/invalid device public key
 * can't force a predictable shared secret.
 *
 * Every derived secret (the X25519 seed, the ECDH shared secret, the AES wrap key)
 * is `clean()`ed in a `finally` block as soon as it's no longer needed — same
 * discipline `passkeyDekController.ts` already applies to its own KEKs, extended
 * here rather than left as an inconsistency.
 */
import { x25519 } from "@noble/curves/ed25519.js";
import { clean } from "@noble/ciphers/utils.js";
import {
  deriveKey,
  wrapKey,
  unwrapKey,
  bytesToBase64,
  base64ToBytes,
} from "../../core/keyDerivation.ts";
import type { WrappedKey } from "../../core/keyDerivation.ts";

/** IMMUTABLE once any device public key has been derived/registered — changing it makes every derived device key different, permanently (same rationale as `webauthnKeyProvider`'s salts). */
const DEVICE_KEY_SALT = new TextEncoder().encode("zechinus-device-key-v1");
const DEVICE_KEY_INFO = "device-key-x25519-seed-v1";
const WRAP_KEK_INFO = "device-key-wrap-shared-secret-v1";

export type DeviceWrappedKey = WrappedKey & { ephemeralPublicKeyB64: string };

/** Public key for a raw 32-byte X25519 seed — however it was obtained (derived from a KEK, or freshly random for a one-shot handshake). Does NOT clean `seed` — the caller owns its lifetime, it's typically used again right after (e.g. to unwrap). */
function publicKeyFromSeed(seed: Uint8Array): string {
  return bytesToBase64(x25519.getPublicKey(seed));
}

/** Unwraps using a raw 32-byte X25519 seed directly — no KEK derivation. Shared by `unwrapWithDeviceKey` (seed = derived from KEK) and `unwrapWithEphemeralKey` (seed = freshly random, held only in memory for one handshake, never derived from anything persistent). Cleans the shared secret and derived wrap key before returning; does NOT clean `seed` — the caller owns it. */
function unwrapWithSeed(
  seed: Uint8Array,
  wrapped: DeviceWrappedKey,
): Uint8Array {
  const ephemeralPublicKey = base64ToBytes(wrapped.ephemeralPublicKeyB64);
  const sharedSecret = x25519.getSharedSecret(seed, ephemeralPublicKey);
  try {
    const wrapKek = deriveKey(sharedSecret, DEVICE_KEY_SALT, WRAP_KEK_INFO, 32);
    try {
      return unwrapKey(wrapKek, wrapped);
    } finally {
      clean(wrapKek);
    }
  } finally {
    clean(sharedSecret);
  }
}

/** Deterministically derives this device's X25519 public key from the KEK. Same KEK → same public key, every time — nothing to persist, nothing to "create". */
export function deriveDevicePublicKey(kek: Uint8Array): string {
  const seed = deriveKey(kek, DEVICE_KEY_SALT, DEVICE_KEY_INFO, 32);
  try {
    return publicKeyFromSeed(seed);
  } finally {
    clean(seed);
  }
}

/**
 * Generates a fresh, genuinely random X25519 keypair for a ONE-SHOT key-delivery
 * handshake: a device that's fallen behind an epoch publishes this public key
 * instead of relying on a persisted/derivable identity — any device already on
 * the current epoch wraps the DEK for it, the requester unwraps with `seed` then
 * discards it immediately. Deliberately NOT derived from the KEK: this key's only
 * job is to exist for the few seconds/minutes of one handshake — persisting or
 * re-deriving it would just recreate the exact standing-secret problem
 * `deriveDevicePublicKey` exists to avoid, for no benefit, since nothing needs to
 * address this key again after the handshake completes.
 *
 * Returns `seed` to the caller (not cleaned here) — it's needed once more, to
 * `unwrapWithEphemeralKey` the reply when it arrives. The caller must `clean()` it
 * themselves once the handshake is over (success or abandoned).
 */
export function generateEphemeralDeviceKey(): {
  seed: Uint8Array;
  publicKeyB64: string;
} {
  const seed = x25519.utils.randomSecretKey();
  return { seed, publicKeyB64: publicKeyFromSeed(seed) };
}

/** Unwraps a DEK wrapped for an ephemeral handshake key (see `generateEphemeralDeviceKey`). `seed` is the raw private key returned by that call — discard it (call `clean()` on it) immediately after this returns, it is never reused. */
export function unwrapWithEphemeralKey(
  seed: Uint8Array,
  wrapped: DeviceWrappedKey,
): Uint8Array {
  return unwrapWithSeed(seed, wrapped);
}

/**
 * Wraps a DEK for delivery to a specific device's public key — called by whichever
 * device already holds the plaintext DEK. Needs only the recipient's public key,
 * never the recipient's KEK/private material.
 */
export function wrapForDevicePublicKey(
  devicePublicKeyB64: string,
  dek: Uint8Array,
): DeviceWrappedKey {
  const devicePublicKey = base64ToBytes(devicePublicKeyB64);
  const ephemeralSeed = x25519.utils.randomSecretKey();
  try {
    const ephemeralPublicKeyB64 = bytesToBase64(
      x25519.getPublicKey(ephemeralSeed),
    );
    const sharedSecret = x25519.getSharedSecret(ephemeralSeed, devicePublicKey);
    try {
      const wrapKek = deriveKey(
        sharedSecret,
        DEVICE_KEY_SALT,
        WRAP_KEK_INFO,
        32,
      );
      try {
        return { ...wrapKey(wrapKek, dek), ephemeralPublicKeyB64 };
      } finally {
        clean(wrapKek);
      }
    } finally {
      clean(sharedSecret);
    }
  } finally {
    clean(ephemeralSeed);
  }
}

/** Unwraps a DEK wrapped for this device — re-derives this device's private key from the KEK on the spot, needs no persisted material. Throws if the wrap targets a different device's public key. */
export function unwrapWithDeviceKey(
  kek: Uint8Array,
  wrapped: DeviceWrappedKey,
): Uint8Array {
  const seed = deriveKey(kek, DEVICE_KEY_SALT, DEVICE_KEY_INFO, 32);
  try {
    return unwrapWithSeed(seed, wrapped);
  } finally {
    clean(seed);
  }
}
