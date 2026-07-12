/**
 * Mobile device-bound key provider — placeholder for the mobile side of multi-device
 * DEK delivery (key-custody roadmap Fase 3.2). Not implementable yet: a real Secure
 * Enclave (iOS) / StrongBox (Android) keypair needs a native module, which needs the
 * Expo dev-client build, not just Expo Go. Nothing calls this yet.
 *
 * Deliberately a DIFFERENT shape than the web side (`deriveDevicePublicKey`/
 * `unwrapWithDeviceKey` in `deviceKeyProvider.ts`, pure functions of the KEK, nothing
 * persisted): Secure Enclave/StrongBox generate their OWN key material internally and
 * refuse to import externally-derived key material — you cannot hand them a seed
 * derived from the KEK the way the web side does with X25519. On mobile the hardware
 * IS the persistence boundary (and a stronger one than deriving from the KEK would
 * be — compromising it needs a physical hardware attack, not just the KEK), so a
 * stateful object wrapping a hardware-generated, hardware-held key is the right shape
 * here, not a pure function.
 */
export interface MobileDeviceKeyProvider {
  /** Generates the device keypair inside Secure Enclave/StrongBox on first call, returns the (exportable) public key. Idempotent. */
  getOrCreateDevicePublicKey(): Promise<{ publicKeyB64: string }>;
  /** Unwraps a DEK wrapped for THIS device's public key, inside the hardware. Throws if wrapped for a different device. */
  unwrapWithDeviceKey(wrapped: { ciphertext: string }): Promise<Uint8Array>;
}

// FIXME: Secure Enclave/StrongBox keypair not implemented — requires a native module
// only buildable with the Expo dev-client (mobile roadmap Fase 3.2). Wire real
// hardware-backed key generation + unwrap here when that build exists. Throws instead of
// returning fake data so a caller can't silently proceed as if device-bound wrapping
// worked on mobile.
export function mobileDeviceKeyProvider(): MobileDeviceKeyProvider {
  return {
    async getOrCreateDevicePublicKey() {
      throw new Error(
        "mobileDeviceKeyProvider.getOrCreateDevicePublicKey: not implemented — " +
          "Secure Enclave/StrongBox keypair requires the mobile dev-client (Fase 3.2).",
      );
    },
    async unwrapWithDeviceKey() {
      throw new Error(
        "mobileDeviceKeyProvider.unwrapWithDeviceKey: not implemented — " +
          "Secure Enclave/StrongBox keypair requires the mobile dev-client (Fase 3.2).",
      );
    },
  };
}
