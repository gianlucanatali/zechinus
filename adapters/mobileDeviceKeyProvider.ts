/**
 * Mobile device-bound key provider — placeholder for the `DeviceKeyProvider` port's
 * mobile side. Not implementable yet: a real Secure Enclave (iOS) / StrongBox (Android)
 * keypair needs a native module, which needs the Expo dev-client build (mobile roadmap
 * Fase 3.2), not just Expo Go. Nothing calls this yet — it exists only so the port has
 * both sides referenced from day one.
 */
import type { DeviceKeyProvider } from "./deviceKeyProvider.ts";

// FIXME: Secure Enclave/StrongBox keypair not implemented — requires a native module
// only buildable with the Expo dev-client (mobile roadmap Fase 3.2). Wire real
// hardware-backed key generation + unwrap here when that build exists. Throws instead of
// returning fake data so a caller can't silently proceed as if device-bound wrapping
// worked on mobile.
export function mobileDeviceKeyProvider(): DeviceKeyProvider {
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
