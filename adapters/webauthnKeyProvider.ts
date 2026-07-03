/* eslint-disable no-undef */
/**
 * WebAuthn PRF key provider — the web-platform adapter for deriving an E2E-encryption
 * key from a passkey. Any app doing zero-knowledge E2E encryption with WebAuthn PRF
 * needs this exact ceremony (register/authenticate, extract the PRF extension output,
 * HKDF-derive a DEK/KEK from it) — it's not the host app-specific, so it lives here, not
 * in the consuming app. What IS app-specific is the config: the actual salt/info
 * bytes (tied to that app's already-encrypted data — changing them breaks decryption
 * for every existing user) and the relying-party id/name. A future native-biometrics
 * adapter (React Native) would mirror this file's shape, swapping `navigator.credentials`
 * for a native API, while reusing the same `@datacloak/core/keyDerivation.ts` engine.
 */

import { deriveKey } from "../core/keyDerivation.ts";

// WebAuthn Level 3 PRF extension — not yet in @types/webidl.
type PRFExtInput = AuthenticationExtensionsClientInputs & {
  prf: { eval: { first: BufferSource } };
};

type PRFExtOutput = AuthenticationExtensionsClientOutputs & {
  prf?: { results?: { first?: ArrayBuffer } };
};

export type PasskeyInfo = {
  credentialId: string; // base64url
  prfOutput?: ArrayBuffer; // available on Chrome during create
};

export interface WebauthnKeyProviderConfig {
  /** WebAuthn relying party id (domain) — e.g. "myapp.com", "localhost" in dev. */
  rpId: string;
  /** Relying party display name shown in the platform's passkey UI. */
  rpName: string;
  /**
   * Salt for the PRF extension's `eval.first` input. IMMUTABLE once any passkey is
   * registered with it — changing it makes every PRF output (and everything derived
   * from it) different, permanently.
   */
  prfSalt: Uint8Array;
  /** HKDF salt/info for deriving the DEK from raw PRF output. IMMUTABLE — see above. */
  dekSalt: Uint8Array;
  dekInfo: string;
  /** HKDF info for deriving a KEK (double-envelope flows) from raw PRF output. IMMUTABLE. */
  kekInfo: string;
}

export interface WebauthnKeyProvider {
  /** Registers a new passkey with the PRF extension enabled. Once per device/account. */
  registerPasskeyWithPRF(userName: string): Promise<PasskeyInfo>;
  /**
   * Authenticates with an existing passkey and returns the DEK derived from its PRF
   * output. `credentialId` optional: omitted shows every available passkey (useful for
   * multi-device — iCloud/Google Password Manager sync the credential).
   */
  getDEKFromPasskey(credentialId?: string): Promise<Uint8Array>;
  /** Extracts the raw PRF output without deriving a DEK (used to derive a KEK separately). */
  getPRFOutput(credentialId?: string): Promise<ArrayBuffer>;
  /** Extracts the PRF output AND the credential id (used by unlock to know which wrapped_key to fetch). */
  getPRFOutputWithCredentialId(
    credentialId?: string,
  ): Promise<{ prfOutput: ArrayBuffer; credentialId: string }>;
  /** Derives a KEK from a passkey's PRF output — different `info` than the DEK, not blob-compatible with it. */
  deriveKEKFromPRF(prfOutput: ArrayBuffer): Uint8Array;
}

function base64urlToBytes(b64url: string): Uint8Array<ArrayBuffer> {
  const b64 = b64url
    .replace(/-/g, "+")
    .replace(/_/g, "/")
    .padEnd(b64url.length + ((4 - (b64url.length % 4)) % 4), "=");
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length); // guaranteed ArrayBuffer, not SharedArrayBuffer
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

export function webauthnKeyProvider(
  config: WebauthnKeyProviderConfig,
): WebauthnKeyProvider {
  return {
    async registerPasskeyWithPRF(userName: string): Promise<PasskeyInfo> {
      const challenge = crypto.getRandomValues(new Uint8Array(32));
      const userId = crypto.getRandomValues(new Uint8Array(16));

      const credential = (await navigator.credentials.create({
        publicKey: {
          challenge,
          rp: { name: config.rpName, id: config.rpId },
          user: { id: userId, name: userName, displayName: userName },
          pubKeyCredParams: [
            { type: "public-key", alg: -7 }, // ES256 (preferred)
            { type: "public-key", alg: -257 }, // RS256 (fallback Windows Hello)
          ],
          authenticatorSelection: {
            userVerification: "required",
            residentKey: "required",
          },
          extensions: {
            prf: { eval: { first: config.prfSalt } },
          } as PRFExtInput,
        },
      })) as PublicKeyCredential | null;

      if (!credential)
        throw new Error("webauthnKeyProvider: registration cancelled");

      const ext = credential.getClientExtensionResults() as PRFExtOutput;
      if (!ext.prf) {
        throw new Error(
          "webauthnKeyProvider: this browser doesn't support the PRF extension. " +
            "Use Chrome 116+ (desktop/Android) or Safari with iOS 18+ / macOS 15+.",
        );
      }

      return {
        credentialId: credential.id,
        prfOutput: ext.prf?.results?.first,
      };
    },

    async getDEKFromPasskey(credentialId?: string): Promise<Uint8Array> {
      const { prfOutput } = await getAssertionPRF(config, credentialId);
      if (prfOutput.byteLength < 32) {
        throw new Error(
          `webauthnKeyProvider: PRF output must be at least 32 bytes (got ${prfOutput.byteLength})`,
        );
      }
      return deriveKey(
        new Uint8Array(prfOutput),
        config.dekSalt,
        config.dekInfo,
        32,
      );
    },

    async getPRFOutput(credentialId?: string): Promise<ArrayBuffer> {
      const { prfOutput } = await getAssertionPRF(config, credentialId);
      return prfOutput;
    },

    async getPRFOutputWithCredentialId(credentialId?: string) {
      return getAssertionPRF(config, credentialId);
    },

    deriveKEKFromPRF(prfOutput: ArrayBuffer): Uint8Array {
      return deriveKey(
        new Uint8Array(prfOutput),
        config.prfSalt,
        config.kekInfo,
        32,
      );
    },
  };
}

async function getAssertionPRF(
  config: WebauthnKeyProviderConfig,
  credentialId?: string,
): Promise<{ prfOutput: ArrayBuffer; credentialId: string }> {
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const allowCredentials: PublicKeyCredentialDescriptor[] = credentialId
    ? [{ type: "public-key", id: base64urlToBytes(credentialId) }]
    : [];

  const assertion = (await navigator.credentials.get({
    publicKey: {
      challenge,
      rpId: config.rpId,
      allowCredentials,
      userVerification: "required",
      extensions: { prf: { eval: { first: config.prfSalt } } } as PRFExtInput,
    },
  })) as PublicKeyCredential | null;

  if (!assertion)
    throw new Error("webauthnKeyProvider: authentication cancelled");

  const ext = assertion.getClientExtensionResults() as PRFExtOutput;
  const prfOutput = ext.prf?.results?.first;
  if (!prfOutput) {
    throw new Error(
      "webauthnKeyProvider: PRF output not available. This browser supports " +
        "passkeys but not the PRF extension — update your browser.",
    );
  }

  return { prfOutput, credentialId: assertion.id };
}
