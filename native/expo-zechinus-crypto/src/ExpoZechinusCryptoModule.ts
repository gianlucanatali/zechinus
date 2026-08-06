import { NativeModule, requireNativeModule } from 'expo';

/**
 * One key, one instance — the JS-side type for the native `CryptoKeyRef` class
 * (Swift/CryptoKit on iOS, Kotlin on Android), registered under the explicit
 * name "CryptoKey" to match `adapters/keyhandles/nativeModuleKeyHandle.ts`'s
 * `NativeCryptoModule` interface. Raw key bytes are handed to the constructor
 * and never returned by any method here.
 */
export declare class CryptoKey extends NativeModule<{}> {
  constructor(rawBytes: Uint8Array);
  initMacKey(macKey: Uint8Array): Promise<void>;
  aesGcmEncrypt(nonce: Uint8Array, aad: Uint8Array, plaintext: Uint8Array): Promise<Uint8Array>;
  aesGcmDecrypt(nonce: Uint8Array, aad: Uint8Array, ciphertext: Uint8Array): Promise<Uint8Array>;
  hkdfDerive(salt: Uint8Array, info: string, length: number): Promise<Uint8Array>;
  hmacSha256(payload: Uint8Array): Promise<string>;
  wrapSelf(kek: Uint8Array): Promise<{ ciphertext: string; nonce: string }>;
  destroy(): void;
}

declare class ExpoZechinusCryptoModule extends NativeModule<{}> {
  CryptoKey: typeof CryptoKey;
}

export default requireNativeModule<ExpoZechinusCryptoModule>('ExpoZechinusCrypto');
