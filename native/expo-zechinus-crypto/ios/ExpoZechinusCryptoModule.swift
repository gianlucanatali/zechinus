import ExpoModulesCore

public class ExpoZechinusCryptoModule: Module {
  public func definition() -> ModuleDefinition {
    Name("ExpoZechinusCrypto")

    // Explicit "CryptoKey" name: the Swift type is `CryptoKeyRef` (to avoid any name
    // collision with CryptoKit's own types), but `adapters/keyhandles/nativeModuleKeyHandle.ts`'s
    // `NativeCryptoModule` interface expects `CryptoKey` on the JS side — this is the
    // verification Task A3 Step 1 asked for, resolved here rather than left implicit.
    Class("CryptoKey", CryptoKeyRef.self) {
      Constructor { (rawBytes: Data) -> CryptoKeyRef in try CryptoKeyRef(rawBytes: rawBytes) }

      AsyncFunction("initMacKey") { (ref: CryptoKeyRef, macKey: Data) in try ref.initMacKey(macKey) }
      AsyncFunction("aesGcmEncrypt") { (ref: CryptoKeyRef, nonce: Data, aad: Data, plaintext: Data) -> Data in
        try ref.aesGcmEncrypt(nonce, aad, plaintext)
      }
      AsyncFunction("aesGcmDecrypt") { (ref: CryptoKeyRef, nonce: Data, aad: Data, ciphertext: Data) -> Data in
        try ref.aesGcmDecrypt(nonce, aad, ciphertext)
      }
      AsyncFunction("hkdfDerive") { (ref: CryptoKeyRef, salt: Data, info: String, length: Int) -> Data in
        try ref.hkdfDerive(salt, info, length)
      }
      AsyncFunction("hmacSha256") { (ref: CryptoKeyRef, payload: Data) -> String in try ref.hmacSha256(payload) }
      AsyncFunction("wrapSelf") { (ref: CryptoKeyRef, kek: Data) -> [String: String] in try ref.wrapSelf(kek) }
      Function("destroy") { (ref: CryptoKeyRef) in ref.destroy() }
    }

    // Module-level (not on the Class): these operate on the Keychain, not on an
    // in-memory key. `cacheKeyForZeroTap`/`tryRestoreFromNativeCache`/`clearNativeCache`
    // are the native counterpart of the `IsolatedKeyCache` port
    // (`adapters/controllers/passkeyDekController.ts`) — the key never leaves this
    // boundary: `tryRestoreFromNativeCache` hands back an already-built `CryptoKey`
    // instance, never raw bytes. Logic lives in `ZeroTapKeychainStore` (plain type,
    // same reason `CryptoKeyRef` is a plain type — see that file's own doc comment);
    // these are thin bindings.
    AsyncFunction("cacheKeyForZeroTap") { (ref: CryptoKeyRef, userId: String, dekEpoch: Int, credentialId: String) in
      try ZeroTapKeychainStore.cache(key: ref, userId: userId, dekEpoch: dekEpoch, credentialId: credentialId)
    }

    AsyncFunction("tryRestoreFromNativeCache") { (userId: String) -> [String: Any]? in
      guard let restored = ZeroTapKeychainStore.tryRestore(userId: userId) else { return nil }
      return ["key": restored.key, "dekEpoch": restored.dekEpoch, "credentialId": restored.credentialId]
    }

    AsyncFunction("clearNativeCache") { (userId: String) in
      ZeroTapKeychainStore.clear(userId: userId)
    }
  }
}
