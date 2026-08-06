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
  }
}
