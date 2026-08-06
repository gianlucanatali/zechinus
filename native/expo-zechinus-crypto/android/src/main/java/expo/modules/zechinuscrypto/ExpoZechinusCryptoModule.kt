package expo.modules.zechinuscrypto

import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition

class ExpoZechinusCryptoModule : Module() {
  override fun definition() = ModuleDefinition {
    Name("ExpoZechinusCrypto")

    // Explicit "CryptoKey" name — see the matching comment in ExpoZechinusCryptoModule.swift.
    Class("CryptoKey", CryptoKeyRef::class) {
      Constructor { rawBytes: ByteArray -> CryptoKeyRef(rawBytes) }

      AsyncFunction("initMacKey") { ref: CryptoKeyRef, macKey: ByteArray -> ref.initMacKey(macKey) }
      AsyncFunction("aesGcmEncrypt") { ref: CryptoKeyRef, nonce: ByteArray, aad: ByteArray, plaintext: ByteArray ->
        ref.aesGcmEncrypt(nonce, aad, plaintext)
      }
      AsyncFunction("aesGcmDecrypt") { ref: CryptoKeyRef, nonce: ByteArray, aad: ByteArray, ciphertext: ByteArray ->
        ref.aesGcmDecrypt(nonce, aad, ciphertext)
      }
      AsyncFunction("hkdfDerive") { ref: CryptoKeyRef, salt: ByteArray, info: String, length: Int ->
        ref.hkdfDerive(salt, info, length)
      }
      AsyncFunction("hmacSha256") { ref: CryptoKeyRef, payload: ByteArray -> ref.hmacSha256(payload) }
      AsyncFunction("wrapSelf") { ref: CryptoKeyRef, kek: ByteArray -> ref.wrapSelf(kek) }
      Function("destroy") { ref: CryptoKeyRef -> ref.destroy() }
    }
  }
}
