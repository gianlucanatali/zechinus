package expo.modules.zechinuscrypto

import androidx.fragment.app.FragmentActivity
import expo.modules.kotlin.exception.Exceptions
import expo.modules.kotlin.functions.Coroutine
import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition

class ExpoZechinusCryptoModule : Module() {
  private fun requireFragmentActivity(): FragmentActivity =
    appContext.currentActivity as? FragmentActivity
      ?: throw Exceptions.MissingActivity()

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

    // Module-level (not on the Class): these operate on the Keystore/BiometricPrompt,
    // not on an in-memory key — the native counterpart of the `IsolatedKeyCache` port
    // (`adapters/controllers/passkeyDekController.ts`). Logic lives in
    // `ZeroTapKeystoreStore` (see that file's own doc comment, including the real
    // cache()-also-needs-a-prompt platform asymmetry vs iOS).
    AsyncFunction("cacheKeyForZeroTap") Coroutine { ref: CryptoKeyRef, userId: String, dekEpoch: Int, credentialId: String ->
      ZeroTapKeystoreStore.cache(requireFragmentActivity(), ref, userId, dekEpoch, credentialId)
    }

    AsyncFunction("tryRestoreFromNativeCache") Coroutine { userId: String ->
      val restored = ZeroTapKeystoreStore.tryRestore(requireFragmentActivity(), userId)
      if (restored == null) null
      else mapOf("key" to restored.first, "dekEpoch" to restored.second, "credentialId" to restored.third)
    }

    AsyncFunction("clearNativeCache") { userId: String ->
      ZeroTapKeystoreStore.clear(appContext.reactContext ?: requireFragmentActivity(), userId)
    }
  }
}
