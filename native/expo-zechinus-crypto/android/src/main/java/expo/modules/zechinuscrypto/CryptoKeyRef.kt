package expo.modules.zechinuscrypto

import android.util.Base64
import com.google.crypto.tink.subtle.Hkdf
import expo.modules.kotlin.sharedobjects.SharedObject
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

class ZechinusCryptoException(message: String) : Exception(message)

/**
 * One key, one instance — see `CryptoKeyRef.swift` for the rationale. Key material is
 * never returned to JS by any method here.
 *
 * `android.util.Base64`, NOT `java.util.Base64` — the latter requires API 26 and would
 * crash on the older devices Expo's minSdk still allows. `NO_WRAP` is mandatory: the
 * default inserts newlines and breaks interop.
 */
class CryptoKeyRef(rawBytes: ByteArray) : SharedObject() {
  private var key: ByteArray?
  private var macKey: ByteArray? = null

  init {
    if (rawBytes.size != 32) {
      throw ZechinusCryptoException("CryptoKey: key must be 32 bytes, got ${rawBytes.size}")
    }
    key = rawBytes.copyOf()
  }

  private fun requireKey(): ByteArray = key ?: throw ZechinusCryptoException("CryptoKey: already destroyed")

  fun initMacKey(bytes: ByteArray) {
    requireKey()
    macKey = bytes.copyOf()
  }

  fun aesGcmEncrypt(nonce: ByteArray, aad: ByteArray, plaintext: ByteArray): ByteArray {
    val k = requireKey()
    if (nonce.size != 12) throw ZechinusCryptoException("CryptoKey: nonce must be 12 bytes, got ${nonce.size}")
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(k, "AES"), GCMParameterSpec(128, nonce))
    cipher.updateAAD(aad)
    return cipher.doFinal(plaintext) // ciphertext||tag, same as @noble/ciphers
  }

  fun aesGcmDecrypt(nonce: ByteArray, aad: ByteArray, ciphertext: ByteArray): ByteArray {
    val k = requireKey()
    if (nonce.size != 12) throw ZechinusCryptoException("CryptoKey: nonce must be 12 bytes, got ${nonce.size}")
    if (ciphertext.size <= 16) {
      throw ZechinusCryptoException(
        "CryptoKey: ciphertext must include the 16-byte GCM tag, got ${ciphertext.size} bytes"
      )
    }
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(k, "AES"), GCMParameterSpec(128, nonce))
    cipher.updateAAD(aad)
    return cipher.doFinal(ciphertext)
  }

  /**
   * HKDF-SHA256 via Tink, NOT hand-written. AES-GCM and HMAC come from the platform;
   * HKDF is the one primitive Android's `javax.crypto` does not expose under a standard
   * algorithm name, so the choice is a maintained library or our own code. Fifteen lines
   * of hand-written key derivation is not a good trade for one dependency.
   */
  fun hkdfDerive(salt: ByteArray, info: String, length: Int): ByteArray =
    Hkdf.computeHkdf("HMACSHA256", requireKey(), salt, info.toByteArray(Charsets.UTF_8), length)

  fun hmacSha256(payload: ByteArray): String {
    requireKey()
    val mk = macKey ?: throw ZechinusCryptoException("CryptoKey: no MAC key — call initMacKey first")
    val mac = Mac.getInstance("HmacSHA256")
    mac.init(SecretKeySpec(mk, "HmacSHA256"))
    return mac.doFinal(payload).joinToString("") { "%02x".format(it) }
  }

  fun wrapSelf(kek: ByteArray): Map<String, String> {
    val k = requireKey()
    val nonce = ByteArray(12).also { SecureRandom().nextBytes(it) }
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(kek, "AES"), GCMParameterSpec(128, nonce))
    return mapOf(
      "ciphertext" to Base64.encodeToString(cipher.doFinal(k), Base64.NO_WRAP),
      "nonce" to Base64.encodeToString(nonce, Base64.NO_WRAP),
    )
  }

  /** Idempotent. Zeroing before dropping the reference is the point — the JVM won't do it. */
  fun destroy() {
    key?.fill(0)
    macKey?.fill(0)
    key = null
    macKey = null
  }

  /**
   * The only place in this module that turns key material back into plain bytes —
   * `internal` (not exposed via the `Class("CryptoKey", ...)` binding), so it exists for
   * `ZeroTapKeystoreStore` in this same module to call, and is unreachable from JS: it is
   * never listed inside the `Class` definition, so the Expo Modules bridge has no way to
   * invoke it. The returned hex string goes straight into an AndroidKeyStore-encrypted
   * blob gated by `BiometricPrompt` (`ZeroTapKeystoreStore.cache`) — it is never logged,
   * returned across the JS bridge, or persisted anywhere else.
   */
  internal fun exportForKeychainOnly(): String =
    requireKey().joinToString("") { "%02x".format(it) }
}
