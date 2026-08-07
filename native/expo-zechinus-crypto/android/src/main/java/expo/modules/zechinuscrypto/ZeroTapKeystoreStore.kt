package expo.modules.zechinuscrypto

import android.content.Context
import android.content.SharedPreferences
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.util.Base64
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import kotlinx.coroutines.suspendCancellableCoroutine
import org.json.JSONObject
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import kotlin.coroutines.resume

/**
 * OS-gated zero-tap cache for Android — Keystore + BiometricPrompt counterpart of
 * `ZeroTapKeychainStore.swift` on iOS. `setUserAuthenticationRequired(true)` +
 * `setInvalidatedByBiometricEnrollment(true)` is the analogue of iOS's
 * `.biometryCurrentSet`: re-enrolling a fingerprint/face invalidates the Keystore key,
 * so an attacker who adds their own biometric to an unlocked device cannot reach the
 * cached DEK.
 *
 * **Real platform asymmetry vs iOS, not yet resolved by real-device testing:**
 * iOS's Keychain ACL only gates READS (`SecItemCopyMatching`) — writing a
 * `.biometryCurrentSet` item (`SecItemAdd`) needs no live ceremony, since the caller
 * already has the plaintext in hand. A single symmetric AndroidKeyStore AES key with
 * `setUserAuthenticationRequired(true)` gates BOTH directions equally, so — as written
 * here — `cache()` ALSO needs a live `BiometricPrompt` ceremony, right after the unlock
 * that already showed one. The standard fix (asymmetric Keystore key: unrestricted
 * public-key encrypt, auth-gated private-key decrypt) is a larger change deferred until
 * a real device confirms whether the extra prompt is actually a problem in practice.
 */
object ZeroTapKeystoreStore {
  private const val KEYSTORE_PROVIDER = "AndroidKeyStore"
  private const val PREFS_NAME = "zechinus_zero_tap_cache"
  private const val TRANSFORMATION = "${KeyProperties.KEY_ALGORITHM_AES}/${KeyProperties.BLOCK_MODE_GCM}/${KeyProperties.ENCRYPTION_PADDING_NONE}"
  private const val GCM_TAG_LENGTH_BITS = 128

  private fun keystoreAlias(userId: String) = "zechinus.zero-tap-dek.v1.$userId"
  private fun prefsKey(userId: String) = "entry.$userId"

  private fun prefs(context: Context): SharedPreferences =
    context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

  private fun keyStore(): KeyStore = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }

  private fun getOrCreateKey(userId: String): SecretKey {
    val alias = keystoreAlias(userId)
    val existing = keyStore().getKey(alias, null) as? SecretKey
    if (existing != null) return existing

    val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE_PROVIDER)
    val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
      .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
      .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
      .setUserAuthenticationRequired(true)
      .setInvalidatedByBiometricEnrollment(true)
      .build()
    keyGenerator.init(spec)
    return keyGenerator.generateKey()
  }

  /**
   * Caches `key`'s bytes, encrypted under a Keystore key gated by a live BiometricPrompt
   * ceremony (see this object's own doc comment on why the write side needs one, unlike
   * iOS). `activity` hosts the prompt UI.
   */
  suspend fun cache(
    activity: FragmentActivity,
    key: CryptoKeyRef,
    userId: String,
    dekEpoch: Int,
    credentialId: String,
  ) {
    val secretKey = getOrCreateKey(userId)
    val cipher = Cipher.getInstance(TRANSFORMATION).apply { init(Cipher.ENCRYPT_MODE, secretKey) }
    val authenticatedCipher = authenticateAndGetCipher(activity, cipher) ?: return

    val plaintext = key.exportForKeychainOnly().toByteArray(Charsets.UTF_8)
    val ciphertext = authenticatedCipher.doFinal(plaintext)
    val entry = JSONObject().apply {
      put("ciphertext", Base64.encodeToString(ciphertext, Base64.NO_WRAP))
      put("iv", Base64.encodeToString(authenticatedCipher.iv, Base64.NO_WRAP))
      put("dekEpoch", dekEpoch)
      put("credentialId", credentialId)
    }
    prefs(activity).edit().putString(prefsKey(userId), entry.toString()).apply()
  }

  /**
   * Restores a cached key. The OS shows the biometric prompt inside
   * `authenticateAndGetCipher`. Returns `null` — never throws — on user cancel, no
   * biometrics, nothing cached, or `KeyPermanentlyInvalidatedException` (biometry
   * re-enrolled since caching — exactly the case this mechanism exists to intercept,
   * which a JS-level gate can never see): all expected outcomes, the caller falls
   * through to a real ceremony.
   */
  suspend fun tryRestore(
    activity: FragmentActivity,
    userId: String,
  ): Triple<CryptoKeyRef, Int, String>? {
    val raw = prefs(activity).getString(prefsKey(userId), null) ?: return null
    val entry = try { JSONObject(raw) } catch (_: Exception) { return null }

    val secretKey = try {
      keyStore().getKey(keystoreAlias(userId), null) as? SecretKey ?: return null
    } catch (_: Exception) {
      return null
    }

    val iv = Base64.decode(entry.getString("iv"), Base64.NO_WRAP)
    val cipher = try {
      Cipher.getInstance(TRANSFORMATION).apply {
        init(Cipher.DECRYPT_MODE, secretKey, GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv))
      }
    } catch (_: KeyPermanentlyInvalidatedException) {
      clear(activity, userId)
      return null
    }

    val authenticatedCipher = authenticateAndGetCipher(activity, cipher) ?: return null
    val ciphertext = Base64.decode(entry.getString("ciphertext"), Base64.NO_WRAP)
    val keyHex = try {
      String(authenticatedCipher.doFinal(ciphertext), Charsets.UTF_8)
    } catch (_: Exception) {
      return null
    }
    val keyBytes = keyHex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    val restored = try { CryptoKeyRef(keyBytes) } catch (_: Exception) { return null }

    return Triple(restored, entry.getInt("dekEpoch"), entry.getString("credentialId"))
  }

  fun clear(context: Context, userId: String) {
    prefs(context).edit().remove(prefsKey(userId)).apply()
    try {
      keyStore().deleteEntry(keystoreAlias(userId))
    } catch (_: Exception) {
      // No-op — deleting a key that's already gone (or never existed) is not an error.
    }
  }

  /**
   * Bridges `BiometricPrompt`'s callback API to a suspension point. Resolves `null`
   * (never throws) on any non-success result — cancel, lockout, no hardware, error —
   * matching this whole module's "fail closed to a real ceremony" philosophy.
   */
  private suspend fun authenticateAndGetCipher(
    activity: FragmentActivity,
    cipher: Cipher,
  ): Cipher? = suspendCancellableCoroutine { continuation ->
    val executor = ContextCompat.getMainExecutor(activity)
    val callback = object : BiometricPrompt.AuthenticationCallback() {
      override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
        continuation.resume(result.cryptoObject?.cipher)
      }
      override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
        continuation.resume(null)
      }
      override fun onAuthenticationFailed() {
        // A single failed attempt (e.g. unrecognized fingerprint) — BiometricPrompt
        // keeps showing its own UI and retries on its own; only a terminal callback
        // (success/error) should resolve this continuation.
      }
    }
    val prompt = BiometricPrompt(activity, executor, callback)
    val promptInfo = BiometricPrompt.PromptInfo.Builder()
      .setTitle(activity.getString(activity.applicationInfo.labelRes.takeIf { it != 0 } ?: android.R.string.ok))
      .setNegativeButtonText(activity.getString(android.R.string.cancel))
      .build()
    prompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(cipher))
  }
}
