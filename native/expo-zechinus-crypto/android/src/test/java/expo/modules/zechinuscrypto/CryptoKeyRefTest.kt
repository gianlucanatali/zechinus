package expo.modules.zechinuscrypto

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

// sdk = [34]: Robolectric 4.13 doesn't yet support the app's real targetSdkVersion (36) —
// these tests exercise javax.crypto/android.util.Base64, whose behavior doesn't vary
// across API 34-36, so pinning the simulated SDK is safe.
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class CryptoKeyRefTest {
  private fun makeKey(): CryptoKeyRef = CryptoKeyRef(ByteArray(32) { 1 })

  @Test
  fun rejectsWrongKeyLength() {
    assertThrows(ZechinusCryptoException::class.java) { CryptoKeyRef(ByteArray(16) { 1 }) }
  }

  @Test
  fun roundTrip() {
    val key = makeKey()
    val nonce = ByteArray(12) { 2 }
    val aad = "aad".toByteArray()
    val ct = key.aesGcmEncrypt(nonce, aad, "hello".toByteArray())
    assertArrayEquals("hello".toByteArray(), key.aesGcmDecrypt(nonce, aad, ct))
  }

  @Test
  fun truncatedCiphertextThrowsInsteadOfCrashing() {
    val key = makeKey()
    assertThrows(ZechinusCryptoException::class.java) {
      key.aesGcmDecrypt(ByteArray(12) { 2 }, ByteArray(0), ByteArray(8))
    }
  }

  @Test
  fun wrongAadFailsAuthentication() {
    val key = makeKey()
    val nonce = ByteArray(12) { 2 }
    val ct = key.aesGcmEncrypt(nonce, "right".toByteArray(), "hello".toByteArray())
    assertThrows(Exception::class.java) { key.aesGcmDecrypt(nonce, "wrong".toByteArray(), ct) }
  }

  /**
   * The invariant that makes the whole model correct: two keys alive together
   * (a rotation keeps `previousCryptoHandle` alongside the current one) are
   * independent instances, and destroying one never touches the other.
   */
  @Test
  fun destroyingOneInstanceLeavesTheOtherUsable() {
    val current = CryptoKeyRef(ByteArray(32) { 1 })
    val previous = CryptoKeyRef(ByteArray(32) { 9 })
    val nonce = ByteArray(12) { 2 }

    previous.destroy()

    current.aesGcmEncrypt(nonce, ByteArray(0), "still works".toByteArray())
    assertThrows(ZechinusCryptoException::class.java) {
      previous.aesGcmEncrypt(nonce, ByteArray(0), "gone".toByteArray())
    }
  }

  @Test
  fun doubleDestroyIsIdempotent() {
    val key = makeKey()
    key.destroy()
    key.destroy() // must not throw
  }

  @Test
  fun hkdfCallMatchesRfc5869TestCase1() {
    // RFC 5869 A.1: IKM = 0x0b * 22, salt = 0x00..0c, info = 0xf0..f9, L = 42
    val key = CryptoKeyRef(ByteArray(32) { 0x0b })
    // hkdfDerive uses the key itself as IKM, so seed a dedicated 22-byte IKM via a
    // throwaway instance is not possible (CryptoKeyRef enforces 32-byte keys) — this
    // vector is exercised directly against Hkdf.computeHkdf instead, see below.
    val okm = com.google.crypto.tink.subtle.Hkdf.computeHkdf(
      "HMACSHA256",
      ByteArray(22) { 0x0b },
      ByteArray(13) { it.toByte() },
      ByteArray(10) { (0xf0 + it).toByte() },
      42,
    )
    assertEquals(
      "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
      okm.joinToString("") { "%02x".format(it) },
    )
  }

  @Test
  fun hkdfCallMatchesRfc5869TestCase2LongInputs() {
    // RFC 5869 A.2: IKM/salt/info = 80/80/80 bytes of sequential values, L = 82
    val ikm = ByteArray(80) { it.toByte() }
    val salt = ByteArray(80) { (it + 0x60).toByte() }
    val info = ByteArray(80) { (it + 0xb0).toByte() }
    val okm = com.google.crypto.tink.subtle.Hkdf.computeHkdf("HMACSHA256", ikm, salt, info, 82)
    assertEquals(
      "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87",
      okm.joinToString("") { "%02x".format(it) },
    )
  }

  @Test
  fun hkdfCallMatchesRfc5869TestCase3EmptySaltAndInfo() {
    // RFC 5869 A.3: IKM = 0x0b * 22, salt and info both EMPTY, L = 42 — the case that
    // behaves differently from every other vector, and that no other test touches.
    val okm = com.google.crypto.tink.subtle.Hkdf.computeHkdf(
      "HMACSHA256",
      ByteArray(22) { 0x0b },
      ByteArray(0),
      ByteArray(0),
      42,
    )
    assertEquals(
      "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
      okm.joinToString("") { "%02x".format(it) },
    )
  }
}
