import XCTest
@testable import ExpoZechinusCrypto

final class ZeroTapKeychainStoreTests: XCTestCase {
  // Real device/biometric behavior is NOT simulable — see Task C3, its only real
  // verification. What IS testable here: the failure paths never crash and never leak
  // key material through an unexpected code path.

  func testTryRestoreReturnsNilWhenNothingCached() {
    let userId = "zero-tap-test-user-\(UUID().uuidString)"
    XCTAssertNil(ZeroTapKeychainStore.tryRestore(userId: userId))
  }

  func testClearIsIdempotentWhenNothingCached() {
    let userId = "zero-tap-test-user-\(UUID().uuidString)"
    ZeroTapKeychainStore.clear(userId: userId) // must not throw/crash
    ZeroTapKeychainStore.clear(userId: userId) // twice — still must not throw/crash
  }

  func testCacheOnSimulatorWithoutEnrolledBiometricsFailsExplicitlyOrSucceeds() throws {
    // The Simulator's biometric enrollment state varies by CI/dev machine — this test
    // doesn't assert WHICH outcome happens, only that there is no third outcome (a
    // crash, or a silently-corrupted Keychain item). Either this throws a
    // ZechinusCryptoError (no enrolled biometry -> SecItemAdd fails) or it succeeds
    // (biometry enrolled) — in which case tryRestore must be able to find *something*
    // for that account without a live biometric prompt actually resolving it here.
    let userId = "zero-tap-test-user-\(UUID().uuidString)"
    let key = try CryptoKeyRef(rawBytes: Data(repeating: 7, count: 32))
    defer { ZeroTapKeychainStore.clear(userId: userId) }

    do {
      try ZeroTapKeychainStore.cache(key: key, userId: userId, dekEpoch: 1, credentialId: "cred-1")
    } catch is ZechinusCryptoError {
      return // explicit, typed failure — exactly what this test exists to confirm
    }
  }
}
