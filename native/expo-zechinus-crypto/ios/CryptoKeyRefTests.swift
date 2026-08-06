import XCTest
@testable import ExpoZechinusCrypto

final class CryptoKeyRefTests: XCTestCase {
  private func makeKey() throws -> CryptoKeyRef { try CryptoKeyRef(rawBytes: Data(repeating: 1, count: 32)) }

  func testRejectsWrongKeyLength() {
    XCTAssertThrowsError(try CryptoKeyRef(rawBytes: Data(repeating: 1, count: 16)))
  }

  func testRoundTrip() throws {
    let key = try makeKey()
    let nonce = Data(repeating: 2, count: 12)
    let aad = Data("aad".utf8)
    let ct = try key.aesGcmEncrypt(nonce, aad, Data("hello".utf8))
    XCTAssertEqual(try key.aesGcmDecrypt(nonce, aad, ct), Data("hello".utf8))
  }

  func testTruncatedCiphertextThrowsInsteadOfCrashing() throws {
    let key = try makeKey()
    XCTAssertThrowsError(
      try key.aesGcmDecrypt(Data(repeating: 2, count: 12), Data(), Data(repeating: 0, count: 8))
    )
  }

  func testWrongAadFailsAuthentication() throws {
    let key = try makeKey()
    let nonce = Data(repeating: 2, count: 12)
    let ct = try key.aesGcmEncrypt(nonce, Data("right".utf8), Data("hello".utf8))
    XCTAssertThrowsError(try key.aesGcmDecrypt(nonce, Data("wrong".utf8), ct))
  }

  /// The invariant that makes the whole model correct: two keys alive together
  /// (a rotation keeps `previousCryptoHandle` alongside the current one) are
  /// independent instances, and destroying one never touches the other.
  func testDestroyingOneInstanceLeavesTheOtherUsable() throws {
    let current = try CryptoKeyRef(rawBytes: Data(repeating: 1, count: 32))
    let previous = try CryptoKeyRef(rawBytes: Data(repeating: 9, count: 32))
    let nonce = Data(repeating: 2, count: 12)

    previous.destroy()

    XCTAssertNoThrow(try current.aesGcmEncrypt(nonce, Data(), Data("still works".utf8)))
    XCTAssertThrowsError(try previous.aesGcmEncrypt(nonce, Data(), Data("gone".utf8)))
  }

  func testDoubleDestroyIsIdempotent() throws {
    let key = try makeKey()
    key.destroy()
    key.destroy() // must not throw
  }
}
