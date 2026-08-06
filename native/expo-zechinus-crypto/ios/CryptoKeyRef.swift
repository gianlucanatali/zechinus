import CryptoKit
import ExpoModulesCore
import Foundation

enum ZechinusCryptoError: Error, LocalizedError {
  case destroyed
  case noMacKey
  case invalidKeyLength(Int)
  case invalidNonceLength(Int)
  case ciphertextTooShort(Int)
  case invalidHkdfLength(Int)
  case accessControlUnavailable
  case keychainWrite(OSStatus)

  var errorDescription: String? {
    switch self {
    case .destroyed: return "CryptoKey: already destroyed"
    case .noMacKey: return "CryptoKey: no MAC key — call initMacKey first"
    case .invalidKeyLength(let n): return "CryptoKey: key must be 32 bytes, got \(n)"
    case .invalidNonceLength(let n): return "CryptoKey: nonce must be 12 bytes, got \(n)"
    case .ciphertextTooShort(let n): return "CryptoKey: ciphertext must include the 16-byte GCM tag, got \(n) bytes"
    case .invalidHkdfLength(let n): return "CryptoKey: HKDF length must be 1...8160, got \(n)"
    case .accessControlUnavailable: return "CryptoKey: could not create a biometric-gated Keychain access control (no biometry enrolled on this device?)"
    case .keychainWrite(let status): return "CryptoKey: Keychain write failed with status \(status)"
    }
  }
}

/// What `cacheKeyForZeroTap` persists to the Keychain, opaque to anything reading it
/// outside this module — the biometric ACL on the Keychain item is what actually
/// protects it, this struct only describes the shape of the plaintext-once-inside-
/// Secure-Enclave-access payload.
struct CachedEntry: Codable {
  let keyHex: String
  let dekEpoch: Int
  let credentialId: String
}

extension Data {
  /// Lowercase-or-uppercase hex string -> bytes. `nil` on malformed input (odd length,
  /// non-hex characters) rather than trapping — a corrupted/tampered Keychain entry
  /// must fail closed (`tryRestoreFromNativeCache` returns `nil`), never crash.
  init?(hexString: String) {
    guard hexString.count % 2 == 0 else { return nil }
    var bytes = [UInt8]()
    bytes.reserveCapacity(hexString.count / 2)
    var index = hexString.startIndex
    while index < hexString.endIndex {
      let next = hexString.index(index, offsetBy: 2)
      guard let byte = UInt8(hexString[index..<next], radix: 16) else { return nil }
      bytes.append(byte)
      index = next
    }
    self = Data(bytes)
  }

  var hexString: String {
    map { String(format: "%02x", $0) }.joined()
  }
}

/// One key, one instance — the native counterpart of one Web Worker on web. Two handles
/// alive at once (a DEK rotation keeps `previousCryptoHandle` alongside the current one)
/// means two independent instances, so `destroy()` on one cannot reach the other.
/// The key material is never returned to JS by any method here.
public final class CryptoKeyRef: SharedObject {
  private var key: SymmetricKey?
  private var macKey: SymmetricKey?

  public init(rawBytes: Data) throws {
    guard rawBytes.count == 32 else { throw ZechinusCryptoError.invalidKeyLength(rawBytes.count) }
    self.key = SymmetricKey(data: rawBytes)
    super.init()
  }

  private func requireKey() throws -> SymmetricKey {
    guard let key else { throw ZechinusCryptoError.destroyed }
    return key
  }

  public func initMacKey(_ bytes: Data) throws {
    _ = try requireKey()
    macKey = SymmetricKey(data: bytes)
  }

  public func aesGcmEncrypt(_ nonce: Data, _ aad: Data, _ plaintext: Data) throws -> Data {
    let key = try requireKey()
    guard nonce.count == 12 else { throw ZechinusCryptoError.invalidNonceLength(nonce.count) }
    let sealed = try AES.GCM.seal(
      plaintext, using: key, nonce: try AES.GCM.Nonce(data: nonce), authenticating: aad
    )
    // Convention matching @noble/ciphers: ciphertext with the 16-byte GCM tag appended.
    return sealed.ciphertext + sealed.tag
  }

  public func aesGcmDecrypt(_ nonce: Data, _ aad: Data, _ ciphertext: Data) throws -> Data {
    let key = try requireKey()
    guard nonce.count == 12 else { throw ZechinusCryptoError.invalidNonceLength(nonce.count) }
    guard ciphertext.count > 16 else { throw ZechinusCryptoError.ciphertextTooShort(ciphertext.count) }
    // `Data(...)` around each slice is REQUIRED: a Data slice keeps the parent's index
    // base, so slicing an already-sliced Data reads from the wrong offset. Re-wrapping
    // rebases to 0. Task A6 exercises this path through this method, not through raw
    // CryptoKit — which is the only way the bug would have been caught.
    let body = Data(ciphertext.prefix(ciphertext.count - 16))
    let tag = Data(ciphertext.suffix(16))
    let sealed = try AES.GCM.SealedBox(
      nonce: try AES.GCM.Nonce(data: nonce), ciphertext: body, tag: tag
    )
    return try AES.GCM.open(sealed, using: key, authenticating: aad)
  }

  public func hkdfDerive(_ salt: Data, _ info: String, _ length: Int) throws -> Data {
    let key = try requireKey()
    guard length > 0 && length <= 255 * 32 else { throw ZechinusCryptoError.invalidHkdfLength(length) }
    let derived = HKDF<SHA256>.deriveKey(
      inputKeyMaterial: key, salt: salt, info: Data(info.utf8), outputByteCount: length
    )
    return derived.withUnsafeBytes { Data($0) }
  }

  public func hmacSha256(_ payload: Data) throws -> String {
    _ = try requireKey()
    guard let macKey else { throw ZechinusCryptoError.noMacKey }
    return Data(HMAC<SHA256>.authenticationCode(for: payload, using: macKey))
      .map { String(format: "%02x", $0) }.joined()
  }

  /// Wraps THIS key (not one passed in) under the given KEK. No explicit nonce:
  /// `AES.GCM.seal` generates a fresh cryptographically secure one.
  public func wrapSelf(_ kek: Data) throws -> [String: String] {
    let key = try requireKey()
    let sealed = try AES.GCM.seal(key.withUnsafeBytes { Data($0) }, using: SymmetricKey(data: kek))
    return [
      "ciphertext": (sealed.ciphertext + sealed.tag).base64EncodedString(),
      "nonce": Data(sealed.nonce).base64EncodedString(),
    ]
  }

  /// Idempotent: destroying twice is legitimate. Dropping the reference is enough —
  /// CryptoKit's SymmetricKey zeroes its own backing store on deallocation.
  public func destroy() {
    key = nil
    macKey = nil
  }

  /// The only place in this module that turns key material back into plain bytes —
  /// `internal` (not `public`), so it exists for `ExpoZechinusCryptoModule`'s Keychain
  /// functions in this same target to call, and is unreachable from JS: it is never
  /// listed inside `Class(CryptoKey.self) { ... }`, so the Expo Modules bridge has no
  /// way to invoke it. The exported hex string goes straight into a Keychain item
  /// gated by `.biometryCurrentSet` (`cacheKeyForZeroTap`) — it is never logged,
  /// returned across the JS bridge, or persisted anywhere else.
  func exportForKeychainOnly() throws -> String {
    try requireKey().withUnsafeBytes { Data($0) }.hexString
  }
}
