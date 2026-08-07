import Foundation
import Security

/// Keychain access for the OS-gated zero-tap cache — pulled out of
/// `ExpoZechinusCryptoModule`'s `AsyncFunction` closures into a plain type for the same
/// reason `CryptoKeyRef` is a plain type and not the `Module` itself (see that file's own
/// doc comment): a `Module` isn't comfortably instantiable in XCTest, and this type is what
/// `ZeroTapKeychainStoreTests.swift` needs to test directly.
enum ZeroTapKeychainStore {
  private static func account(_ userId: String) -> String { "zechinus.zero-tap-dek.v1.\(userId)" }

  /// `.biometryCurrentSet` (NOT `.biometryAny`) is deliberate: enrolling a new face or
  /// finger invalidates the item, so an attacker who adds their own biometric to an
  /// unlocked device cannot reach the cached DEK. `WhenUnlockedThisDeviceOnly` keeps it
  /// out of every backup and out of iCloud.
  static func cache(
    key: CryptoKeyRef,
    userId: String,
    dekEpoch: Int,
    credentialId: String
  ) throws {
    var accessControlError: Unmanaged<CFError>?
    guard let acl = SecAccessControlCreateWithFlags(
      nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, .biometryCurrentSet, &accessControlError
    ) else { throw ZechinusCryptoError.accessControlUnavailable }

    let payload = try JSONEncoder().encode(
      CachedEntry(keyHex: try key.exportForKeychainOnly(), dekEpoch: dekEpoch, credentialId: credentialId)
    )
    let query: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: "zechinus",
      kSecAttrAccount as String: account(userId),
      kSecAttrAccessControl as String: acl,
      kSecValueData as String: payload,
    ]
    SecItemDelete(query as CFDictionary) // idempotent: replaces any previous entry
    let status = SecItemAdd(query as CFDictionary, nil)
    guard status == errSecSuccess else { throw ZechinusCryptoError.keychainWrite(status) }
  }

  /// The OS shows the biometric prompt HERE, inside `SecItemCopyMatching`, and returns
  /// nothing if it fails. Returns `nil` (never throws) on user cancel / no biometrics /
  /// nothing cached: all expected outcomes, the caller falls back to a real ceremony.
  static func tryRestore(userId: String) -> (key: CryptoKeyRef, dekEpoch: Int, credentialId: String)? {
    let query: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: "zechinus",
      kSecAttrAccount as String: account(userId),
      kSecReturnData as String: true,
      kSecUseOperationPrompt as String: NSLocalizedString("zechinus.unlock.prompt", comment: ""),
    ]
    var item: CFTypeRef?
    guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess,
          let data = item as? Data,
          let entry = try? JSONDecoder().decode(CachedEntry.self, from: data),
          let keyBytes = Data(hexString: entry.keyHex),
          let restored = try? CryptoKeyRef(rawBytes: keyBytes)
    else { return nil }

    return (key: restored, dekEpoch: entry.dekEpoch, credentialId: entry.credentialId)
  }

  static func clear(userId: String) {
    let query: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: "zechinus",
      kSecAttrAccount as String: account(userId),
    ]
    SecItemDelete(query as CFDictionary) // no-op (not an error) when nothing is cached
  }
}
