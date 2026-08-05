/**
 * `webauthnKeyProvider`'s WebAuthn ceremony itself (`registerPasskeyWithPRF`,
 * `getDEKFromPasskey`, ...) needs a real `navigator.credentials` and can't run under
 * `node --test` — that's covered by the consuming app's own E2E suite. What's tested
 * here is the part that doesn't touch the browser: config is threaded correctly into
 * the underlying `deriveKey` call, verified against the same fixed-input regression
 * vector used for `zechinus/tests/keyDerivation.test.ts`.
 */
import assert from "node:assert/strict";
import test from "node:test";
import { webauthnKeyProvider } from "../adapters/webauthnKeyProvider.ts";

function bytesFromRange(len: number, fn: (i: number) => number): Uint8Array {
  const out = new Uint8Array(len);
  for (let i = 0; i < len; i++) out[i] = fn(i);
  return out;
}

test("webauthnKeyProvider.deriveKEKFromPRF: matches the golden vector, using config.prfSalt/config.kekInfo not module constants", () => {
  const prf = bytesFromRange(32, (i) => (i * 3) % 256);
  const PRF_SALT = new Uint8Array([
    116, 195, 89, 245, 113, 126, 174, 242, 74, 10, 188, 78, 55, 11, 126, 179,
    38, 253, 76, 48, 109, 72, 117, 62, 149, 107, 210, 250, 151, 131, 161, 158,
  ]);

  const provider = webauthnKeyProvider({
    rpId: "test.example",
    rpName: "Test",
    prfSalt: PRF_SALT,
    dekSalt: new TextEncoder().encode("myapp-dek-v1"),
    dekInfo: "dek|hkdf-sha256-aes256gcm-v1",
    kekInfo: "myapp-kek-passkey-v1",
  });

  const kek = provider.deriveKEKFromPRF(prf.buffer as ArrayBuffer);
  assert.equal(
    Buffer.from(kek).toString("hex"),
    "ff18981213230ba1dacac802fb4917acf43ad0592fcf5d6bb0ce4787d5770f12".slice(
      0,
      64,
    ),
  );
});

test("webauthnKeyProvider: a different config produces different derived material (config actually flows through, not ignored)", () => {
  const prf = bytesFromRange(32, (i) => (i * 3) % 256);

  const providerA = webauthnKeyProvider({
    rpId: "a.example",
    rpName: "A",
    prfSalt: bytesFromRange(32, () => 1),
    dekSalt: new TextEncoder().encode("salt-a"),
    dekInfo: "info-a",
    kekInfo: "kek-a",
  });
  const providerB = webauthnKeyProvider({
    rpId: "b.example",
    rpName: "B",
    prfSalt: bytesFromRange(32, () => 2),
    dekSalt: new TextEncoder().encode("salt-b"),
    dekInfo: "info-b",
    kekInfo: "kek-b",
  });

  const kekA = providerA.deriveKEKFromPRF(prf.buffer as ArrayBuffer);
  const kekB = providerB.deriveKEKFromPRF(prf.buffer as ArrayBuffer);
  assert.notDeepEqual(kekA, kekB);
});
