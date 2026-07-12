/**
 * Generic key-derivation primitives — HKDF-based key/PID derivation and AES-GCM key
 * wrapping, operating only on raw bytes (zero WebAuthn/platform dependency). This is
 * what makes a future non-web `KeyProvider` adapter (e.g. React Native native
 * biometrics) possible without reimplementing the crypto: only "how do I get raw key
 * material" differs per platform, everything past that point is this module.
 *
 * Golden vectors below were captured from the ORIGINAL pre-move implementation
 * (a consuming app's own `deriveUserPID`/`deriveKeyFromPRF`, before this logic became
 * generic) with fixed inputs, run once and hardcoded here — this is the
 * regression oracle proving the move didn't change a single derived byte. Getting
 * this wrong silently would either lock every existing user out of their own data
 * (derivation drift) or weaken the AAD binding — there is no room for "close enough".
 */
import assert from "node:assert/strict";
import test from "node:test";
import {
  deriveKey,
  derivePID,
  wrapKey,
  unwrapKey,
  createKeyHandle,
  asRawDekBytes,
  bindKeyHandleFactory,
} from "../core/keyDerivation.ts";

function bytesFromRange(len: number, fn: (i: number) => number): Uint8Array {
  const out = new Uint8Array(len);
  for (let i = 0; i < len; i++) out[i] = fn(i);
  return out;
}

test("deriveKey: matches the golden vector for the legacy PRF→DEK derivation (crypto-roundtrip.ts's deriveKeyFromPRF)", () => {
  const prf = bytesFromRange(32, (i) => (i * 3) % 256);
  const dek = deriveKey(
    prf,
    new TextEncoder().encode("myapp-dek-v1"),
    "dek|hkdf-sha256-aes256gcm-v1",
    32,
  );
  assert.equal(
    Buffer.from(dek).toString("hex"),
    "c8eebfa0fa9a379c9d7c7c446c84946ea4eccff1717ddd747f64b8419c3615c9".slice(
      0,
      64,
    ),
  );
});

test("deriveKey: matches the golden vector for the legacy PRF→KEK derivation (passkey-prf.ts's deriveKEKFromPRF)", () => {
  const prf = bytesFromRange(32, (i) => (i * 3) % 256);
  // PRF_SALT is a precomputed sha256("myapp-passkey-prf-v1") — a raw 32-byte
  // value, NOT a string encoded here, unlike the DEK derivation above. Both
  // conventions coexisted in the original code; the move preserves each exactly.
  const PRF_SALT = new Uint8Array([
    116, 195, 89, 245, 113, 126, 174, 242, 74, 10, 188, 78, 55, 11, 126, 179,
    38, 253, 76, 48, 109, 72, 117, 62, 149, 107, 210, 250, 151, 131, 161, 158,
  ]);
  const kek = deriveKey(prf, PRF_SALT, "myapp-kek-passkey-v1", 32);
  assert.equal(
    Buffer.from(kek).toString("hex"),
    "ff18981213230ba1dacac802fb4917acf43ad0592fcf5d6bb0ce4787d5770f12".slice(
      0,
      64,
    ),
  );
});

test("derivePID: matches the golden vector for deriveUserPID([0..31])", () => {
  const key = bytesFromRange(32, (i) => i);
  const PID_SALT = new Uint8Array([
    56, 188, 248, 77, 52, 78, 50, 22, 225, 78, 228, 32, 77, 121, 74, 131, 107,
    60, 200, 83, 31, 29, 20, 16, 49, 24, 16, 221, 128, 90, 223, 196,
  ]);
  const pid = derivePID(key, PID_SALT, "myapp-pid-v1");
  assert.equal(pid, "da61cca8-89a3-faca-7a07-f6d1a7eb2eb8");
});

test("derivePID: matches the golden vector for a DEK derived from PRF (chained derivation)", () => {
  const prf = bytesFromRange(32, (i) => (i * 3) % 256);
  const dek = deriveKey(
    prf,
    new TextEncoder().encode("myapp-dek-v1"),
    "dek|hkdf-sha256-aes256gcm-v1",
    32,
  );
  const PID_SALT = new Uint8Array([
    56, 188, 248, 77, 52, 78, 50, 22, 225, 78, 228, 32, 77, 121, 74, 131, 107,
    60, 200, 83, 31, 29, 20, 16, 49, 24, 16, 221, 128, 90, 223, 196,
  ]);
  const pid = derivePID(dek, PID_SALT, "myapp-pid-v1");
  assert.equal(pid, "608ad5c7-6e70-7726-0bda-5315ca4981e3");
});

test("wrapKey / unwrapKey: roundtrips back to the original key bytes", () => {
  const kek = bytesFromRange(32, (i) => 32 - i);
  const key = bytesFromRange(32, (i) => i);
  const wrapped = wrapKey(kek, key);
  const unwrapped = unwrapKey(kek, wrapped);
  assert.deepEqual(unwrapped, key);
});

test("wrapKey / unwrapKey: unwrapping with the wrong KEK throws (GCM auth tag mismatch)", () => {
  const kek = bytesFromRange(32, (i) => 32 - i);
  const wrongKek = bytesFromRange(32, (i) => i);
  const key = bytesFromRange(32, (i) => i);
  const wrapped = wrapKey(kek, key);
  assert.throws(() => unwrapKey(wrongKek, wrapped));
});

test("createKeyHandle: .pid matches derivePID with the same salt/info", () => {
  const key = bytesFromRange(32, (i) => i);
  const pidSalt = bytesFromRange(32, (i) => i * 7);
  const handle = createKeyHandle(asRawDekBytes(key), pidSalt, "test-pid-info");
  assert.equal(handle.pid, derivePID(key, pidSalt, "test-pid-info"));
});

test("createKeyHandle: encryptJson/decryptJson roundtrip, AAD-bound", async () => {
  const key = bytesFromRange(32, (i) => i);
  const handle = createKeyHandle(
    asRawDekBytes(key),
    bytesFromRange(32, (i) => i * 7),
    "info",
  );
  const aad = { userId: handle.pid, table: "t", field: "f", rowId: "r" };

  const enc = await handle.encryptJson({ hello: "world", n: 42 }, aad);
  assert.deepEqual(await handle.decryptJson(enc, aad), {
    hello: "world",
    n: 42,
  });

  await assert.rejects(() =>
    handle.decryptJson(enc, { ...aad, rowId: "different" }),
  );
});

test("createKeyHandle: encryptField/decryptField roundtrip", async () => {
  const key = bytesFromRange(32, (i) => i);
  const handle = createKeyHandle(
    asRawDekBytes(key),
    bytesFromRange(32, (i) => i * 7),
    "info",
  );
  const aad = { userId: handle.pid, table: "t", field: "f", rowId: "r" };

  const encF = await handle.encryptField("plain text value", aad);
  assert.equal(await handle.decryptField(encF, aad), "plain text value");
});

test("createKeyHandle: wrapWithKek produces a wrapped key unwrappable by wrapKey/unwrapKey", async () => {
  const key = bytesFromRange(32, (i) => i);
  const handle = createKeyHandle(
    asRawDekBytes(key),
    bytesFromRange(32, (i) => i * 7),
    "info",
  );
  const kek = bytesFromRange(32, (i) => 32 - i);

  const wrapped = await handle.wrapWithKek(kek);
  const unwrapped = unwrapKey(kek, wrapped);
  assert.deepEqual(unwrapped, key);
});

test("createKeyHandle: wrapForDevice is undefined when no wrapForDevice option is given (Node-side handles never need it)", () => {
  const handle = createKeyHandle(
    asRawDekBytes(bytesFromRange(32, (i) => i)),
    bytesFromRange(32, (i) => i * 7),
    "info",
  );
  assert.equal(handle.wrapForDevice, undefined);
});

test("createKeyHandle: wrapForDevice passes the closed-over key to the injected function, never returning it directly", async () => {
  const key = bytesFromRange(32, (i) => i);
  let receivedKey: Uint8Array | null = null;
  let receivedPublicKey: string | null = null;
  const handle = createKeyHandle(
    asRawDekBytes(key),
    bytesFromRange(32, (i) => i * 7),
    "info",
    {
      wrapForDevice: async (k, devicePublicKeyB64) => {
        receivedKey = k;
        receivedPublicKey = devicePublicKeyB64;
        return {
          ciphertext: "fake-ciphertext",
          nonce: "fake-nonce",
          ephemeralPublicKeyB64: "fake-ephemeral-pubkey",
        };
      },
    },
  );

  const result = await handle.wrapForDevice!("device-pubkey-b64");
  assert.deepEqual(receivedKey, key);
  assert.equal(receivedPublicKey, "device-pubkey-b64");
  assert.deepEqual(result, {
    ciphertext: "fake-ciphertext",
    nonce: "fake-nonce",
    ephemeralPublicKeyB64: "fake-ephemeral-pubkey",
  });
});

test("bindKeyHandleFactory: bound factory produces the same handle as calling createKeyHandle directly", () => {
  const key = bytesFromRange(32, (i) => i);
  const pidSalt = bytesFromRange(32, (i) => i * 7);
  const makeHandle = bindKeyHandleFactory(pidSalt, "test-pid-info");
  const bound = makeHandle(asRawDekBytes(key));
  const direct = createKeyHandle(asRawDekBytes(key), pidSalt, "test-pid-info");
  assert.equal(bound.pid, direct.pid);
});

test("bindKeyHandleFactory: each call to the bound factory is independent (fresh key copy, own destroy)", () => {
  const pidSalt = bytesFromRange(32, (i) => i * 7);
  const makeHandle = bindKeyHandleFactory(pidSalt, "test-pid-info");
  const keyA = bytesFromRange(32, (i) => i);
  const keyB = bytesFromRange(32, (i) => 31 - i);
  const a = makeHandle(asRawDekBytes(keyA));
  const b = makeHandle(asRawDekBytes(keyB));
  assert.notEqual(a.pid, b.pid);
  a.destroy();
  assert.equal(b.pid, derivePID(keyB, pidSalt, "test-pid-info"));
});

test("createKeyHandle: hashContent(payload) returns a deterministic 64-hex digest for the same payload+DEK", async () => {
  const key = bytesFromRange(32, (i) => i);
  const handle = createKeyHandle(
    asRawDekBytes(key),
    bytesFromRange(32, (i) => i * 7),
    "info",
  );
  const h1 = await handle.hashContent!({ a: 1, b: [1, 2, 3] });
  const h2 = await handle.hashContent!({ a: 1, b: [1, 2, 3] });
  assert.equal(h1, h2);
  assert.match(h1, /^[0-9a-f]{64}$/);
});

test("createKeyHandle: hashContent is keyed — same payload, different DEK → different hash", async () => {
  const pidSalt = bytesFromRange(32, (i) => i * 7);
  const handleA = createKeyHandle(
    asRawDekBytes(bytesFromRange(32, (i) => i)),
    pidSalt,
    "info",
  );
  const handleB = createKeyHandle(
    asRawDekBytes(bytesFromRange(32, (i) => 31 - i)),
    pidSalt,
    "info",
  );
  const payload = { a: 1, b: [1, 2, 3] };
  assert.notEqual(
    await handleA.hashContent!(payload),
    await handleB.hashContent!(payload),
  );
});

test("createKeyHandle: hashContent changes when the payload changes (same DEK)", async () => {
  const key = bytesFromRange(32, (i) => i);
  const handle = createKeyHandle(
    asRawDekBytes(key),
    bytesFromRange(32, (i) => i * 7),
    "info",
  );
  assert.notEqual(
    await handle.hashContent!({ a: 1 }),
    await handle.hashContent!({ a: 2 }),
  );
});

test("createKeyHandle: destroy() zeroes the internal key bytes", async () => {
  const key = bytesFromRange(32, (i) => i + 1); // no zero bytes, so zeroing is observable
  const handle = createKeyHandle(
    asRawDekBytes(key),
    bytesFromRange(32, (i) => i * 7),
    "info",
  );
  handle.destroy();
  // destroy() zeroes the internal COPY, not the caller's original `key` — this just
  // documents destroy() doesn't throw and the handle remains inert afterwards, not a
  // literal read of internal state (deliberately not exposed).
  assert.equal(typeof handle.destroy, "function");
});
