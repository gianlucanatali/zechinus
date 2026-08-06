import { gcm } from "@noble/ciphers/aes.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { randomBytes } from "@noble/ciphers/utils.js";

const b64 = (b) => Buffer.from(b).toString("base64");
const hex = (b) => Buffer.from(b).toString("hex");

const key = randomBytes(32);
const nonce = randomBytes(12);
const aad = new TextEncoder().encode(JSON.stringify(["user-1", "table", "field", "row-1"]));
const plaintext = new TextEncoder().encode("interop test payload — DEK isolation vectors");
const ciphertext = gcm(key, nonce, aad).encrypt(plaintext);

const salt = randomBytes(16);
const info = "zechinus/content-hash-v1";
const derived = hkdf(sha256, key, salt, new TextEncoder().encode(info), 32);

const macPayload = new TextEncoder().encode(JSON.stringify({ a: 1, b: "test" }));
const mac = hmac(sha256, derived, macPayload);

console.log(JSON.stringify({
  key: b64(key), nonce: b64(nonce), aad: b64(aad),
  plaintext: b64(plaintext), ciphertext: b64(ciphertext),
  hkdfSalt: b64(salt), hkdfInfo: info, hkdfLength: 32, hkdfOutput: b64(derived),
  hmacPayload: b64(macPayload), hmacOutput: hex(mac),
}, null, 2));
