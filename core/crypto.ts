/**
 * AES-256-GCM field encryption engine — isomorphic (browser WebCrypto + Deno, same
 * API). Operates purely on raw key bytes + `FieldAAD`; owns no notion of where the
 * key comes from (that's `keyDerivation.ts` + whatever `KeyProvider` adapter derives
 * it). AAD binds ciphertext to WHERE it lives (table/field/row/user) — moving a blob
 * to a different slot makes the GCM auth tag fail to verify.
 *
 * Pipeline: plaintext → gzip (if > COMPRESS_THRESHOLD) → AES-256-GCM → base64 JSON.
 */
import { gcm } from "@noble/ciphers/aes.js";
import { randomBytes, clean } from "@noble/ciphers/utils.js";
import type { FieldAAD, EncryptedField } from "./types.ts";

const COMPRESS_THRESHOLD = 64;

const ENCODER = new TextEncoder();
const DECODER = new TextDecoder("utf-8", { fatal: true });

function toBase64(bytes: Uint8Array): string {
  const CHUNK = 8192;
  let out = "";
  for (let i = 0; i < bytes.length; i += CHUNK)
    out += String.fromCharCode(...bytes.subarray(i, i + CHUNK));
  return btoa(out);
}

function fromBase64(b64: string): Uint8Array {
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
}

function buildAADBytes(aad: FieldAAD): Uint8Array {
  return ENCODER.encode(`${aad.userId}|${aad.table}|${aad.field}|${aad.rowId}`);
}

async function compress(data: Uint8Array): Promise<Uint8Array> {
  const cs = new CompressionStream("gzip");
  const writer = cs.writable.getWriter();
  writer.write(data as Uint8Array<ArrayBuffer>);
  writer.close();
  return new Uint8Array(await new Response(cs.readable).arrayBuffer());
}

async function decompress(data: Uint8Array): Promise<Uint8Array> {
  const ds = new DecompressionStream("gzip");
  const writer = ds.writable.getWriter();
  writer.write(data as Uint8Array<ArrayBuffer>);
  writer.close();
  return new Uint8Array(await new Response(ds.readable).arrayBuffer());
}

/** Encrypts a text field. Compresses automatically above `COMPRESS_THRESHOLD` bytes. */
export async function encryptField(
  dek: Uint8Array,
  plaintext: string,
  aad: FieldAAD,
): Promise<EncryptedField> {
  const raw = ENCODER.encode(plaintext);
  const shouldCompress = raw.length > COMPRESS_THRESHOLD;
  const payload = shouldCompress ? await compress(raw) : raw;

  const nonce = randomBytes(12);
  try {
    const cipher = gcm(dek, nonce, buildAADBytes(aad));
    const ciphertext = cipher.encrypt(payload);
    return {
      ct: toBase64(ciphertext),
      n: toBase64(nonce),
      v: shouldCompress ? 2 : 1,
    };
  } finally {
    clean(nonce);
  }
}

/** Decrypts a field. Throws if the AAD doesn't match (blob moved) or the key is wrong. */
export async function decryptField(
  dek: Uint8Array,
  enc: EncryptedField,
  aad: FieldAAD,
): Promise<string> {
  const ciphertext = fromBase64(enc.ct);
  const nonce = fromBase64(enc.n);
  const cipher = gcm(dek, nonce, buildAADBytes(aad));
  const payload = cipher.decrypt(ciphertext);
  const raw = enc.v === 2 ? await decompress(payload) : payload;
  return DECODER.decode(raw);
}

/** Encrypts an arbitrary JSON value. Always gzips — JSON is always compressible. */
export async function encryptJson<T>(
  dek: Uint8Array,
  value: T,
  aad: FieldAAD,
): Promise<EncryptedField> {
  const json = JSON.stringify(value);
  const raw = ENCODER.encode(json);
  const compressed = await compress(raw);

  const nonce = randomBytes(12);
  try {
    const cipher = gcm(dek, nonce, buildAADBytes(aad));
    return {
      ct: toBase64(cipher.encrypt(compressed)),
      n: toBase64(nonce),
      v: 2,
    };
  } finally {
    clean(nonce);
  }
}

/** Decrypts a JSON value encrypted with `encryptJson`. */
export async function decryptJson<T>(
  dek: Uint8Array,
  enc: EncryptedField,
  aad: FieldAAD,
): Promise<T> {
  const str = await decryptField(dek, enc, aad);
  return JSON.parse(str) as T;
}
