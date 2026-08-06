/**
 * AES-256-GCM field encryption engine — isomorphic (browser WebCrypto + Deno, same
 * API). Operates purely on raw key bytes + `FieldAAD`; owns no notion of where the
 * key comes from (that's `keyDerivation.ts` + whatever `KeyProvider` adapter derives
 * it). AAD binds ciphertext to WHERE it lives (table/field/row/user) — moving a blob
 * to a different slot makes the GCM auth tag fail to verify.
 *
 * Pipeline: plaintext → gzip (if > COMPRESS_THRESHOLD) → AES-256-GCM → base64 JSON.
 *
 * `EncryptedField.v` encodes BOTH the compression choice and the AAD serialization,
 * so a blob is self-describing at decrypt time (no try-and-fallback, no double
 * decrypt): `1`=raw+AAD-v1, `2`=gzip+AAD-v1 (read-only — AAD-v1 is the unescaped
 * pipe-join that let one component's `|` collide with another's, see AAD-v2 below),
 * `3`=raw+AAD-v2, `4`=gzip+AAD-v2 (canonical, written whenever `aad.epoch` is NOT
 * set), `5`=raw+AAD-v3, `6`=gzip+AAD-v3 (written whenever `aad.epoch` IS set —
 * key-custody rotation, Fase 2.1). AAD-v2 is `JSON.stringify([userId, table, field,
 * rowId])`; AAD-v3 is the same 5-tuple PLUS `epoch`, so a row silently relabeled to a
 * different epoch (without being re-encrypted under it) fails the GCM tag check
 * instead of being trusted — the whole reason `epoch` lives in the AAD and not just as
 * plain metadata next to the ciphertext. `enc.epoch` (not `aad.epoch`) is what decrypt
 * actually rebuilds AAD-v3 from: it's the value the stored blob claims for itself,
 * exactly like `enc.v` already is — trusting it for dispatch is safe because
 * reconstructing AAD-v3 from a TAMPERED `enc.epoch` can never match a tag computed
 * under the real one, so tampering fails verification rather than being silently
 * accepted.
 */
import { gcm } from "@noble/ciphers/aes.js";
import { randomBytes, clean } from "@noble/ciphers/utils.js";
import type { FieldAAD, EncryptedField } from "./types.ts";
import { gzipCompress, gzipDecompress } from "./gzip.ts";

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

/** AAD-v1 (legacy, read-only): unescaped pipe-join — a `|` inside a component collides. */
function buildAADBytesV1(aad: FieldAAD): Uint8Array {
  return ENCODER.encode(`${aad.userId}|${aad.table}|${aad.field}|${aad.rowId}`);
}

/** AAD-v2 (canonical, epoch-unaware): JSON-stringified 4-tuple — unambiguous regardless of content. */
export function buildAADBytesV2(aad: FieldAAD): Uint8Array {
  return ENCODER.encode(
    JSON.stringify([aad.userId, aad.table, aad.field, aad.rowId]),
  );
}

/** AAD-v3 (epoch-aware, Fase 2.1): JSON-stringified 5-tuple, epoch included. */
export function buildAADBytesV3(aad: FieldAAD, epoch: number): Uint8Array {
  return ENCODER.encode(
    JSON.stringify([aad.userId, aad.table, aad.field, aad.rowId, epoch]),
  );
}

/**
 * `1`/`2` = legacy AAD-v1 (read-only), `3`/`4` = canonical AAD-v2 (epoch-unaware),
 * `5`/`6` = AAD-v3 (epoch-aware — `epoch` required, throws if missing/undefined, since
 * a v5/v6 blob is only ever produced WITH an epoch).
 */
export function buildAADBytes(
  aad: FieldAAD,
  v: 1 | 2 | 3 | 4 | 5 | 6,
  epoch?: number,
): Uint8Array {
  if (v <= 2) return buildAADBytesV1(aad);
  if (v <= 4) return buildAADBytesV2(aad);
  if (epoch === undefined) {
    throw new Error(
      `crypto.buildAADBytes: envelope v=${v} is epoch-aware but no epoch was provided.`,
    );
  }
  return buildAADBytesV3(aad, epoch);
}

/**
 * Encrypts a text field. Compresses automatically above `COMPRESS_THRESHOLD` bytes.
 * Emits epoch-aware AAD-v3 (`v: 5|6`, `enc.epoch` set) iff `aad.epoch` is provided —
 * omit it entirely for the pre-rotation wire format (`v: 3|4`), unchanged.
 */
export async function encryptField(
  dek: Uint8Array,
  plaintext: string,
  aad: FieldAAD,
): Promise<EncryptedField> {
  const raw = ENCODER.encode(plaintext);
  const shouldCompress = raw.length > COMPRESS_THRESHOLD;
  const payload = shouldCompress ? await gzipCompress(raw) : raw;
  const epochAware = aad.epoch !== undefined;

  const nonce = randomBytes(12);
  try {
    const cipher = gcm(
      dek,
      nonce,
      epochAware ? buildAADBytesV3(aad, aad.epoch!) : buildAADBytesV2(aad),
    );
    const ciphertext = cipher.encrypt(payload);
    return {
      ct: toBase64(ciphertext),
      n: toBase64(nonce),
      v: epochAware ? (shouldCompress ? 6 : 5) : shouldCompress ? 4 : 3,
      ...(epochAware ? { epoch: aad.epoch } : {}),
    };
  } finally {
    clean(nonce);
  }
}

/**
 * Decrypts a field. Throws if the AAD doesn't match (blob moved, or `enc.epoch`
 * tampered without re-encrypting) or the key is wrong. Dispatches compression AND AAD
 * serialization from `enc.v` — see the file-level doc comment for the 1–6 mapping.
 * Epoch (for v5/v6) comes from `enc.epoch` (the STORED claim), never from `aad.epoch`
 * — the caller doesn't assert which epoch a row is, the blob does.
 */
export async function decryptField(
  dek: Uint8Array,
  enc: EncryptedField,
  aad: FieldAAD,
): Promise<string> {
  if (enc.v < 1 || enc.v > 6) {
    throw new Error(`decryptField: unknown envelope version ${enc.v}`);
  }
  const ciphertext = fromBase64(enc.ct);
  const nonce = fromBase64(enc.n);
  const cipher = gcm(dek, nonce, buildAADBytes(aad, enc.v, enc.epoch));
  const payload = cipher.decrypt(ciphertext);
  const raw =
    enc.v === 2 || enc.v === 4 || enc.v === 6
      ? await gzipDecompress(payload)
      : payload;
  return DECODER.decode(raw);
}

/**
 * Encrypts an arbitrary JSON value. Always gzips — JSON is always compressible.
 * Epoch-aware iff `aad.epoch` is provided, same rule as `encryptField`.
 */
export async function encryptJson<T>(
  dek: Uint8Array,
  value: T,
  aad: FieldAAD,
): Promise<EncryptedField> {
  const json = JSON.stringify(value);
  const raw = ENCODER.encode(json);
  const compressed = await gzipCompress(raw);
  const epochAware = aad.epoch !== undefined;

  const nonce = randomBytes(12);
  try {
    const cipher = gcm(
      dek,
      nonce,
      epochAware ? buildAADBytesV3(aad, aad.epoch!) : buildAADBytesV2(aad),
    );
    return {
      ct: toBase64(cipher.encrypt(compressed)),
      n: toBase64(nonce),
      v: epochAware ? 6 : 4,
      ...(epochAware ? { epoch: aad.epoch } : {}),
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

/**
 * The AEAD operation, injected instead of performed with a raw key — same wire
 * format as `encryptField`/`decryptField`, but the actual seal/open happens wherever
 * the delegate implements it (e.g. inside a native module's isolated key instance,
 * `adapters/keyhandles/nativeModuleKeyHandle.ts`). This is what lets a `KeyHandle`
 * built around an opaque native reference produce byte-identical envelopes to one
 * built around a raw key.
 */
export interface AeadDelegate {
  seal(nonce: Uint8Array, aad: Uint8Array, plaintext: Uint8Array): Promise<Uint8Array>;
  open(nonce: Uint8Array, aad: Uint8Array, ciphertext: Uint8Array): Promise<Uint8Array>;
}

/** Same pipeline as `encryptField`, with the AEAD operation delegated. */
export async function encryptFieldWithDelegate(
  delegate: AeadDelegate,
  plaintext: string,
  aad: FieldAAD,
): Promise<EncryptedField> {
  const raw = ENCODER.encode(plaintext);
  const shouldCompress = raw.length > COMPRESS_THRESHOLD;
  const payload = shouldCompress ? await gzipCompress(raw) : raw;
  const epochAware = aad.epoch !== undefined;

  const nonce = randomBytes(12);
  try {
    const aadBytes = epochAware ? buildAADBytesV3(aad, aad.epoch!) : buildAADBytesV2(aad);
    return {
      ct: toBase64(await delegate.seal(nonce, aadBytes, payload)),
      n: toBase64(nonce),
      v: epochAware ? (shouldCompress ? 6 : 5) : shouldCompress ? 4 : 3,
      ...(epochAware ? { epoch: aad.epoch } : {}),
    };
  } finally {
    clean(nonce);
  }
}

/** Same pipeline as `decryptField`, with the AEAD operation delegated. */
export async function decryptFieldWithDelegate(
  delegate: AeadDelegate,
  enc: EncryptedField,
  aad: FieldAAD,
): Promise<string> {
  if (enc.v < 1 || enc.v > 6) {
    throw new Error(`decryptFieldWithDelegate: unknown envelope version ${enc.v}`);
  }
  const payload = await delegate.open(
    fromBase64(enc.n),
    buildAADBytes(aad, enc.v, enc.epoch),
    fromBase64(enc.ct),
  );
  const raw =
    enc.v === 2 || enc.v === 4 || enc.v === 6
      ? await gzipDecompress(payload)
      : payload;
  return DECODER.decode(raw);
}

/**
 * Mirrors `encryptJson` exactly, including the fact that it ALWAYS gzips (`v: 4|6`)
 * regardless of `COMPRESS_THRESHOLD`. Delegating to `encryptFieldWithDelegate` would emit
 * `v: 3|5` for small payloads — a silent divergence between what web writes and what
 * mobile writes for the same value. Both stay readable (the version is self-describing),
 * but "the same store has two shapes depending on which client saved it" is how a later
 * bug becomes unreproducible.
 */
export async function encryptJsonWithDelegate<T>(
  delegate: AeadDelegate,
  value: T,
  aad: FieldAAD,
): Promise<EncryptedField> {
  const compressed = await gzipCompress(ENCODER.encode(JSON.stringify(value)));
  const epochAware = aad.epoch !== undefined;
  const nonce = randomBytes(12);
  try {
    const aadBytes = epochAware ? buildAADBytesV3(aad, aad.epoch!) : buildAADBytesV2(aad);
    return {
      ct: toBase64(await delegate.seal(nonce, aadBytes, compressed)),
      n: toBase64(nonce),
      v: epochAware ? 6 : 4,
      ...(epochAware ? { epoch: aad.epoch } : {}),
    };
  } finally {
    clean(nonce);
  }
}

/** Decrypts a value encrypted with `encryptJsonWithDelegate`. */
export async function decryptJsonWithDelegate<T>(
  delegate: AeadDelegate,
  enc: EncryptedField,
  aad: FieldAAD,
): Promise<T> {
  return JSON.parse(await decryptFieldWithDelegate(delegate, enc, aad)) as T;
}
