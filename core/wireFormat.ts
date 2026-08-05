/**
 * Wire format for a `BlobRecord.blob` string — pure serialization, no crypto. Zechinus
 * decides what a stored ciphertext string looks like (`enc:` prefix + JSON), so it owns
 * this format; the actual AES-GCM encryption stays entirely behind `CryptoHandle`
 * (`core/types.ts`) — the app's own concern, however it derives its DEK.
 */
import type { EncryptedField } from "./types.ts";

/** Prefix distinguishing an encrypted blob from legacy plaintext in a DB column. */
export const ENC_PREFIX = "enc:";

/** True if the value is a blob encrypted with this wire format. */
export function isEncryptedField(
  value: string | null | undefined,
): value is string {
  return typeof value === "string" && value.startsWith(ENC_PREFIX);
}

/** Serializes an `EncryptedField` for storage in a DB text column. */
export function serializeEncField(enc: EncryptedField): string {
  return ENC_PREFIX + JSON.stringify(enc);
}

/** Parses a stored value back into an `EncryptedField`. Accepts both `enc:`-prefixed and bare JSON. */
export function parseEncField(str: string): EncryptedField {
  const json = str.startsWith(ENC_PREFIX) ? str.slice(ENC_PREFIX.length) : str;
  const obj = JSON.parse(json) as EncryptedField;
  if (!obj.ct || !obj.n || !obj.v) {
    throw new Error("wireFormat.parseEncField: invalid EncryptedField");
  }
  return obj;
}
