/**
 * Wire format for a `BlobRecord.blob` string: `enc:` prefix + JSON `EncryptedField`.
 * Pure serialization, no crypto — DataCloak owns this format (it decides what a stored
 * ciphertext string looks like), so it lives in `core/`, not in the app's crypto engine.
 */
import assert from "node:assert/strict";
import test from "node:test";
import {
  ENC_PREFIX,
  isEncryptedField,
  serializeEncField,
  parseEncField,
} from "../core/wireFormat.ts";
import type { EncryptedField } from "../core/types.ts";

const sample: EncryptedField = { ct: "abc123", n: "def456", v: 2 };

test("wireFormat: serializeEncField prefixes with 'enc:' + JSON", () => {
  const wire = serializeEncField(sample);
  assert.equal(wire, `${ENC_PREFIX}${JSON.stringify(sample)}`);
});

test("wireFormat: parseEncField roundtrips serializeEncField's output", () => {
  const wire = serializeEncField(sample);
  assert.deepEqual(parseEncField(wire), sample);
});

test("wireFormat: parseEncField accepts a JSON string without the 'enc:' prefix too", () => {
  assert.deepEqual(parseEncField(JSON.stringify(sample)), sample);
});

test("wireFormat: parseEncField throws on a malformed EncryptedField (missing fields)", () => {
  assert.throws(
    () => parseEncField(`${ENC_PREFIX}${JSON.stringify({ ct: "x" })}`),
    /invalid EncryptedField/,
  );
});

test("wireFormat: isEncryptedField true only for strings starting with 'enc:'", () => {
  assert.equal(isEncryptedField(serializeEncField(sample)), true);
  assert.equal(isEncryptedField("plaintext legacy value"), false);
  assert.equal(isEncryptedField(null), false);
  assert.equal(isEncryptedField(undefined), false);
});
