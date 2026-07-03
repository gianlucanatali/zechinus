/**
 * `enc()` — encrypted-field marker on top of a Zod schema.
 *
 * Philosophy (see plan "MODELLO DATI UFFICIALE"): the author declares the data
 * *shape* with Zod and marks the fields that must be encrypted with `enc()`. The
 * framework decides the mechanics (which end up in the blob, AAD, etc.). `enc()`
 * does NOT transform the schema: it returns the **same** Zod instance (so it keeps
 * validating normally) and registers it in an internal `WeakSet`, so the framework
 * can recognize it.
 *
 * v1 status: used to (a) trigger the "explicit encryption" guardrail and (b)
 * recognize the mixed case (some fields encrypted, others plaintext) — now
 * implemented for `identity: "many"`, still an explicit error for other
 * cardinalities. See `schemaFingerprint.ts` for how field-level `enc()` tags feed
 * the versioning guardrail too.
 */

import { z } from "zod";

const ENCRYPTED = new WeakSet<object>();

/** Marks a Zod schema as an encrypted field. Returns the same instance (still validates). */
export function enc<S extends z.ZodType>(schema: S): S {
  ENCRYPTED.add(schema as unknown as object);
  return schema;
}

/** True if the schema has been marked with `enc()`. */
export function isEncryptedSchema(schema: z.ZodType): boolean {
  return ENCRYPTED.has(schema as unknown as object);
}

/**
 * Returns the keys of a `z.object` whose values are marked `enc()`.
 * For non-object schemas returns `[]` (no key-level field to mark).
 */
export function collectEncryptedKeys(schema: z.ZodType): string[] {
  if (!(schema instanceof z.ZodObject)) return [];
  const shape = schema.shape as Record<string, z.ZodType>;
  return Object.keys(shape).filter((k) => isEncryptedSchema(shape[k]));
}
