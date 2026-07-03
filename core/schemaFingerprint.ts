/**
 * Fingerprint of a Zod schema — preventive versioning guardrail.
 *
 * The `migrators` guardrail (in `store.ts`) catches "bumped `version` but forgot the
 * migrator". It does NOT catch the opposite case: "changed the schema's SHAPE without
 * touching `version` at all" — without this module, that drift is only caught by Zod on
 * read, against old data that no longer validates (reactive: it happens when the app
 * touches real data, not when the author edits the schema).
 *
 * `fingerprintSchema` computes a stable hash of the shape (field names, base type,
 * encrypted yes/no) — deterministic with respect to field declaration order
 * (irrelevant) but sensitive to ANY other visible change. `defineStore` compares it
 * against the `schemaFingerprint` declared in the def: if it's missing or doesn't
 * match, it throws IMMEDIATELY (at definition, i.e. at boot/import/test) with the
 * correct value in the message — the author pastes it in and, at that moment,
 * consciously decides whether a `version` bump + migrator is also needed.
 *
 * Known limitation (bounded depth, not a full diffing engine): the shape is
 * inspected up to `MAX_DEPTH` nesting levels (object/array); beyond that depth a
 * change goes undetected. Sufficient for EW's real schemas (few levels); if deeper
 * inspection is ever needed, raising `MAX_DEPTH` is the first thing to try.
 */

import { z } from "zod";
import { isEncryptedSchema } from "./encryption.ts";

const MAX_DEPTH = 3;

interface ZodDefLike {
  type: string;
  innerType?: z.ZodType;
  shape?: Record<string, z.ZodType>;
  element?: z.ZodType;
}

function defOf(schema: z.ZodType): ZodDefLike {
  return (schema as unknown as { def: ZodDefLike }).def;
}

function describeType(schema: z.ZodType, depth: number): string {
  const def = defOf(schema);
  switch (def.type) {
    case "optional":
    case "nullable":
    case "default":
      return `${def.type}<${describeType(def.innerType!, depth)}>`;
    case "object":
      if (depth <= 0 || !def.shape) return "object";
      return `object{${describeShape(def.shape, depth - 1)}}`;
    case "array":
      if (depth <= 0 || !def.element) return "array";
      return `array<${describeType(def.element, depth - 1)}>`;
    default:
      return def.type;
  }
}

function describeShape(
  shape: Record<string, z.ZodType>,
  depth: number,
): string {
  return Object.keys(shape)
    .sort()
    .map(
      (key) =>
        `${key}:${describeType(shape[key], depth)}:${isEncryptedSchema(shape[key]) ? "enc" : "plain"}`,
    )
    .join(",");
}

/** Sync, non-cryptographic hash (djb2-xor) — not a security boundary, just a shape
 * signature for a definition-time guard; doesn't need cryptographic collision
 * resistance, and must be sync because `defineStore` isn't async. */
function stableHash(input: string): string {
  let hash = 5381;
  for (let i = 0; i < input.length; i++) {
    hash = (hash * 33) ^ input.charCodeAt(i);
  }
  return (hash >>> 0).toString(16).padStart(8, "0");
}

export function fingerprintSchema(
  schema: z.ZodType,
  encryptFlag: "all" | "none" | "fields",
): string {
  return stableHash(
    `encrypt:${encryptFlag}|${describeType(schema, MAX_DEPTH)}`,
  );
}
