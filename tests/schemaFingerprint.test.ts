import assert from "node:assert/strict";
import test from "node:test";
import { z } from "zod";

import { fingerprintSchema, enc } from "../index.ts";

test("fingerprintSchema: same schema → same fingerprint (deterministic)", () => {
  const a = fingerprintSchema(
    z.object({ a: z.string(), b: z.number() }),
    "all",
  );
  const b = fingerprintSchema(
    z.object({ a: z.string(), b: z.number() }),
    "all",
  );
  assert.equal(a, b);
});

test("fingerprintSchema: different field order → same fingerprint (not a shape change)", () => {
  const a = fingerprintSchema(
    z.object({ a: z.string(), b: z.number() }),
    "all",
  );
  const b = fingerprintSchema(
    z.object({ b: z.number(), a: z.string() }),
    "all",
  );
  assert.equal(a, b);
});

test("fingerprintSchema: field added → different fingerprint", () => {
  const a = fingerprintSchema(z.object({ a: z.string() }), "all");
  const b = fingerprintSchema(
    z.object({ a: z.string(), b: z.number() }),
    "all",
  );
  assert.notEqual(a, b);
});

test("fingerprintSchema: a field's type changed → different fingerprint", () => {
  const a = fingerprintSchema(z.object({ a: z.string() }), "all");
  const b = fingerprintSchema(z.object({ a: z.number() }), "all");
  assert.notEqual(a, b);
});

test("fingerprintSchema: a field becomes enc() → different fingerprint", () => {
  const a = fingerprintSchema(
    z.object({ id: z.string(), secret: z.string() }),
    "fields",
  );
  const b = fingerprintSchema(
    z.object({ id: z.string(), secret: enc(z.string()) }),
    "fields",
  );
  assert.notEqual(a, b);
});

test("fingerprintSchema: encrypt:'all' vs 'fields' with the same schema → different fingerprint", () => {
  const schema = z.object({ a: z.string() });
  const a = fingerprintSchema(schema, "all");
  const b = fingerprintSchema(schema, "fields");
  assert.notEqual(a, b);
});
test("fingerprintSchema: record value type changed → different fingerprint", () => {
  // Regression: describeType used to fall through to the generic default for
  // z.record, describing any record as just "record" — a record of structured
  // objects and a record of plain strings hashed identically, so the exact
  // drift this guardrail exists to catch went undetected.
  const a = fingerprintSchema(z.record(z.string(), z.string()), "all");
  const b = fingerprintSchema(
    z.record(z.string(), z.object({ amount: z.number() })),
    "all",
  );
  assert.notEqual(a, b);
});

test("fingerprintSchema: record value object shape changed → different fingerprint", () => {
  const a = fingerprintSchema(
    z.record(z.string(), z.object({ amount: z.number() })),
    "all",
  );
  const b = fingerprintSchema(
    z.record(
      z.string(),
      z.object({ amount: z.number(), currency: z.string() }),
    ),
    "all",
  );
  assert.notEqual(a, b);
});
