# Guardrails: explicit encryption, mandatory versioning, `schemaFingerprint`

Read this when `defineStore` throws at definition time and you need to understand why, or
to fix a `schemaFingerprint` error. Back to [README.md](../README.md).

## Guardrail: encryption always explicit

`defineStore` **refuses** to be defined unless you declare `encrypt: "all"`,
`encrypt: "none"`, or at least one `enc()` field in the schema. No silent default —
impossible to write plaintext data by omission.

## Guardrail: versioning is mandatory, not a mental note

`version: N` **requires exactly N-1 `migrators`** (v1→v2, v2→v3, …, v(N-1)→vN).
`defineStore` throws an explicit error **at definition** (at boot/import, not on the first
read of old data) if the count doesn't match:

```ts
defineStore({
  name: "portfolio_blobs",
  version: 4,
  migrators: [v1ToV2, v2ToV3, v3ToV4], // exactly 3, or the app won't start
  // ...
});
```

This catches "bumped `version` but forgot the migrator" **immediately**, not months later
staring at a production blob that no longer decodes.

**The opposite case — "changed the schema's shape but forgot to bump `version` at all" —
is covered by a second guardrail, `schemaFingerprint` (mandatory, like `encrypt`).**
`defineStore` computes a fingerprint of the schema's current shape and compares it against
the declared one; if it's missing or doesn't match, it throws **at definition** — i.e. on
the next `npm test`/`npm run dev`/`npm run build`, not the first time the app touches real
data written with the old shape. Concretely, here's what a developer sees:

```ts
// 1. First definition — schemaFingerprint missing:
defineStore({
  name: "portfolio_blobs",
  encrypt: "all",
  schema: z.object({ positions: z.array(Position).default([]) }),
  version: 1,
});
// → throws: "schemaFingerprint missing — add schemaFingerprint: "3a7f2c11" to the def"
//   You copy the suggested value, paste it in. Zero manual computation.

// 2. Months later, you add a field to the schema WITHOUT thinking about versioning:
defineStore({
  name: "portfolio_blobs",
  encrypt: "all",
  schema: z.object({
    positions: z.array(Position).default([]),
    cashBuffer: z.number().default(0), // ← new field, version still 1
  }),
  version: 1,
  schemaFingerprint: "3a7f2c11", // ← the old value, no longer valid
});
// → throws immediately: "the schema shape has changed relative to the declared
//   schemaFingerprint (expected "3a7f2c11", computed "9e01bb44"). If this change
//   requires migrating existing data: bump version + add a migrator, THEN update
//   schemaFingerprint. If it's a safe change (e.g. a field with .default()): just
//   update schemaFingerprint."
```

The point: **you cannot change the schema "quietly".** Whether or not you remember to
think about versioning, the next boot/test run refuses to start until you consciously
update `schemaFingerprint` — that's the moment, reading the message, where you decide
whether a `version` bump + migrator is also needed, or whether it's a safe change. Zod's
reactive check (on old data, at read time) remains a second safety net, not the only check.

**Precision on "safe change" — it is still a different shape, just a backward-compatible
one.** A field added with `.default()` genuinely produces a new blob shape (the fingerprint
changing proves that). "Safe" doesn't mean "not a version" — it means Zod can absorb old
ciphertext into the new shape at parse time, with no data loss and no explicit migrator
needed, so the guardrail doesn't _require_ a `version` bump for it. It does not _forbid_
one either: if your team wants to track every shape change as an explicit version — for a
stricter audit trail, or because you don't trust "backward-compatible" judgment calls —
nothing stops you from bumping `version` and writing an identity migrator (`(d) => d`) for
every change, safe or not. The guardrail's job is to make you decide consciously each
time; it deliberately doesn't pick a house style for how strict that decision has to be.

**IMPORTANT — never compute `schemaFingerprint` inline at the call site**, e.g.
`schemaFingerprint: fingerprintSchema(MySchema, "all")` in the same `defineStore()` call
that uses `MySchema`. That makes the guardrail compare the schema against itself — a
tautology that can never fail, no matter how much the shape drifts later. Always a frozen
string literal, computed once, committed to git:

```ts
const store = defineStore({
  name: "portfolio_blobs",
  schema: PortfolioDataSchema,
  version: 1,
  // Frozen literal — NOT fingerprintSchema(PortfolioDataSchema, ...) inline (see above).
  // Regenerate with `npm run sync-fingerprints -- path/to/this/file.ts`.
  schemaFingerprint: "da2584b4",
});
```

### Fixing a `schemaFingerprint` guardrail error

Once you've decided (per the message above) whether the change needs a `version`
bump + migrator or is safe as-is, run:

```
npm run sync-fingerprints -- path/to/yourBlobService.ts
```

It re-imports the file, catches the guardrail's own thrown error, extracts the correct
value from the message, and writes it into the `schemaFingerprint` field for you — same
idea as `eslint --fix`, just for this one guardrail. It assumes one `defineStore()` call
per file (today's convention across every ported service); a file with more than one
needs a manual fix.

**Deliberately NOT wired into the pre-commit hook.** Auto-fixing on every commit would
silently remove the "stop and consciously decide: does this need a migrator or not?"
moment that is the entire reason this guardrail exists. Run the command yourself, after
you've made that decision — not before, and not automatically.

If you forget to run it (or fix it manually): nothing bad happens beyond friction —
`defineStore()` keeps throwing on every `npm test` / `npm run dev` / `npm run build`
until it's fixed. It cannot be silently skipped; there is no environment where the
guardrail doesn't run, because it fires the moment the module is imported.
