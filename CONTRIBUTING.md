# Contributing

## Setup

```
npm install
```

No other setup needed — everything the test suite touches (crypto, storage adapters,
React hooks) either runs against real primitives (`@noble/*`) or an in-memory fixture,
never a live Supabase/Postgres instance.

## Running things

```
npm run test:all    # node --test (core logic) + Vitest (React hooks, jsdom) — run this before any PR
npm test            # node --test only, faster loop while iterating on core/adapters
npm run test:react  # Vitest only, faster loop while iterating on react/
npm run typecheck   # standalone tsc --noEmit — catches package-boundary violations too
```

`npm run test:all` is what CI runs; it must be clean before a PR is reviewable.

## Where to read before changing something

- **`README.md`** — the source of truth for the public API and what v1 does/doesn't do.
  Start here.
- **`AGENTS.md`** — the operative guide: cardinality choice, the encryption guardrail,
  versioning rules, the package-boundary rule, and a reflection checklist for "does this
  belong inside the framework or in the calling app". Read it before writing any AAD,
  envelope, or storage-upsert logic — that logic usually belongs here, not in a consumer.
- **`SECURITY.md`** — the threat model: what a compromised/curious server can and can't
  do, and declared non-goals. Read it before changing anything under `core/crypto.ts`,
  `core/keyDerivation.ts`, or any AAD/envelope shape.
- **`docs/`** — narrower guides, each pointed to from `AGENTS.md` at the moment it's
  relevant (package boundary, extending a `StorageAdapter`, porting a legacy AAD,
  aggregation extras, Node multi-user concurrency). Don't read the whole folder
  up front — open the one file your change actually touches.

## Conventions

- **English-only.** Code, comments, docs, tests, error messages, test names — no
  exceptions, even for a one-line comment.
- **Examples are real code, not prose.** `examples/basic-usage.ts` is compiled and
  exercised by `tests/examples.test.ts`. If you change a public signature, update the
  example first until it compiles and the test passes — that's what "How these docs
  stay in sync" in the README is checking for.
- **TDD for anything in `core/`.** A new cardinality, a new `StorageAdapter` capability,
  a new AAD shape — write the failing test first (see `AGENTS.md`'s "Reflection
  checkpoint" for how to tell whether something belongs in `core/` at all before you
  start).
- **Never bypass the encryption guardrail.** `defineStore` throws unless encryption is
  declared explicitly. If you hit that error while adding a feature, declare it — don't
  build a path around it.

## Before opening a PR

1. `npm run test:all` clean.
2. `npm run typecheck` clean.
3. If you touched the public API: `examples/basic-usage.ts` still compiles, and the
   README sections listed in "How these docs stay in sync" are updated to match.
4. If you touched anything crypto-adjacent (AAD, envelope, key derivation): re-read
   `SECURITY.md` and update it if the threat model actually changed — not just the code.
