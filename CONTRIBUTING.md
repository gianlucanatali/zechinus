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

## Releasing a new version

`npm version <bump>` + `git push origin main --tags` publishes the git tag consumers pin
to (`github:gianlucanatali/zechinus#vX.Y.Z`) — this is a real release, not a local
bookkeeping step.

**An AI agent may run this on its own only for a patch bump (`x.y.Z`)** — a genuinely
minor change: a bug fix, restoring a feature that existed before and was lost, a
refactor with no intentional new public surface. **A minor or major bump (`x.Y.z` /
`X.y.z`) always needs an explicit conversation with the maintainer first** — why that
level is justified — and explicit confirmation before running `npm version`, even when
the change technically adds a new optional field/method and would qualify as a "feature"
under strict semver. Real case: three lost features (`IsolatedKeyCache`,
`PasskeyWrapCache`, silent passkey unlock) were restored back-to-back in one session as
three consecutive minor bumps (0.3.0 → 0.4.0 → 0.5.0) — each was actually a small fix
that should have been a patch (0.2.1 → 0.2.2 → 0.2.3). Fixing a tag published in error:
propose the fix (delete the tag, re-tag as a patch) and get confirmation before doing it
— don't just redo it unilaterally, even to correct your own earlier mistake.

## Before opening a PR

1. `npm run test:all` clean.
2. `npm run typecheck` clean.
3. If you touched the public API: `examples/basic-usage.ts` still compiles, and the
   README sections listed in "How these docs stay in sync" are updated to match.
4. If you touched anything crypto-adjacent (AAD, envelope, key derivation): re-read
   `SECURITY.md` and update it if the threat model actually changed — not just the code.
