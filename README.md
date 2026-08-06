# Zechinus

**End-to-end encryption as an adapter layer, for apps that already own their backend.**

Zechinus isn't "an encrypted store" — it's the correct cryptographic decisions made for
you. Anyone can write a CRUD store; Zechinus owns the hard 20% that gets skipped or
gotten wrong — per-row AAD, versioned envelopes, runtime validation, always-explicit
encryption — so the domain only declares **the shape of its data**, never the mechanics.

> Status: v1, extracted as a standalone package. It grew inside a production app's
> monorepo before being pulled out and renamed — some file paths/comments in this
> README still describe that original host-app integration as illustrative context.
>
> **Language:** English-only — code, comments, docs, tests, error messages.
>
> **Threat model:** see `SECURITY.md` for what a compromised/curious server can and
> cannot do, and what's a declared non-goal (rollback protection). True DEK rotation
> IS built — see [docs/key-management.md](docs/key-management.md) § "DEK rotation".

## Installation

Not yet published to the npm registry — install directly from GitHub:

```
npm install github:gianlucanatali/zechinus
```

(Or, if consumed inside a monorepo that owns this package directly, an npm workspace
entry works the same way — see [docs/package-boundary.md](docs/package-boundary.md).)

## Mental model

A record = **cardinality** (how many blobs, addressed how) + **what to encrypt** (default:
everything) + **schema** (Zod: type + validation). From this, Zechinus derives AAD,
envelope, upsert/insert, lazy migration — all the mechanics stay invisible to the author.

```
frontend/service → defineStore({ name, identity, encrypt, schema, version }) → store.load/save/...
                                            ↓
                              StorageAdapter (Supabase today; pluggable)
```

## Quickstart

The three examples below are **real, compiled, tested code** (not prose that rots):
`zechinus/examples/basic-usage.ts` + `zechinus/tests/examples.test.ts`. If the API
changes, those files stop compiling or the test fails — that's the alignment guarantee,
see ["How these docs stay in sync"](#how-these-docs-stay-in-sync) below.

```ts
import { z } from "zod";
import { configureSecureStore, defineStore } from "zechinus";
import { supabaseStorageAdapter } from "zechinus/adapters/storage/supabaseStorageAdapter.ts";

// once, at app bootstrap
configureSecureStore({ storage: supabaseStorageAdapter(getSupabaseClient) });

// perUser — one blob per user (portfolio, asset, snapshot)
const portfolioStore = defineStore({
  name: "portfolio_blobs",
  identity: "perUser", // default, can be omitted
  encrypt: "all", // ALWAYS explicit — see the guardrails doc below
  schema: z.object({ positions: z.array(Position).default([]) }),
  version: 1,
});
await portfolioStore.save(userId, cryptoHandle, data);
const data = await portfolioStore.load(userId, cryptoHandle);

// perKey — one blob per (user, domain key) — e.g. transactions per month
const transactionStore = defineStore({
  name: "transaction_blobs",
  identity: { perKey: "year_month" },
  encrypt: "all",
  schema: z.object({ transactions: z.array(Tx).default([]) }),
  version: 1,
});
await transactionStore.save(userId, cryptoHandle, "2026-07", data);
const data = await transactionStore.load(userId, cryptoHandle, "2026-07");

// many — a collection with a generated id — e.g. rebalance simulations
const simulationStore = defineStore({
  name: "rebalance_simulations",
  identity: "many",
  encrypt: "all",
  schema: z.object({
    name: z.string().default(""),
    addedLiquidity: z.number().default(0),
  }),
  version: 1,
});
const id = await simulationStore.create(userId, cryptoHandle, data);
const rows = await simulationStore.list(userId, cryptoHandle); // [{ id, data }, ...]
await simulationStore.update(userId, cryptoHandle, id, data);
await simulationStore.remove(userId, cryptoHandle, id);
```

Full runnable examples (in-memory adapter, no Supabase required):
`zechinus/examples/basic-usage.ts`.

## Where to go

| I want to...                                                     | Read                                                                                     |
| ------------------------------------------------------------------ | ------------------------------------------------------------------------------------------- |
| Encrypt a new table                                               | [docs/stores.md](docs/stores.md)                                                        |
| Pick a cardinality (`perUser`, `keyed`, `many`)                   | [docs/stores.md#cardinality](docs/stores.md#cardinality)                                |
| Build a read model from several stores                            | [docs/aggregations.md](docs/aggregations.md)                                            |
| Wire this into React                                              | [docs/react.md](docs/react.md)                                                          |
| Understand what's stored on the server                            | [docs/wire-format.md](docs/wire-format.md)                                              |
| Port a table that already has encrypted data                      | [docs/wire-format.md#legacy-aad](docs/wire-format.md#legacy-aad)                        |
| Detect concurrent writes / skip no-op writes                      | [docs/content-hash-and-locking.md](docs/content-hash-and-locking.md)                    |
| Fix a `schemaFingerprint` error                                   | [docs/guardrails.md](docs/guardrails.md)                                                |
| Understand key management, unlock, rotation                       | [docs/key-management.md](docs/key-management.md)                                        |
| Write a new adapter                                                | [docs/adapters.md](docs/adapters.md)                                                    |
| Run this from a Node script                                       | [docs/node.md](docs/node.md)                                                            |
| Know what Zechinus does NOT do                                    | [docs/limitations.md](docs/limitations.md)                                              |
| Understand why a design choice was made                           | [docs/DECISIONS.md](docs/DECISIONS.md)                                                  |

## How these docs stay in sync

Project convention: **examples are real code, not prose.** `zechinus/examples/*.ts` is
compiled by `tsc` (`npm run typecheck`, always mandatory before declaring work done) and
called from `zechinus/tests/examples.test.ts` (`npm test`). If you change the public
signature of `defineStore`/`Store`/`KeyedStore`/`CollectionStore`
(`zechinus/core/store.ts`, exported from `zechinus/index.ts`):

1. Update `zechinus/examples/basic-usage.ts` FIRST until it compiles again and the test
   passes.
2. Mirror the change into THIS README (the Quickstart snippets) and, if the change
   touches a topic covered by one of the `docs/` pages linked above, mirror it there too
   — not generated, so they need to be kept in sync by hand, but a broken example in
   step 1 is the signal you can't ignore.
3. If the change is a new capability (new cardinality, new encryption mode), document it
   in the relevant `docs/` page (e.g. [docs/stores.md](docs/stores.md) for a new
   cardinality) and add it to the Quickstart once implemented.

There is no automatic API-reference generator yet (TypeDoc or similar) — deliberately
deferred until there's a real reader for one. The signatures are already documented with
TSDoc in `core/*.ts`, ready to be extracted whenever that changes.

## Development

See `CONTRIBUTING.md` for local setup, the test/typecheck commands, and where to read
before making a change (`AGENTS.md` is the detailed guide). This project was built with
AI pair-programming (Claude) under close human review — the test suite (550 tests
across `node --test` and Vitest), `SECURITY.md`'s threat model, and the commit history
are the actual evidence of that, not a badge.
