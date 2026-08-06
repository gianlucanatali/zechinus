# Node scripts & multi-user concurrency — `zechinus/node`

Read this when writing a Node script/service (not browser code) that touches Zechinus
stores. Back to [README.md](../README.md).

`configureSecureStore`'s ambient identity (`keys: KeyProvider`) is a single
module-level variable — fine for a browser tab (exactly one user at a time) but unsafe
for a Node script/service that handles multiple users concurrently, e.g. `Promise.all`
over per-user jobs: every ambient `store.get()`/`store.set()` call would see whichever
identity was configured last, across every in-flight promise chain.

`zechinus/node` exports `alsKeyProvider` (a `KeyProvider` backed by Node's
`AsyncLocalStorage`) and `withIdentity(userId, cryptoHandle, fn)`, which binds an
identity to the current async context for the lifetime of `fn` — every promise chain
it spawns sees its own identity, isolated from sibling chains, even under `Promise.all`.
Outside any `withIdentity` scope the getters return `null`, so an ambient call fails
loud (`"no active session (locked)"`) instead of silently reusing a stale identity.

```ts
import { alsKeyProvider, withIdentity } from "zechinus/node";

configureSecureStore({
  storage: pgStorageAdapter(getClient),
  keys: alsKeyProvider,
});

await Promise.all(
  users.map(({ userId, cryptoHandle }) =>
    withIdentity(userId, cryptoHandle, () =>
      myStore.mutate((d) => ({ ...d, synced: true })),
    ),
  ),
);
```

This is a separate entry point on purpose: `node:async_hooks` must never reach the
browser bundle, so `zechinus/node` is never imported from `zechinus` (bare barrel) or
`zechinus/react`.

## Which `KeyProvider` to use

- **Browser / single ambient user** (the app's normal runtime): the app's own
  `KeyProvider` (`passkeyDekController`, bridging `PasskeyContext`/`UserContext` — see
  [docs/key-management.md](key-management.md)), as today.
- **Node script/service, one user at a time, no concurrency**: still fine with a
  simple fixed `KeyProvider` (see `fixedKeyProvider` pattern in `tests/defineStore.test.ts`).
- **Node script/service handling MULTIPLE users concurrently**: use `alsKeyProvider` +
  `withIdentity(userId, cryptoHandle, fn)` from `zechinus/node`, above. Each `withIdentity`
  call isolates its identity to its own async context — safe under `Promise.all`, never
  leaks across sibling chains. Outside any `withIdentity` scope the getters return `null`
  and an ambient store call fails loud (`"no active session (locked)"`), never silently
  reusing a stale identity.
