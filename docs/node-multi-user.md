# Node scripts & multi-user concurrency — which `KeyProvider` to use

Read this when writing a Node script/service (not browser code) that touches Zechinus
stores.

`configureSecureStore`'s ambient identity is one module-level variable — correct for a
browser tab (one user per tab), wrong for a Node script/service touching more than one
user's data concurrently (e.g. `Promise.all` over per-user jobs): every ambient call
would see whichever identity was configured last, across every in-flight promise chain.

- **Browser / single ambient user** (the app's normal runtime): the app's own
  `KeyProvider` (`passkeyDekController`, bridging `PasskeyContext`/`UserContext`), as
  today.
- **Node script/service, one user at a time, no concurrency**: still fine with a
  simple fixed `KeyProvider` (see `fixedKeyProvider` pattern in `tests/defineStore.test.ts`).
- **Node script/service handling MULTIPLE users concurrently**: use `alsKeyProvider` +
  `withIdentity(userId, cryptoHandle, fn)` from `zechinus/node` (`AsyncLocalStorage`-backed).
  Each `withIdentity` call isolates its identity to its own async context — safe under
  `Promise.all`, never leaks across sibling chains. Outside any `withIdentity` scope the
  getters return `null` and an ambient store call fails loud (`"no active session
(locked)"`), never silently reusing a stale identity.

**Never import `zechinus/node` from `zechinus/index.ts` or `zechinus/react/index.ts`**
— `node:async_hooks` must never reach the browser bundle. It is a standalone entry point,
by design, mirroring how `zechinus/react` is kept out of non-React consumers.
