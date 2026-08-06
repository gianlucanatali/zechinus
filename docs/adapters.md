# Writing and extending adapters

Read this before writing a new adapter, adding a capability an existing adapter doesn't
have, or looking up what's already shipped. Back to [README.md](../README.md).

## Folder taxonomy — one subfolder per port type

Adapters live under `adapters/`, grouped by which port they implement (introduced when the
adapter count outgrew a single flat folder):

| Subfolder                | Port                                          | Ships today                                                                                                                       |
| ------------------------- | ---------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| `adapters/storage/`      | `StorageAdapter` (persistence)                | `supabaseStorageAdapter.ts` (PostgREST), `pgStorageAdapter.ts` (raw SQL)                                                            |
| `adapters/keyproviders/` | `KeyProvider` primitives                      | `webauthnKeyProvider.ts` (WebAuthn PRF, web-only), `mnemonicRecovery.ts` (BIP39 recovery phrase)                                    |
| `adapters/keyhandles/`   | `KeyHandle` isolation                          | `workerKeyHandle.ts` (raw key bytes confined to a Web Worker, never on the main thread)                                             |
| `adapters/cache/`        | `CacheAdapter`                                 | `tanstackAdapter.ts` (in-memory, TanStack Query-backed), `mobilePersistentCacheAdapter.ts` + `expoDeviceCacheStorage.ts` (Expo/RN persistent, device-encrypted) |
| `adapters/controllers/`  | Full ceremonies built on top of the ports      | `passkeyDekController.ts` (passkey + BIP39-recovery unlock ceremony, a complete `KeyProvider` implementation), `dekRotationCoordinator.ts` (multi-device DEK-rotation handshake) |
| `adapters/crypto/`       | Device-bound key material (multi-device DEK delivery) | `deviceKeyProvider.ts` (web, deterministic from the passkey KEK), `mobileDeviceKeyProvider.ts` (mobile placeholder, not wired yet) |

`adapters/expo-ambient.d.ts` stays at the `adapters/` root — it's an ambient type
declaration, not a port implementation, so it doesn't belong to any one category.

The distinction between `controllers/` and the other five: `storage/`, `keyproviders/`,
`keyhandles/`, `cache/`, and `crypto/` each implement ONE port interface directly (see
[docs/key-management.md](key-management.md) § "Architecture: the ports" for the port
list). `controllers/` sits one layer up — `passkeyDekController` composes a
`webauthnKeyProvider` + `mnemonicRecovery` + a `KeyHandle` factory into a full,
ready-to-use `KeyProvider` (see [docs/key-management.md](key-management.md) §
"`passkeyDekController`"), and `dekRotationCoordinator` orchestrates a handshake across
several ports at once — neither is a single-port implementation on its own.

Importing any adapter still goes through the same `zechinus/adapters/*` wildcard export
(`package.json`'s `exports` map), with the subfolder as part of the path:

```ts
import { supabaseStorageAdapter } from "zechinus/adapters/storage/supabaseStorageAdapter.ts";
import { pgStorageAdapter } from "zechinus/adapters/storage/pgStorageAdapter.ts";
import { webauthnKeyProvider } from "zechinus/adapters/keyproviders/webauthnKeyProvider.ts";
import { mnemonicRecovery } from "zechinus/adapters/keyproviders/mnemonicRecovery.ts";
import { createWorkerKeyHandle } from "zechinus/adapters/keyhandles/workerKeyHandle.ts";
```

## Extending `StorageAdapter`

If a new usage pattern needs a capability the adapter doesn't have (e.g. a new way to
address rows): add the method as **optional** (`method?:`) on `StorageAdapter`
(`zechinus/core/types.ts`), implement it in `supabaseStorageAdapter`, and write an
in-memory adapter in the test (`zechinus/tests/*.test.ts`, see `defineStoreMany.test.ts`
for the pattern). `defineStore` must throw an explicit, descriptive error if the
configured adapter doesn't support the requested capability — never a silent fallback.
Optional methods today: `putIfMatch`/`updateByIdIfMatch` (optimistic locking, see
[docs/content-hash-and-locking.md](content-hash-and-locking.md)), `list`/`insert`/
`updateById`/`deleteById` (`identity: "many"`), `listByKeyRange` (`perKey`
range queries), `listAll` (`perKey` full enumeration, needed only by `rotateEpoch` — see
[docs/key-management.md](key-management.md) § "DEK rotation"), and `getHash` (in-session
skip-fetch revalidation, see [docs/content-hash-and-locking.md](content-hash-and-locking.md))
— an adapter missing one simply never unlocks that specific capability, every other
capability keeps working.

### The extension recipe, step by step

1. Add the method as **optional** (`method?:`) on `StorageAdapter` in `core/types.ts` —
   never required, so existing adapters keep compiling.
2. Implement it in `adapters/storage/supabaseStorageAdapter.ts` (or your own adapter). Any
   query/update/delete should filter by the owning user id explicitly, even when
   row-level security also enforces it — index usage, not just correctness.
3. In `defineStore` (`core/store.ts`), the code path using the new capability must throw an
   explicit, descriptive error if `storage.<method>` is undefined — mirror the existing
   pattern (`the configured adapter doesn't support 'many' (list missing)`). Never
   silently no-op or fall back.
4. Write a TDD test in `tests/` **before** the implementation: an in-memory `StorageAdapter`
   double (copy the pattern from `defineStoreMany.test.ts` or `defineStorePerKey.test.ts`),
   4+ cases (roundtrip, AAD-per-row not movable across rows/keys/ids,
   adapter-missing-capability → explicit error, Zod validation rejects bad writes).

`getHashesByKeys` (`core/types.ts`) is a real, already-shipped example of this exact
recipe — a batch hash-only read for several keys of one `perKey` store in one round trip,
implemented in both shipped adapters (`supabaseStorageAdapter.ts`/`pgStorageAdapter.ts`),
consumed by `defineAggregation`'s cold-session check (see
[docs/aggregations.md](aggregations.md) § "Cold-session freshness verification"). Use it
as the template.

## `tanstackAdapter` requires `gcTime: Infinity` — enforced, not just documented

`tanstackAdapter` (`adapters/cache/tanstackAdapter.ts`) writes via `setQueryData`/
`getQueryData` and never mounts a real `useQuery` observer — every entry it creates has
zero observers for its whole life. TanStack schedules that entry's garbage collection
unconditionally at creation time (a separate axis from `staleTime`) and evicts it once
`gcTime` elapses, no matter how many times it was refreshed in between. With the default
5-minute `gcTime`, cached decrypted data silently disappears from every Zechinus-backed
hook after that long of the consuming app sitting idle — no error, since `CacheAdapter` has
no "refetch" concept for a caller to notice or recover from. This is a real bug that
shipped once (the host app's Dashboard going blank after ~5 minutes idle, filling again
only on remount).

Following the same idiom as the encryption guardrail (`defineStore` throwing on a missing
`encrypt` declaration, see [docs/guardrails.md](guardrails.md)): **`tanstackAdapter`
throws immediately at construction** if `queryClient.getDefaultOptions().queries?.gcTime
!== Infinity`. Documentation alone (a README note nobody reads before it bites them 5
minutes into a real session) was judged insufficient — the fix must fail loud at wiring
time (app boot / `configureSecureStore` call), not silently at 3am in a real user's idle
tab. If you extend or replace this adapter, or write a new `CacheAdapter` backed by
anything with its own eviction/TTL concept, apply the same principle: assert the safe
configuration at construction, don't just document it.

## Capability reference — existing hooks & `KeyProvider` implementations

What already exists before wiring a new component/service to Zechinus — not a "don't
build this" list (see `AGENTS.md` § "Known v1 boundaries" for that), just what's already
shipped:

- React binding exists for all 3 cardinalities (`useStore`/`useKeyedStore`/
  `useCollectionStore`, all in `react/`). Each needs `keys` (`KeyProvider`) and `cache`
  (`CacheAdapter`) in `configureSecureStore`; without them it throws explicitly. Both
  ports are plain get/subscribe objects, deliberately not hook-shaped
  (`useSyncExternalStore` reads them inside the hook, not inside the port itself) — don't
  design a new port as `useXyz()`. See [docs/react.md](react.md).
- `useIsUnlocked()` (`react/useIsUnlocked.ts`) is the boolean-only counterpart — needs
  just `keys`, never `cache`, and never hands the caller a `CryptoHandle`. Use it instead
  of `useStore`/`usePasskeyDek` whenever a component only needs a lock/unlock gate.
- `KeyProvider` has two known concrete implementations: `adapters/controllers/passkeyDekController.ts`
  - its React binding `usePasskeyDek` (the full passkey+BIP39-recovery ceremony —
    register/unlock/add-passkey/regenerate-recovery-words — the host app's actual production
    `KeyProvider`, bridged into `PasskeyContext`/`UserContext`; see
    [docs/key-management.md](key-management.md) for the pointer), and `alsKeyProvider`
    (`zechinus/node`, `AsyncLocalStorage`-backed, for Node scripts/services — see
    [docs/node.md](node.md)). Whatever a _future_ implementation looks like must not
    assume a browser: React Native needs a different `getCryptoHandle`/`getUserId`/
    `subscribe` behind native passkey/biometrics, but the port itself already doesn't
    require WebAuthn — only a future concrete implementation would.
- `passkeyDekController.getUnlockCredentialId()` / `usePasskeyDek`'s `unlockCredentialId` —
  the passkey credential id (base64url) behind the DEK currently active this session, set
  by `unlockWithPasskey`/`registerPasskey→confirm`, `null` when locked or unlocked via
  recovery phrase. Distinct from `getUnlockMethod()` (which only says "passkey" vs.
  "recovery"): use this when the app needs to know _which_ specific passkey a device is
  bound to — e.g. tracking it on a device-registry row so a security-incident remediation
  flow can point the user at the exact passkey to remove.
- `useDevDekInjection`/`DevDekInjectionBridge` (`react/useDevDekInjection.ts`) — the E2E/dev
  escape hatch that injects a raw DEK via `window.__setTestDek(hexKey)`, bypassing the
  passkey ceremony. Mount `DevDekInjectionBridge` behind a static `import.meta.env.DEV &&`
  check, never call the raw hook directly, so it's dead-code-eliminated from production.
- `useIsAnyKeyedStoreLoading()` (`react/useIsAnyKeyedStoreLoading.ts`) — the `KeyedStore`
  analog of `isAnyAggregationComputing()`: a cross-store "any keyed-store fetch in flight"
  signal, for an E2E test waiting right after a DEK unlock. See
  [docs/aggregations.md](aggregations.md).
- `setGzipImpl` (`core/gzip.ts`) — pluggable compression for `core/crypto.ts`'s
  encrypt/decrypt path. Defaults to the browser's native `CompressionStream`; React Native
  calls it at bootstrap with an fflate-backed implementation. Blobs written under one
  implementation decrypt under any other. See [docs/limitations.md](limitations.md) §
  "React Native".
