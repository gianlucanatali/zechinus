# Capability reference — existing hooks & `KeyProvider` implementations

Read this when you need to know what already exists before wiring a new component/service
to Zechinus — not a "don't build this" list (see `AGENTS.md` § "Known v1 boundaries" for
that), just what's already shipped.

- React binding exists for all 3 cardinalities (`useStore`/`useKeyedStore`/
  `useCollectionStore`, all in `react/`). Each needs `keys` (`KeyProvider`) and `cache`
  (`CacheAdapter`) in `configureSecureStore`; without them it throws explicitly. Both
  ports are plain get/subscribe objects, deliberately not hook-shaped
  (`useSyncExternalStore` reads them inside the hook, not inside the port itself) — don't
  design a new port as `useXyz()`.
- `useIsUnlocked()` (`react/useIsUnlocked.ts`) is the boolean-only counterpart — needs
  just `keys`, never `cache`, and never hands the caller a `CryptoHandle`. Use it instead
  of `useStore`/`usePasskeyDek` whenever a component only needs a lock/unlock gate.
- `KeyProvider` has two known concrete implementations: `adapters/passkeyDekController.ts`
  - its React binding `usePasskeyDek` (the full passkey+BIP39-recovery ceremony —
    register/unlock/add-passkey/regenerate-recovery-words — the host app's actual production
    `KeyProvider`, bridged into `PasskeyContext`/`UserContext`; see README's own section for
    the pointer), and `alsKeyProvider` (`zechinus/node`, `AsyncLocalStorage`-backed, for Node
    scripts/services — see `docs/node-multi-user.md`). Whatever a _future_ implementation
    looks like must not assume a browser: React Native needs a different
    `getCryptoHandle`/`getUserId`/`subscribe` behind native passkey/biometrics, but the port
    itself already doesn't require WebAuthn — only a future concrete implementation would.
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
  signal, for an E2E test waiting right after a DEK unlock. See README's own section.
- `setGzipImpl` (`core/gzip.ts`) — pluggable compression for `core/crypto.ts`'s
  encrypt/decrypt path. Defaults to the browser's native `CompressionStream`; React Native
  calls it at bootstrap with an fflate-backed implementation. Blobs written under one
  implementation decrypt under any other. See README § "React Native".
