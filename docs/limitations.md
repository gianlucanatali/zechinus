# What Zechinus doesn't do yet (v1 scope — 2026-07-04)

Read this to know what Zechinus does NOT do yet before assuming a capability exists. Back
to [README.md](../README.md).

Explicit error at definition (never a silent stub), with a `FIXME` in the source:

- **`encrypt: "none"`** (fully plaintext row, zero blob) — no real consumer yet.
- **Mixed `enc()` fields with an `identity` other than `"many"`** (perUser/perKey) — no
  real consumer needs them today.
- **Hub-and-spoke storage** (plaintext columns + ref on one backend, blob on another,
  e.g. low-cost object storage) — planned capability, not implemented yet.
- **Cross-session persistent skip-fetch cache for web** (skip the network round-trip
  across page reloads, not just within a session) — `tanstackAdapter` stays in-memory
  only, no persisted web cache (ciphertext on IndexedDB, say), no consumer yet. See
  [docs/content-hash-and-locking.md](content-hash-and-locking.md) — the in-session
  variant IS built. **Mobile already has this**: `mobilePersistentCacheAdapter`/
  `expoPersistentCacheAdapter()` (`adapters/cache/`) persist a device-encrypted cache to
  `expo-secure-store`/`expo-file-system`, hydrated on cold launch — not yet wired into
  `mobile/`'s own bootstrap (see that file's header comment).
- **React Native**: the crypto engine (`@noble/*`) and `core/keyDerivation.ts` are
  already isomorphic — `webauthnKeyProvider` (`adapters/keyproviders/webauthnKeyProvider.ts`)
  is the **web** adapter (uses `navigator.credentials`, browser-only). RN needs its own
  adapter (native passkey/biometrics) calling the same `deriveKey`/`createKeyHandle` — not
  written yet, but the split already isolates exactly what would need to change.
  **Compression on RN:** `core/crypto.ts` uses gzip for every encrypt/decrypt via the
  pluggable `setGzipImpl` API exported from `core/gzip.ts`. By default it uses the
  browser's native `CompressionStream` (web + Deno); RN at bootstrap calls
  `setGzipImpl({ compress, decompress })` with an fflate-backed implementation
  (or any standard RFC 1952 gzip library) — blobs written under one implementation
  decrypt under any other. `useAutoLock` (`react/useAutoLock.ts`) is still web-only
  (`window` events); the other React hooks (`useStore`/`useKeyedStore`/
  `useCollectionStore`/`useIsUnlocked`) have no DOM dependency and work on RN.
