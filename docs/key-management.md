# Key management: DEK rotation, the ports, and the passkey ceremony

Read this to understand key management, unlock, and rotation — how DEK rotation works end
to end, the four port interfaces Zechinus is built on (`StorageAdapter`/`KeyProvider`/
`CacheAdapter`/`CryptoHandle`), and `passkeyDekController`, the ready-to-use passkey +
BIP39-recovery `KeyProvider` implementation. Back to [README.md](../README.md).

## DEK rotation

**Built** — a synchronous, session-invalidating ceremony, never a lazy per-row
mechanism (a lazy "legacy DEK" convergence symmetric to `migrateLegacyAAD` was
considered and rejected early on: it breaks multi-device consistency, and no
production zero-knowledge system rotates that way). Full rationale: `docs/DECISIONS.md`
§ "DEK rotation is a synchronous, session-invalidating ceremony — never lazy".

- **Epoch-tagged AAD** (`FieldAAD.epoch`, wire format `v:5/6` — see
  [docs/wire-format.md](wire-format.md)): every row records which rotation cycle
  encrypted it, cryptographically bound into the AAD (tamper-evident — an attacker can't
  relabel a row's epoch to trick a client into decrypting with a compromised key).
- **Generic per-store migration** — `Store`/`KeyedStore`/`CollectionStore.rotateEpoch(userId,
oldHandle, newHandle, newEpoch)`, present on EVERY `defineStore`-created store
  automatically, no app-level wiring per store. Fetches the user's full row set for that
  store (`get`/`list`/`listAll` — no SQL-side epoch filtering, no new indexed column needed:
  skip-detection is a decrypt probe, "does this row already read under the new handle?"),
  re-encrypts whatever's still on the old key, and reports
  `{migrated, alreadyMigrated, failed}` — a corrupted row is collected, never aborts the
  rest. Idempotent: safe to call again after an interruption. The cardinality-blind engine
  lives in `zechinus/core/rotationMigration.ts`.
- **Per-store paranoid re-check** — `Store`/`KeyedStore`/`CollectionStore.verifyRotatedRows(userId,
oldHandle, newHandle, newEpoch)`, present on every `defineStore`-created store like
  `rotateEpoch` itself. Deliberately redundant with `rotateEpoch`'s own `failed` count: it
  re-reads every row AFTER migration completes, catching rows written ambiently
  (`set()`/`mutate()`) during the rotation window that `rotateEpoch`'s one-time pass never
  saw. Tries the new handle first (tagged `newEpoch`), falls back to the old handle on
  failure (`atOldEpoch` — not yet migrated, not an error), and only a row decrypting under
  NEITHER counts as `failed` (genuine corruption). The app-level orchestrator calls this
  after `rotateEpoch` and feeds `{atOldEpoch, failed.length}` into
  `checkRetirementEligibility` below.
- **perKey enumeration**: `StorageAdapter.listAll` (optional, see
  [docs/adapters.md](adapters.md) § "Extending `StorageAdapter`") is the one new adapter
  capability rotation needed — `perUser`/`many` already had an unconditional "everything
  for this user" read.
- **Multi-device handshake**: a device that already has the new DEK can hand it to one
  that doesn't via a one-shot ephemeral X25519 key (never persisted, never the device's
  stable identity) — `zechinus/adapters/controllers/dekRotationCoordinator.ts`.
- **Verify-before-retire**: the old epoch's key material is discarded the instant every row
  verifiably decrypts under the new one — no per-device confirmation gate. A straggler
  device's old wrap is useless to it either way (the old DEK can't decrypt any row once
  migration is done), so it always needs the multi-device handshake above to get the
  current DEK, whether its stale wrap still exists or was already deleted — waiting for it
  buys nothing. Rotation is therefore a single fast phase (data migration + verification +
  retirement, minutes), not a multi-day one — `zechinus/core/rotationRetirement.ts`.
- **Anti-overlap guard**: a new rotation can't start before the previous one's old epoch is
  retired (starting one early risks destroying the only key that can still decrypt rows
  stuck behind — rotations are strictly sequential, never overlapping) —
  `DekRotationStorage.beginRotation`/`completeRotation`, an atomic conditional write so two
  racing callers (two tabs, two devices) can't both succeed —
  `zechinus/adapters/controllers/dekRotationCoordinator.ts`.
- **Liveness heartbeat for resume**: `DekRotationStorage.touchRotationHeartbeat`/
  `getRotationHeartbeat` let a passive observer distinguish "the driver is still actively
  working" (e.g. paused on a human step with no timeout) from "the driver died" before
  attempting to take over an abandoned rotation — this interface only carries the raw
  timestamp; the staleness threshold and the "safe to resume" policy (recover the DEK a
  prior attempt already wrapped, never regenerate fresh bytes) live in the consuming app
  (`src/context/RotationContext.tsx`'s `resumeRotationAsDriver`), not here.

**Not yet wired** (app-level, tracked in the consuming app's own roadmap, not this
package's): the actual "rotate my key" trigger in a settings UI, and calling
`rotateEpoch` across the app's real stores.

## Architecture: the ports

`StorageAdapter` (persistence — Supabase/Postgres today) · `KeyProvider` (where the app's
current key handle + userId live — the host app's implementation bridges WebAuthn/passkey,
but the port itself doesn't require that) · `CacheAdapter` (React binding's cache — a real
`tanstackAdapter(queryClient)` ships today) · `CryptoHandle` (the minimal shape a key
handle must have — `{ pid, encryptJson, decryptJson }` — see `core/types.ts`; an app
derives its key however it wants, WebAuthn/passkey, password KDF, hardware token, as long
as the resulting object structurally satisfies this). Extending Zechinus = implementing
an adapter or supplying a conforming object, never touching the core.

**`StorageAdapter` implementations shipped today:**

- `supabaseStorageAdapter(getClient)` — uses `@supabase/supabase-js`'s query builder, i.e.
  PostgREST (HTTP + RLS via JWT). Requires the Supabase stack, not just a Postgres
  connection.
- `pgStorageAdapter(getClient)` — real SQL against plain Postgres (self-hosted, RDS, etc.),
  no Supabase/PostgREST required. `getClient` is duck-typed (`query(text, params) => {
rows }`, matching node-postgres's shape) — no hard dependency on `pg` or any specific
  driver; bring your own connection.

Both implement the exact same `StorageAdapter` interface (`core/types.ts`) — swapping one
for the other requires no changes to `defineStore` calls, only to `configureSecureStore`.
See [docs/adapters.md](adapters.md) for where each adapter lives on disk and how to write
a new one.

## `passkeyDekController` / `usePasskeyDek` — the passkey+recovery ceremony

`adapters/controllers/passkeyDekController.ts` is a full, ready-to-use `KeyProvider`
implementation — not just the port. It owns the entire zero-knowledge unlock ceremony any
app doing WebAuthn PRF + BIP39 recovery needs: register a passkey, generate a recovery
phrase, wrap the DEK under both, unlock via either, add an additional passkey to an
already-unlocked DEK, regenerate recovery words. None of this is app-specific — it's the
same sequence regardless of which app is asking. What stays app-side, injected via config:
`storage` (a `PasskeyWrapStorage` — 5 methods, table/column names + DB client),
`createHandle` (raw bytes → `KeyHandle`, plain or Worker-isolated), and the app's own
`webauthnKeyProvider`/`mnemonicRecovery` instances. Framework-agnostic (no React import) —
`react/usePasskeyDek.ts` is the thin React binding (`useSyncExternalStore`), the host app's
own production `KeyProvider`.

`react/useDevDekInjection.ts` (+ `DevDekInjectionBridge`) is the companion dev/E2E escape
hatch: headless test runners have no passkey to authenticate with, so this hook exposes a
`window.__setTestDek(hexKey)`/`window.__clearTestDek()` pair (gated by a runtime `enabled`
flag) that injects raw key bytes directly into a `PasskeyDekController`, bypassing the
ceremony. Mount `DevDekInjectionBridge` behind a static `import.meta.env.DEV &&` check
(not the raw hook) so bundlers can dead-code-eliminate it from production entirely, not
just disable it at runtime.
