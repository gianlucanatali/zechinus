# Technical decisions

Why Zechinus is shaped the way it is — the choices that aren't obvious from reading the
code, and what was rejected instead. `SECURITY.md` documents the threat model (what a
compromised server can/can't do); this document is about the design trade-offs that
produced that threat model. `AGENTS.md` is the operative "how to use/extend it" guide.
Back to [README.md](../README.md).

## AAD binds `{userId, table, field, rowId}`, not just `userId`

Every ciphertext's AAD is the tuple `[userId, table, field, rowId]`. The alternative —
binding only `userId`, or nothing at all — is cheaper to implement but lets a
compromised/curious server move ciphertext to a different row, field, table, or even a
different user's account and have it still decrypt (AES-GCM's AAD check would pass,
since nothing in the ciphertext itself encodes where it's "supposed" to live). Binding
the full tuple means any such move fails the GCM auth tag check immediately — the
server literally cannot reassign one user's row to another without the client noticing.
The cost is that AAD serialization has to be unambiguous (see next section) and that
`rowId`/`table`/`field` become permanent, immutable identifiers once anything is
encrypted under them (see "The one invariant you must never break" in the README).

## AAD serialization: JSON tuple (v2/v3), not pipe-join (v1)

Early envelope versions (`v: 1`/`2`) joined the four AAD components with `|` and no
escaping. If any component's value could contain a literal `|`, two logically different
AADs could serialize to the identical byte string — and AES-GCM has no way to tell them
apart once that happens. `v: 3`/`4` moved to `JSON.stringify([userId, table, field,
rowId])`, which is unambiguous regardless of what characters any component contains.
`v: 1`/`2` stay read-only (real data was already written under them); every new write
emits `3`/`4` or, once `epoch` is involved, `5`/`6`. This is why the envelope has a
version byte at all instead of one fixed format: a wire-format bug like the pipe-join
collision has to be fixable without an all-at-once data migration, by making decode
deterministic from the stored version alone.

## Cardinality is a first-class declaration, not a convention

`defineStore` requires `identity: "perUser" | { perKey: string } | "many"` up front,
rather than letting each store figure out its own primary key / upsert shape ad hoc.
Cardinality drives the primary key, the AAD `rowId`, and whether a write is an
upsert-by-user or an insert-with-generated-id — getting any of those wrong by hand is
exactly the kind of mistake this package exists to make impossible. Three cardinalities
cover what real stores need (one secret object per user; one object per user+key, e.g. a
monthly batch or a per-table label dictionary; an independent collection with
framework-generated ids); each is its own standalone builder function sharing a `Build
Context`, so adding a fourth cardinality later is one new builder + one dispatch branch,
never a change to the existing three.

## `content_hash` is a keyed HMAC, not a plain hash

Where a `content_hash` column exists, it's `HMAC-SHA256` keyed by a MAC key derived from
the DEK — not a plain `SHA256(plaintext)`. A plain hash would let a curious server
detect that two rows (or two users, if it could compare across accounts) share the same
plaintext, or run a dictionary attack against low-entropy values, entirely without the
DEK. Keying it to the DEK closes both: the server sees an opaque string it can't invert
and can't use to correlate anything it doesn't already have the key for. The trade-off
this accepts deliberately: correlation *within* one user's own rows (the same user
writing the same value twice produces the same hash) is possible and is what makes the
skip-write/skip-fetch/optimistic-lock optimizations work at all — that's a single user
noticing their own duplicate, not a leak to a third party.

## Optimistic locking rides on `content_hash`, not a version counter column

Two tabs/devices editing the same record need a way to detect "this row changed since I
read it" without a dedicated version-counter column on every table. Reusing
`content_hash` for this (compare-and-swap: write only if the stored hash still matches
what was read) means the guardrail is available to any store that already opted into
`contentHash: true` for the anti-fingerprinting reason above, with no extra schema.
`optimisticLock: true` requires `contentHash: true` for exactly this reason —
`defineStore` throws at definition time if you ask for one without the other, rather
than silently working with a weaker guarantee.

## DEK rotation is a synchronous, session-invalidating ceremony — never lazy

When true DEK rotation (the key's actual bytes changing, not just re-wrapping the same
key under a new KEK) was designed, a lazy per-row convergence — symmetric to how
`legacyAAD` porting works, where old and new formats coexist until each row happens to
be touched again — was considered and rejected. No production zero-knowledge system
rotates that way, for a concrete reason: it breaks multi-device consistency. A lazy
migration means some rows are under the old key and some under the new key for an
unbounded window, and a second device with only the old key has no way to know which is
which without probing. Rotation must instead be one fast, coordinated phase:

- **Epoch-tagged AAD** (`FieldAAD.epoch`, wire format `v: 5/6`) — every row records which
  rotation cycle encrypted it, cryptographically bound into the AAD itself, so a server
  can't relabel a row's epoch to trick a client into decrypting with a compromised key.
- **Generic per-store migration engine** (`rotateEpoch`, present on every
  `defineStore`-created store automatically) re-encrypts a user's full row set under the
  new key and reports `{migrated, alreadyMigrated, failed}` — idempotent, safe to resume
  after an interruption, never aborts on one corrupted row.
- **A paranoid re-check pass** (`verifyRotatedRows`) re-reads everything after migration
  to catch rows written *during* the rotation window that the one-time migration pass
  never saw.
- **Multi-device handshake**: a device that already has the new key can hand it to one
  that doesn't via a one-shot ephemeral X25519 key, never persisted and never the
  device's stable identity.
- **Verify-before-retire, no confirmation gate**: the old key is discarded the instant
  every row verifiably decrypts under the new one. Waiting longer buys nothing — a
  straggler device's old wrap is useless either way once migration is done, so it always
  needs the handshake to get the current key regardless of whether its stale wrap still
  exists.
- **Anti-overlap guard**: a new rotation can't start before the previous one's old epoch
  is fully retired, enforced via an atomic conditional write so two racing callers (two
  tabs, two devices) can't both begin one.

The result is a rotation that's minutes, not days — a single fast phase (migrate,
verify, retire) instead of an open-ended lazy convergence.

## WebAuthn PRF for key derivation, BIP39 mnemonic as the recovery path

Deriving the KEK from a passkey's PRF extension output (rather than a password) means
the key material never has to be typed, transmitted, or stored anywhere — it's
recomputed from a hardware-backed secret on each unlock. The unavoidable cost of
zero-knowledge is that nobody else can reset a lost key for you, so a recovery path is
mandatory, not optional: a 24-word BIP39 mnemonic (the same standard used by crypto
wallets and password managers) derives an independent KEK via the same generic
`deriveKey` primitive passkeys use, shown once at setup and never stored.

## Rollback protection is a declared non-goal

A compromised/curious server can serve a stale-but-authentic old version of a row and
the client has no way to detect that from the ciphertext alone — there's no monotonic
version counter enforced server-side. Building one needs a tamper-proof place to store
the high-water-mark, which the server can't be trusted to hold either — a meaningfully
bigger design than this package's current scope, and nobody consuming it has asked for
it. Documented in `SECURITY.md` as an explicit "not built" rather than left implicit.

## `StorageAdapter`/`CacheAdapter`/`KeyProvider` are ports, not baked into `core/`

`core/` never imports Supabase, a Postgres driver, or the WebAuthn browser API directly
— every external integration is a pluggable adapter behind one of three interfaces.
This is what makes `defineStore` usable from a bare Node script, keeps the bare barrel
(`index.ts`) free of dependencies a non-React/non-Supabase consumer doesn't want, and
means a new backend (a different database, a native-biometrics `KeyProvider` for React
Native) is a new adapter implementing an existing interface — never a change to `core/`
itself.

## The package boundary: never import your own package name from inside the package

Every file under this package imports the rest of it via relative paths
(`../core/types.ts`), never its own package name (`zechinus`/`zechinus/*`) — that
specifier only means something to code *outside* the package. `npm run typecheck`
enforces this by type-checking the package standalone, with no path aliases available to
paper over a violation. The reason this is enforced rather than just documented: a
self-import silently works inside a monorepo (the bundler resolves it via the same
symlink a real consumer would use) right up until the package is extracted and
published standalone, at which point it becomes a circular dependency on itself. Catching
it at typecheck time, before extraction, is what made this actual extraction
(this repository) a rename-and-push instead of a hunt for hidden coupling.

## Native-module DEK isolation (mobile): a per-instance Expo class, not a global key

React Native has no Web Workers — the mechanism `workerKeyHandle.ts` uses to keep a
DEK's raw bytes out of the main JS heap on web. The closest real analogue on iOS/Android
is a native module with a genuine per-instance object, not a singleton holding one
global key: `nativeModuleKeyHandle.ts` builds each `KeyHandle` around a distinct native
`CryptoKey` instance (Swift `CryptoKeyRef`/CryptoKit, Kotlin `CryptoKeyRef`/`javax.crypto`
+ Tink for HKDF), exposed via Expo's `Class`/`SharedObject` binding — confirmed to exist
in the Expo Modules API before any native code was written, not assumed. A DEK rotation
keeps two handles alive at once (the current and previous epoch); destroying one must
never affect the other, the same invariant `new Worker()` guarantees on web.

**What this does not claim.** Native memory is not sandboxed — the native object lives
in the same process and address space as the rest of the app, not behind a hardware or
OS process boundary. It closes off casual/JS-level extraction of raw key bytes, not
code-execution-level compromise. JS can still use the key as an oracle (call
encrypt/decrypt/hash through it) for as long as the handle is alive; it just can never
read the bytes back out.

**Rejected: iOS Secure Enclave.** The Enclave only generates/imports asymmetric P-256
keys — it cannot hold an arbitrary AES key, and this DEK is derived from a passkey PRF
output or an unwrap, not born inside the Enclave.

**Rejected (for now): Android Keystore with real key import**, which would be a genuine
hardware-backed boundary unlike the process-memory isolation actually shipped. Rejected
because it would only exist on one platform (iOS has no equivalent for an arbitrary AES
key) and because Android Keystore doesn't expose HKDF/HMAC on an imported key the same
way this design needs — worth reconsidering as Android-only follow-up work if the
platform asymmetry becomes a practical problem.

**A real, undecided asymmetry**: an OS-level biometric ACL on the cached zero-tap entry
gates iOS's Keychain read only (`SecItemCopyMatching`) — writing a `.biometryCurrentSet`
item doesn't require a live ceremony, since the caller already holds the plaintext. A
symmetric AndroidKeyStore key with `setUserAuthenticationRequired(true)` gates both
directions identically, so caching a key right after unlock shows a second live
biometric prompt on Android that iOS never shows. The standard fix (an asymmetric
Android key: encrypt with the public key freely, decrypt with the gated private key) is
deferred to verification on a real device, not decided without hardware to confirm it
against.

## 2026-08-07 — Restricting wrap capability at the accessor boundary

**Problem:** `PasskeyDekController.getCryptoHandle()`/`getPreviousCryptoHandle()`
returned the full `KeyHandle` (including `wrapWithKek`/`wrapForDevice`) to every
consumer, even though the overwhelming majority (stores, aggregations, every React
hook) only ever use the `CryptoHandle` shape (`pid`/`encryptJson`/`decryptJson`/
`hashContent`). Any JS code in the same bundle that could reach `getCryptoHandle()`
could call `wrapWithKek`/`wrapForDevice` with an attacker-chosen KEK/device public
key and recover the raw DEK — no secret of zechinus's own needs to be broken, since
the caller already knows the key it supplied.

A second, independent oracle was found during this investigation:
`PasskeyDekController.wrapCurrentDekForDevice(devicePublicKeyB64)` — a public method
on the controller itself (not reachable via `getCryptoHandle()` at all), taking an
unvalidated device public key directly from the caller. Verified as having zero call
sites anywhere in the consuming app (EasyWealth) — including its own intended
internal caller (`fulfillPendingRotationRequests` in `dekRotationCoordinator.ts`
calls `wrapForDevicePublicKey` directly with a raw DEK parameter, never through this
method). Removed entirely rather than "fixed" — see the rejected-alternative below
for why.

**Decision:** `getCryptoHandle()`/`getPreviousCryptoHandle()` now return a runtime-
restricted object (`toCryptoHandle()`, `core/keyDerivation.ts`) that physically lacks
`wrapWithKek`/`wrapForDevice`/`encryptField`/`decryptField`/`destroy` — not a type-
only restriction, which a cast would bypass. A new `getWrapCapableHandle()` returns
the full `KeyHandle`, for the one legitimate external consumer (EasyWealth's
device-link flow). `wrapCurrentDekForDevice` was deleted from the interface.

**Rejected alternative — an authenticity tag on the KEK.** Considered validating
that a `kek` passed to `wrapWithKek` actually came from `deriveKEKFromPRF`/
`mnemonicRecovery().deriveKEK` (e.g. an HMAC tag appended by those functions,
checked by `wrapKey`). Rejected: both derivation functions are pure and callable
with ANY caller-chosen input — an attacker can call them directly with bytes/words
of their own choosing, get back a validly "tagged" KEK, and still knows every bit
of it. The tag would prove "this passed through the right function," not "the
input was genuine" — which is the only thing that matters. Security theater, adds
complexity, closes nothing.

**Deviation found during implementation, not anticipated in the original plan:**
`toCryptoHandle()` builds a NEW object literal on every call. A naive accessor
(`() => cryptoHandle ? toCryptoHandle(cryptoHandle) : null`) breaks two things that
weren't visible until actually running the test suite: (1) React's
`useSyncExternalStore` contract — `getSnapshot` must return a reference-stable value
between actual state changes, or components using `usePasskeyDek()` would re-render
in an infinite loop in production; (2) reference-equality assertions already present
in `tests/passkeyDekController.test.ts` (one of which expects the SAME restricted
object whether a handle is reached via `getCryptoHandle()` before a rotation or
`getPreviousCryptoHandle()` after — a single cache keyed by "current" vs "previous"
slot, tried first, does not satisfy this). Fixed with a `WeakMap<KeyHandle,
CryptoHandle>` keyed by the underlying handle itself, not by slot — entries drop
once a handle is no longer referenced anywhere (e.g. after `destroy()`). The same
issue and fix were applied to `react/useDevDekInjection.ts`
(`DevDekInjectionBridge`), which also typed its `cryptoHandle` prop as the full
`KeyHandle` despite only ever using it as a truthiness check — found while wiring up
EasyWealth's `PasskeyContext.tsx`, which passes `usePasskeyDek()`'s now-restricted
handle into it.

**Structural risks this fix does NOT close — stated plainly, not deferred:**

1. **Full closure of the passkey-PRF oracle is impossible for a web app**, not
   merely expensive. `credential.getClientExtensionResults().prf.results.first` is
   delivered to page JS as a plain, readable `ArrayBuffer` by the WebAuthn Level 3
   PRF extension's own contract — there is no browser API that seals it into a
   non-extractable `CryptoKey` before JS ever sees the raw bytes. Any JS executing
   in that context at that moment — including a compromised dependency in the same
   bundle — can read it, independently of anything in this fix.
2. **Monkey-patching `navigator.credentials.get`/`.create`.** Neither frozen nor
   protected by Trusted Types in this app today. A compromised dependency can
   intercept the WebAuthn ceremony before it reaches zechinus at all, bypassing
   this entire fix (and any conceivable fix inside zechinus/EasyWealth) — this is a
   supply-chain risk (dependency pinning/auditing), out of scope for a code change
   here.
3. **`dek_rotation_requests` RLS permits the authenticated user to write their own
   rows** (`auth.uid() = user_id`, no additional gate). Under the "malicious
   same-session JS" threat model, a defensive check inside a future
   `fulfillPendingRotationRequests` caller (verify the request is "legitimate")
   would not help — the same compromised session can write its own "legitimate-
   looking" request row first. Closing this for real needs an out-of-band
   confirmation channel (e.g. explicit approval from an already-trusted second
   device) that does not exist today — deliberately not built here, since the
   multi-device rotation UI itself (key-custody roadmap Fase 2.3) is still
   unbuilt; whoever builds it must design that channel as part of the feature,
   not retrofit it.

**What this fix DOES achieve:** it removes a large, easily-reachable surface
(essentially every store/hook/aggregation in the app) that had no reason to be able
to reach wrap capability at all, and deletes a live-but-unused oracle
(`wrapCurrentDekForDevice`) with zero product cost. It protects against accidental
future exposure (a well-meaning future change importing `getCryptoHandle()`
somewhere new) and narrows what a code review needs to scrutinize. It does not, and
cannot, protect against a fully compromised dependency executing in the same
browser tab as an unlocked session — no client-side E2E encryption scheme can,
without hardware-backed non-extractable keys the Web platform does not currently
expose for this exact use case.
