/**
 * defineStore — public API of the DataCloak secure-store framework.
 *
 * The author declares the data *shape* with Zod, the *cardinality*, and *what to
 * encrypt*; the framework owns all the mechanics (crypto, AAD, envelope,
 * versioning, content_hash, I/O, validation). See the plan's "🧱 MODELLO DATI
 * UFFICIALE" + "🔌 defineStore — giro completo" sections.
 *
 * `defineStore` adds on top of the blob engine (`blobCodec`/`defineBlobStore`):
 *  - **Zod validation** on write (before encrypting) and on read (after
 *    decrypting+migrating) — recovers the safety net that E2E encryption removes
 *    from the DB on encrypted fields;
 *  - **encryption guardrail**: encryption must ALWAYS be explicit, never a silent
 *    default;
 *  - **versioning guardrails**: `version` bumps must be paired with migrators, and
 *    the schema shape must be paired with a fingerprint — both checked at
 *    definition time, not reactively when old data fails to decode.
 *
 * Cardinalities supported in v1: `perUser` (one blob per user), `perKey` (one blob
 * per `(user, domain key)`, AAD tied to the key), and `many` (a collection with a
 * framework-generated id, one blob per row, AAD tied to the id). `many` also
 * supports mixed `enc()` fields (plaintext columns alongside the blob); other
 * cardinalities require `encrypt: "all"`.
 */

import { z } from "zod";
import { defineBlobStore } from "./blobStore.ts";
import { loadRow, saveRow, saveRowIfMatch, canonicalAAD } from "./rowStore.ts";
import { encodeBlob } from "./blobCodec.ts";
import {
  decodeWithCandidates,
  type DecodeCandidate,
} from "./legacyFallback.ts";
import { getSecureStoreConfig } from "./config.ts";
import { randomId } from "./randomId.ts";
import { toEnvelope, type BlobMigrator } from "./versioning.ts";
import { collectEncryptedKeys } from "./encryption.ts";
import { fingerprintSchema } from "./schemaFingerprint.ts";
import type { BlobRecord, CryptoHandle, FieldAAD, KeyColumn } from "./types.ts";
import { LockedSessionError, OptimisticLockConflictError } from "./errors.ts";
import {
  reencryptRowIfNeeded,
  type RotationOutcome,
} from "./rotationMigration.ts";

/**
 * Resolves the current session's `CryptoHandle` AND userId from the configured
 * `KeyProvider` — used by `get()`/`mutate()`/`getRange()` so callers never have to
 * fetch a `CryptoHandle` OR pass a `userId` themselves (it's the same ambient
 * session identity `getCryptoHandle()` already comes from — `passkeyDekController`
 * sets/clears both together, synchronously, never one without the other). A caller
 * needing a DIFFERENT identity (dev/test tooling, scripts) still has `load`/`save`,
 * which keep taking both explicitly — or `withIdentity()` from `datacloak/node`.
 *
 * NOT exported from the public barrel: if a service needs this directly, that's
 * a sign `defineStore` is missing an ambient wrapper for whatever it's doing
 * (see `getRange` below) — extend the framework, don't reach around it.
 */
function resolveAmbientIdentity(storeName: string): {
  cryptoHandle: CryptoHandle;
  /** Present only during an in-progress DEK rotation — see `KeyProvider.getPreviousCryptoHandle`. */
  previousCryptoHandle: CryptoHandle | null;
  userId: string;
} {
  const { keys } = getSecureStoreConfig();
  if (!keys) {
    throw new Error(
      `${storeName}: no KeyProvider configured — pass 'keys' to configureSecureStore()`,
    );
  }
  const cryptoHandle = keys.getCryptoHandle();
  const userId = keys.getUserId();
  if (!cryptoHandle || !userId) {
    throw new LockedSessionError(storeName);
  }
  return {
    cryptoHandle,
    previousCryptoHandle: keys.getPreviousCryptoHandle?.() ?? null,
    userId,
  };
}

/** Store cardinality: how many records per user, and how they're addressed. */
export type Identity = "perUser" | "many" | { perKey: string };

export interface StoreDef<S extends z.ZodType> {
  /** Table/collection name = the `table` value in the AAD. Never change it for existing data. */
  name: string;
  /** Zod schema of the plaintext: TS type + validation (write/read) + versioning base. */
  schema: S;
  version: number;
  /** Cardinality. Defaults to `"perUser"`. */
  identity?: Identity;
  /**
   * Encryption declaration. Must be explicit (guardrail): `"all"` (the whole
   * object in one blob) or `"none"` (no field encrypted), or mark fields with
   * `enc()` in the schema. If nothing is declared → error (no plaintext data by
   * omission).
   */
  encrypt?: "all" | "none";
  /**
   * Fingerprint of the CURRENT schema shape. Like `encrypt`: optional in the type
   * but MANDATORY at runtime (guardrail, same pattern as "encryption always
   * explicit") — if you change the schema without updating this value,
   * `defineStore` throws IMMEDIATELY (at definition time, not on the first read
   * of old data) with the correct value in the message. Compute it with
   * `fingerprintSchema(schema, encrypt ?? "fields")`.
   */
  schemaFingerprint?: string;
  /** Value returned when the record doesn't exist. If absent, derived from the schema's defaults. */
  empty?: z.infer<S>;
  /**
   * For PORTING an existing table only — omit entirely for a brand-new store (the
   * vast majority of stores never set this). A function reconstructing the OLD
   * (pre-DataCloak) AAD shape for a given row — `rowKey` is `cryptoHandle.pid` for `perUser`,
   * the domain key for `perKey`, the row id for `many`.
   *
   * On read, the canonical AAD (`field:"data"`) is always tried FIRST; only if that
   * fails to decrypt does the store retry under this legacy AAD. A successful legacy
   * decrypt is immediately re-encrypted and persisted under the canonical AAD — every
   * touched row converges permanently, one row at a time, no live migration script.
   * ALL writes (save/create/update) ALWAYS use the canonical AAD, never this one — a
   * store never has two ways to write. If both the canonical and legacy attempts
   * fail, the canonical error propagates (never masked by the legacy attempt).
   */
  legacyAAD?: (cryptoHandle: CryptoHandle, rowKey: string) => FieldAAD;
  migrators?: BlobMigrator[];
  /**
   * Set `true` if this table has a `content_hash` column — DataCloak computes it
   * internally as a keyed HMAC-SHA256 of the plaintext envelope (the DEK-derived MAC
   * key lives in the `CryptoHandle`, see `keyDerivation.ts`'s `hashContent`), so the
   * server only ever sees an opaque, non-fingerprintable string, never a plain hash
   * of the content. Omit (or `false`) for tables without the column.
   */
  contentHash?: boolean;
  /**
   * Requires `contentHash: true`. Enables `saveIfMatch`/`updateIfMatch` — a
   * conditional write that rejects (returns `{ok:false}`, never throws) instead of
   * silently overwriting a row that changed since it was last read. See README's
   * "Optimistic locking" section for the multi-tab conflict this prevents.
   */
  optimisticLock?: boolean;
  /**
   * Only relevant for `identity: "many"`. Overrides the default row id generator
   * (`core/randomId.ts`, RFC4122 UUIDv4). A consumer wanting sortable ids (ULID,
   * a timestamp-prefixed scheme, ...) supplies its own `() => string` — DataCloak
   * only needs the result to be unique per (userId, collection), it never inspects
   * the id's shape.
   */
  idGenerator?: () => string;
}

/** `perUser`-cardinality store: one blob per user. */
export interface Store<T> {
  readonly name: string;
  readonly version: number;
  load(userId: string, cryptoHandle: CryptoHandle): Promise<T>;
  save(userId: string, cryptoHandle: CryptoHandle, data: T): Promise<void>;
  /**
   * Ambient read — no `userId`, no `CryptoHandle`. Both are resolved from the
   * `KeyProvider` passed to `configureSecureStore()` (the same ambient session
   * identity `useStore()` already reads) — see `mutate` for the full rationale.
   */
  get(): Promise<T>;
  /**
   * Ambient blind write — no `userId`/`CryptoHandle`, and unlike `mutate()` no
   * read either: exactly `save()`'s semantics (unconditional upsert), just with
   * the identity resolved ambiently. For a caller that already has the final
   * value (not derived from `get()`), this skips `mutate()`'s wasted
   * load-then-discard.
   *
   * Refuses to run (throws) on a store with `optimisticLock: true` — a blind
   * overwrite would silently bypass the conflict protection the store owner
   * asked for. Use `mutate()` there instead.
   */
  set(data: T): Promise<void>;
  /**
   * Load → transform → save in one call, no `userId`/`CryptoHandle` in sight —
   * both are resolved from the `KeyProvider` passed to `configureSecureStore()`
   * (the same ambient session identity `useStore()` already reads: there is
   * exactly one active (cryptoHandle, userId) pair per session, set/cleared together —
   * a caller needing a DIFFERENT one — dev/test tooling, scripts — still has
   * `load`/`save`, which keep taking both explicitly, or `withIdentity()` from
   * `datacloak/node`). Business logic that
   * only needs to transform data never has to know the framework has a cryptoHandle or
   * an identity at all. Throws if no `KeyProvider` is configured, or if the
   * session is locked (no active cryptoHandle/userId).
   *
   * When the store declares `optimisticLock: true`, `mutate()` transparently
   * uses `loadWithHash`/`saveIfMatch` internally — same conflict detection
   * `useStore()` gives React callers, just for plain service code. Single
   * attempt: throws `OptimisticLockConflictError` on conflict rather than
   * retrying blindly (a blind retry would re-run `fn` against fresher data
   * without the caller ever deciding whether that's still valid).
   *
   * `options.retryOnConflict` opts INTO that retry, bounded to N total attempts:
   * on conflict, re-reads the fresh current state and re-applies `fn` to it (not
   * the stale one), then retries the conditional write. Only safe when `fn` is a
   * pure, self-contained derivation of `current` that stays correct against any
   * fresher state (e.g. appending a pre-generated record) — NOT when `fn`
   * overwrites specific fields from data captured outside `current` (e.g. a
   * user-typed value), where retrying would silently clobber a genuine
   * multi-tab conflict instead of surfacing it. Omit entirely to keep today's
   * single-attempt throw.
   */
  mutate(
    fn: (current: T) => T | Promise<T>,
    options?: { retryOnConflict?: number },
  ): Promise<T>;
  /** Present only when the store declares `contentHash: true`. */
  loadWithHash?(
    userId: string,
    cryptoHandle: CryptoHandle,
  ): Promise<{ data: T; hash: string | null }>;
  /**
   * Present only when the store declares `optimisticLock: true`. See `StoreDef.optimisticLock`.
   * On success, `hash` is the new content_hash — pass it straight into the next
   * `saveIfMatch` call, no extra fetch needed. `null` on conflict (`ok:false`).
   */
  saveIfMatch?(
    userId: string,
    cryptoHandle: CryptoHandle,
    data: T,
    expectedHash: string | null,
  ): Promise<{ ok: boolean; hash: string | null }>;
  /**
   * DEK rotation (key-custody roadmap Fase 2.3): re-encrypts this user's row
   * from `oldHandle` to `newHandle`, tagging it with `newEpoch`. Always present
   * — every `defineStore`-created store gets this for free, no app-level wiring
   * needed per store. Safe to call repeatedly (idempotent): a row already
   * migrated by an earlier/interrupted call is detected and left untouched
   * (`alreadyMigrated`), never re-written. A row missing entirely (never saved)
   * is a no-op (`migrated: 0, alreadyMigrated: 0, failed: []`) — there is
   * nothing to rotate. Does NOT touch the read-through cache: the plaintext
   * value never changes, only its ciphertext, so any cached copy stays valid.
   */
  rotateEpoch(
    userId: string,
    oldHandle: CryptoHandle,
    newHandle: CryptoHandle,
    newEpoch: number,
  ): Promise<RotationOutcome>;
}

/** `perKey`-cardinality store: one blob per `(user, domain key)`. */
export interface KeyedStore<T> {
  readonly name: string;
  readonly version: number;
  load(userId: string, cryptoHandle: CryptoHandle, key: string): Promise<T>;
  save(
    userId: string,
    cryptoHandle: CryptoHandle,
    key: string,
    data: T,
  ): Promise<void>;
  /** Ambient read for the given key — no `userId`/`CryptoHandle` — see `Store.mutate`. */
  get(key: string): Promise<T>;
  /** Ambient blind write for the given key — no `userId`/`CryptoHandle`, no read — see `Store.set`. */
  set(key: string, data: T): Promise<void>;
  /**
   * Load → transform → save for the given key, no `userId`/`CryptoHandle` in
   * sight — see `Store.mutate` (same `options.retryOnConflict` contract).
   */
  mutate(
    key: string,
    fn: (current: T) => T | Promise<T>,
    options?: { retryOnConflict?: number },
  ): Promise<T>;
  /**
   * Ambient bulk creation for N distinct keys in a single round-trip — needs
   * `insertMany` on the adapter. A real INSERT, not an upsert: any key that
   * already exists fails the WHOLE batch (never silently overwrites it). For
   * callers that know every key is brand-new (e.g. seeding many months right
   * after a full wipe) — updating an EXISTING key still goes through `mutate`/`set`.
   */
  createMany(entries: Array<{ key: string; data: T }>): Promise<void>;
  /** Range query over sortable keys (e.g. `year_month`) — needs `listByKeyRange` on the adapter. */
  list(
    userId: string,
    cryptoHandle: CryptoHandle,
    range: { from: string; to: string },
  ): Promise<Array<{ key: string; data: T }>>;
  /** Ambient range query — no `userId`/`CryptoHandle` — see `Store.mutate`. */
  getRange(range: {
    from: string;
    to: string;
  }): Promise<Array<{ key: string; data: T }>>;
  /** Present only when the store declares `contentHash: true`. */
  loadWithHash?(
    userId: string,
    cryptoHandle: CryptoHandle,
    key: string,
  ): Promise<{ data: T; hash: string | null }>;
  /**
   * Present only when the store declares `contentHash: true` AND the configured
   * adapter supports `getHashesByKeys` — batch hash-only read for SEVERAL keys in
   * one round trip (see `StorageAdapter.getHashesByKeys`'s doc comment). Used by
   * `defineAggregation`'s cold-session freshness check; not a general-purpose app
   * API (an app wanting a single key's hash already has `loadWithHash`).
   */
  getHashesForKeys?(
    userId: string,
    keys: string[],
  ): Promise<Record<string, string | null>>;
  /**
   * Present only when the store declares `optimisticLock: true`. See `StoreDef.optimisticLock`.
   * On success, `hash` is the new content_hash — pass it straight into the next
   * `saveIfMatch` call, no extra fetch needed. `null` on conflict (`ok:false`).
   */
  saveIfMatch?(
    userId: string,
    cryptoHandle: CryptoHandle,
    key: string,
    data: T,
    expectedHash: string | null,
  ): Promise<{ ok: boolean; hash: string | null }>;
  /**
   * DEK rotation (key-custody roadmap Fase 2.3): re-encrypts EVERY key this user
   * has in this store from `oldHandle` to `newHandle`, tagging each with
   * `newEpoch`. Requires `listAll` on the configured adapter (throws by name if
   * missing). Idempotent per key, same contract as `Store.rotateEpoch`.
   */
  rotateEpoch(
    userId: string,
    oldHandle: CryptoHandle,
    newHandle: CryptoHandle,
    newEpoch: number,
  ): Promise<RotationOutcome>;
}

/** `identity: "many"` — a collection with a framework-generated id, one encrypted blob per row. */
export interface CollectionStore<T> {
  readonly name: string;
  readonly version: number;
  /**
   * `hash` is `null` unless the store declares `contentHash: true` — pass it
   * straight into `updateIfMatch` as `expectedHash`, no separate lookup needed.
   */
  list(
    userId: string,
    cryptoHandle: CryptoHandle,
  ): Promise<Array<{ id: string; data: T; hash: string | null }>>;
  create(userId: string, cryptoHandle: CryptoHandle, data: T): Promise<string>;
  update(
    userId: string,
    cryptoHandle: CryptoHandle,
    id: string,
    data: T,
  ): Promise<void>;
  remove(userId: string, cryptoHandle: CryptoHandle, id: string): Promise<void>;
  /** Ambient read (all rows) — no `userId`/`CryptoHandle` — see `Store.mutate`. */
  get(): Promise<Array<{ id: string; data: T; hash: string | null }>>;
  /** Ambient create — no `userId`/`CryptoHandle` — see `Store.mutate`. */
  add(data: T): Promise<string>;
  /**
   * Ambient hard-delete — no `userId`/`CryptoHandle` — the ambient counterpart of
   * `remove()`, same relationship as `get()`↔`list()` and `add()`↔`create()`. For
   * callers outside a mounted React component (e.g. a service reacting to account
   * deletion). Like `add()`/`update()`, it does NOT write through the cache (see
   * README § "Deliberate exclusion") — safe here because the rows being discarded
   * belong to an entity no UI can select anymore.
   */
  discard(id: string): Promise<void>;
  /**
   * Present only when the store declares `optimisticLock: true`. `expectedHash`
   * comes from the `hash` field returned alongside each row in `list()` — see
   * README's "Optimistic locking" section. On success, `hash` is the row's new
   * content_hash — pass it into the next `updateIfMatch` call, no extra fetch
   * needed. `null` on conflict (`ok:false`).
   */
  updateIfMatch?(
    userId: string,
    cryptoHandle: CryptoHandle,
    id: string,
    data: T,
    expectedHash: string | null,
  ): Promise<{ ok: boolean; hash: string | null }>;
  /**
   * DEK rotation (key-custody roadmap Fase 2.3): re-encrypts EVERY row this user
   * has in this collection from `oldHandle` to `newHandle`, tagging each with
   * `newEpoch`. Requires `list` on the configured adapter (throws by name if
   * missing — same requirement `CollectionStore.list()` already has). Idempotent
   * per row, same contract as `Store.rotateEpoch`. Plaintext (mixed `enc()`)
   * columns are untouched — rotation only ever re-encrypts the blob.
   */
  rotateEpoch(
    userId: string,
    oldHandle: CryptoHandle,
    newHandle: CryptoHandle,
    newEpoch: number,
  ): Promise<RotationOutcome>;
}

/** `defineStore`'s return type based on cardinality: perKey → KeyedStore, many → CollectionStore, else Store. */
export type StoreApi<S extends z.ZodType, Id extends Identity> = Id extends {
  perKey: string;
}
  ? KeyedStore<z.infer<S>>
  : Id extends "many"
    ? CollectionStore<z.infer<S>>
    : Store<z.infer<S>>;

export function defineStore<
  S extends z.ZodType,
  Id extends Identity = "perUser",
>(def: StoreDef<S> & { identity?: Id }): StoreApi<S, Id> {
  type T = z.infer<S>;
  const identity: Identity = def.identity ?? "perUser";
  const migrators = def.migrators ?? [];

  // ── Versioning guardrail: version N requires EXACTLY N-1 migrators ──────────────
  // (v1→v2, v2→v3, ..., v(N-1)→vN). Throws at DEFINITION time, not on the first read
  // of old data: forces the developer to think about versioning the moment they
  // change the schema, not months later staring at production data.
  // Covers only "bumped version but forgot the migrator" — does NOT cover "changed
  // the shape without bumping version at all" (only Zod catches that, on read, on
  // old data that no longer validates — see datacloak/README.md).
  const requiredMigrators = def.version - 1;
  if (migrators.length !== requiredMigrators) {
    throw new Error(
      `defineStore(${def.name}): version ${def.version} requires ${requiredMigrators} migrator(s) ` +
        `(v1→v2→…→v${def.version}), ${migrators.length} provided. Add the missing migrators to ` +
        `'migrators', or fix 'version' if the data shape hasn't actually changed.`,
    );
  }

  // ── Guardrail (point 2): encryption must ALWAYS be explicit ─────────────────────
  const encTagged = collectEncryptedKeys(def.schema);
  const hasEncTags = encTagged.length > 0;
  if (def.encrypt === undefined && !hasEncTags) {
    throw new Error(
      `defineStore(${def.name}): encryption not declared — specify encrypt:"all" | encrypt:"none" | at least one enc() field. ` +
        `Rejected to avoid writing plaintext data by omission.`,
    );
  }
  if (def.encrypt === "all" && hasEncTags) {
    throw new Error(
      `defineStore(${def.name}): ambiguous declaration — encrypt:"all" already encrypts the whole record, the enc() ` +
        `markers on fields would be ignored. Remove encrypt:"all" or the enc() markers, not both.`,
    );
  }
  if (def.encrypt === "none") {
    // FIXME: encrypt:"none" (fully plaintext row, zero blob) has no real EW consumer yet —
    //   no adapter supports a row without an encrypted blob. Implement when actually needed.
    throw new Error(
      `defineStore(${def.name}): encrypt:"none" not implemented yet (no real consumer). See plan Fase 2b.`,
    );
  }
  // Plaintext fields (schema minus the encrypted ones) — supported ONLY with identity:"many"
  // in v1: it's the only real case (rebalance/scheduled, filterable portfolioId/status).
  // perUser/perKey remain bound to encrypt:"all" until a real consumer emerges for them.
  const allKeys =
    def.schema instanceof z.ZodObject
      ? Object.keys((def.schema as z.ZodObject).shape)
      : [];
  const encryptedKeys = def.encrypt === "all" ? allKeys : encTagged;
  const plaintextKeys = allKeys.filter((k) => !encryptedKeys.includes(k));
  if (plaintextKeys.length > 0 && identity !== "many") {
    throw new Error(
      `defineStore(${def.name}): mixed enc() fields (plaintext columns alongside the blob) are ` +
        `supported only with identity:"many" in v1. perUser/perKey require encrypt:"all".`,
    );
  }

  // ── Versioning guardrail (preventive): the schema's SHAPE must be paired with a
  // declared fingerprint. Catches "changed the schema but forgot to bump version"
  // IMMEDIATELY (at definition), not when Zod fails on read against old data months
  // later. Complementary to the migrator guardrail above: that one covers "version
  // bumped, migrator forgotten"; this one covers "schema changed, version never touched".
  const computedFingerprint = fingerprintSchema(
    def.schema,
    def.encrypt ?? "fields",
  );
  if (def.schemaFingerprint === undefined) {
    throw new Error(
      `defineStore(${def.name}): schemaFingerprint missing — add ` +
        `schemaFingerprint: "${computedFingerprint}" to the def (this represents the CURRENT ` +
        `schema shape for version ${def.version}).`,
    );
  }
  if (def.schemaFingerprint !== computedFingerprint) {
    throw new Error(
      `defineStore(${def.name}): the schema shape has changed relative to the declared ` +
        `schemaFingerprint (expected "${def.schemaFingerprint}", computed "${computedFingerprint}"). ` +
        `If this change requires migrating existing data: bump 'version' + add a migrator, THEN ` +
        `update schemaFingerprint to the new value. If it's a safe change (e.g. a field added ` +
        `with .default()) that needs no migration: just update schemaFingerprint to ` +
        `"${computedFingerprint}".`,
    );
  }

  // ── Guardrail: optimisticLock requires contentHash ───────────────────────────────
  if (def.optimisticLock && !def.contentHash) {
    throw new Error(
      `defineStore(${def.name}): optimisticLock requires contentHash: true — the lock compares against that column.`,
    );
  }

  // `empty` (the default when nothing has ever been saved) is only required for
  // perUser/perKey — 'many' has no "empty value" concept (list() just returns []
  // on its own); we compute it lazily, only where needed, so a 'many' schema with
  // required fields (e.g. portfolioId with no default) doesn't fail at definition
  // for a default it never uses.

  const validateRead = (raw: unknown, where: string): T => {
    const parsed = def.schema.safeParse(raw);
    if (!parsed.success) {
      throw new Error(
        `defineStore(${def.name}).${where}: decrypted data doesn't conform to the schema: ${parsed.error.message}`,
      );
    }
    return parsed.data as T;
  };
  const validateWrite = (data: T, where: string): T => {
    const parsed = def.schema.safeParse(data);
    if (!parsed.success) {
      throw new Error(
        `defineStore(${def.name}).${where}: data doesn't conform to the schema, write rejected: ${parsed.error.message}`,
      );
    }
    return parsed.data as T;
  };

  // Dispatch to the cardinality-specific builder. Each one is a standalone
  // function taking exactly the shared context it needs (never the whole
  // `defineStore` closure) — adding a 4th cardinality means writing one more
  // `buildXyzStore` function + one more branch here, not editing inside an
  // ever-growing function body.
  const ctx: BuildContext<S> = { def, migrators, validateRead, validateWrite };
  if (typeof identity === "object" && "perKey" in identity) {
    return buildKeyedStore(ctx, identity.perKey) as StoreApi<S, Id>;
  }
  if (identity === "many") {
    return buildCollectionStore(ctx, encryptedKeys, plaintextKeys) as StoreApi<
      S,
      Id
    >;
  }
  return buildPerUserStore(ctx) as StoreApi<S, Id>;
}

/** Shared context every cardinality-specific builder needs — computed once in `defineStore`. */
interface BuildContext<S extends z.ZodType> {
  def: StoreDef<S>;
  migrators: BlobMigrator[];
  validateRead: (raw: unknown, where: string) => z.infer<S>;
  validateWrite: (data: z.infer<S>, where: string) => z.infer<S>;
}

// ── perKey: one blob per (user, key); AAD.rowId = key ──────────────────────────
/**
 * Cache key for a keyed store's per-`(store,user)` write counter — bumped by
 * `buildKeyedStore`'s ambient `set()`/`mutate()` on every write, regardless of
 * which key changed. `useKeyedStoreRange` (`datacloak/react`) subscribes to this
 * key to know when an already-fetched range might be stale; exported so the
 * React binding computes the exact same string, never duplicated by hand.
 */
export function keyedRangeEpochCacheKey(
  storeName: string,
  userId: string,
): string {
  return `${storeName}:${userId}:__keysEpoch__`;
}

/**
 * Cache key holding the domain key(s) touched by the MOST RECENT ambient keyed
 * write (`set()`/`mutate()`/`createMany()`) — overwritten (not appended) on every
 * write, unlike `keyedRangeEpochCacheKey`'s plain counter. `onSourceWrite`
 * (`datacloak/core/onSourceWrite.ts`) is the one consumer: the epoch counter alone
 * tells a listener "something in this store changed", never WHICH key, and
 * `onSourceWrite`'s whole contract (`{ keys: string[] }`) needs the latter. Safe to
 * read as "last write's keys, not yet lost" because `CacheAdapter.subscribe`'s
 * production implementations (`tanstackAdapter`, the in-memory test double) invoke
 * every subscriber SYNCHRONOUSLY inside `cache.set()`, before the write call that
 * triggered it returns — so a subscriber's callback always observes the exact keys
 * of the write that just fired it, never a later write's keys clobbering this slot
 * first.
 */
export function keyedWriteKeysCacheKey(
  storeName: string,
  userId: string,
): string {
  return `${storeName}:${userId}:__writtenKeys__`;
}

function buildKeyedStore<S extends z.ZodType>(
  { def, migrators, validateRead, validateWrite }: BuildContext<S>,
  keyColumn: string,
): KeyedStore<z.infer<S>> {
  type T = z.infer<S>;
  const empty = resolveEmpty(def);
  const cacheKeyFor = (userId: string, key: string): string =>
    `${def.name}:${userId}:${key}`;
  const canonicalAADFor = (cryptoHandle: CryptoHandle, key: string): FieldAAD =>
    canonicalAAD(cryptoHandle, def.name, key);

  // Bumped after every ambient keyed write (set()/mutate()), regardless of which
  // key changed — the only signal `useKeyedStoreRange` needs to know a range it
  // has already fetched might now be stale (a `CacheAdapter` has no notion of
  // "subscribe to every key in [from,to]", so a per-store, per-user counter is
  // the simplest correct invalidation trigger; see `keyedRangeEpochCacheKey`).
  const bumpRangeEpoch = (userId: string, keys: string[]): void => {
    const { cache } = getSecureStoreConfig();
    if (!cache) return;
    const epochKey = keyedRangeEpochCacheKey(def.name, userId);
    cache.set(epochKey, (cache.get<number>(epochKey) ?? 0) + 1);
    // See `keyedWriteKeysCacheKey`'s doc comment — same ambient-write interception,
    // one extra slot carrying WHICH key(s) this write touched (for `onSourceWrite`).
    cache.set(keyedWriteKeysCacheKey(def.name, userId), keys);
  };

  const keyedSave = async (
    userId: string,
    cryptoHandle: CryptoHandle,
    key: string,
    data: T,
  ): Promise<void> => {
    const valid = validateWrite(data, `save(key=${key})`);
    const { storage } = getSecureStoreConfig();
    await saveRow(
      cryptoHandle,
      (record) =>
        storage.put(
          def.name,
          userId,
          [{ column: keyColumn, value: key }],
          record,
        ),
      canonicalAADFor(cryptoHandle, key),
      valid,
      def.version,
      def.contentHash,
    );
  };

  const keyedLoadInternal = async (
    userId: string,
    cryptoHandle: CryptoHandle,
    key: string,
  ): Promise<{ data: T; hash: string | null }> =>
    loadRevalidated({
      contentHash: def.contentHash,
      cacheKey: cacheKeyFor(userId, key),
      collection: def.name,
      userId,
      extraKeys: [{ column: keyColumn, value: key }],
      loadFull: async () => {
        const { storage, keys } = getSecureStoreConfig();
        // Present only during an in-progress DEK rotation — see
        // `resolveAmbientIdentity`'s doc comment. Looked up independently here
        // (not threaded from `resolveAmbientIdentity`) because `load()` reaches
        // this same function with an explicit `cryptoHandle` — e.g. from
        // `useKeyedStore.ts`, which resolves identity from this SAME ambient
        // KeyProvider itself, outside `resolveAmbientIdentity` — and must get
        // the same fallback.
        const previousCryptoHandle = keys?.getPreviousCryptoHandle?.() ?? null;
        const { data, hash } = await loadRow(
          cryptoHandle,
          {
            get: () =>
              storage.get(def.name, userId, [
                { column: keyColumn, value: key },
              ]),
            put: (record) =>
              storage.put(
                def.name,
                userId,
                [{ column: keyColumn, value: key }],
                record,
              ),
          },
          canonicalAADFor(cryptoHandle, key),
          {
            storeName: def.name,
            rowLabel: "perKey ",
            version: def.version,
            migrators,
            empty,
            legacyAAD: def.legacyAAD?.(cryptoHandle, key),
          },
          (upgradedData) => keyedSave(userId, cryptoHandle, key, upgradedData),
          previousCryptoHandle
            ? {
                cryptoHandle: previousCryptoHandle,
                aad: canonicalAADFor(previousCryptoHandle, key),
                legacyAAD: def.legacyAAD?.(previousCryptoHandle, key),
              }
            : null,
        );
        return { data: validateRead(data, `load(key=${key})`), hash };
      },
    });

  const keyed: KeyedStore<T> = {
    name: def.name,
    version: def.version,
    async load(userId, cryptoHandle, key) {
      return (await keyedLoadInternal(userId, cryptoHandle, key)).data;
    },
    save: keyedSave,
    async get(key) {
      const { cryptoHandle, userId } = resolveAmbientIdentity(def.name);
      return (await keyedLoadInternal(userId, cryptoHandle, key)).data;
    },
    async set(key, data) {
      if (def.optimisticLock) {
        throw new Error(
          `${def.name}.set(): refuses to run on an optimisticLock store — a blind overwrite ` +
            `would bypass the conflict protection this store declares. Use mutate() instead.`,
        );
      }
      const { cryptoHandle, userId } = resolveAmbientIdentity(def.name);
      const valid = validateWrite(data, `set(key=${key})`);
      await keyedSave(userId, cryptoHandle, key, valid);
      const hash = def.contentHash
        ? await cryptoHandle.hashContent!(toEnvelope(valid, def.version))
        : null;
      writeThroughCache(cacheKeyFor(userId, key), valid, hash);
      bumpRangeEpoch(userId, [key]);
    },
    async mutate(key, fn, options) {
      const { cryptoHandle, userId } = resolveAmbientIdentity(def.name);
      const maxAttempts = Math.max(1, options?.retryOnConflict ?? 1);
      for (let attempt = 1; attempt <= maxAttempts; attempt++) {
        if (keyed.saveIfMatch) {
          const { data: current, hash } = await keyedLoadInternal(
            userId,
            cryptoHandle,
            key,
          );
          const next = await fn(current);
          const result = await keyed.saveIfMatch(
            userId,
            cryptoHandle,
            key,
            next,
            hash,
          );
          if (result.ok) {
            writeThroughCache(cacheKeyFor(userId, key), next, result.hash);
            bumpRangeEpoch(userId, [key]);
            return next;
          }
          if (attempt === maxAttempts) {
            throw new OptimisticLockConflictError(def.name);
          }
          continue;
        }
        const { data: current, hash } = await keyedLoadInternal(
          userId,
          cryptoHandle,
          key,
        );
        const next = await fn(current);
        const validated = validateWrite(next, `mutate(key=${key})`);
        const nextHash = def.contentHash
          ? await cryptoHandle.hashContent!(toEnvelope(validated, def.version))
          : null;
        if (def.contentHash && hash !== null && nextHash === hash) return next;
        await keyedSave(userId, cryptoHandle, key, next);
        writeThroughCache(cacheKeyFor(userId, key), next, nextHash);
        bumpRangeEpoch(userId, [key]);
        return next;
      }
      // Unreachable — the loop above always returns or throws on its last iteration.
      throw new OptimisticLockConflictError(def.name);
    },
    async createMany(entries) {
      if (!entries.length) return;
      const { cryptoHandle, userId } = resolveAmbientIdentity(def.name);
      const { storage } = getSecureStoreConfig();
      if (!storage.insertMany) {
        throw new Error(
          `defineStore(${def.name}): the configured adapter doesn't support bulk keyed creation (insertMany missing).`,
        );
      }
      const prepared = await Promise.all(
        entries.map(async ({ key, data }) => {
          const valid = validateWrite(data, `createMany(key=${key})`);
          const record = await encodeBlob(
            cryptoHandle,
            canonicalAADFor(cryptoHandle, key),
            valid,
            def.version,
            def.contentHash,
          );
          return { key, valid, record };
        }),
      );
      await storage.insertMany(
        def.name,
        userId,
        prepared.map(({ key, record }) => ({
          extraKeys: [{ column: keyColumn, value: key }],
          record,
        })),
      );
      // Stesso schema di set()/mutate(): ogni chiave creata aggiorna il proprio
      // slot cache, un solo epoch bump per l'intero batch (un range montato che
      // osserva questo store deve rifare list() una volta sola, non N).
      for (const { key, valid, record } of prepared) {
        writeThroughCache(
          cacheKeyFor(userId, key),
          valid,
          record.contentHash ?? null,
        );
      }
      bumpRangeEpoch(
        userId,
        prepared.map(({ key }) => key),
      );
    },
    async list(userId, cryptoHandle, range) {
      const { storage, keys } = getSecureStoreConfig();
      if (!storage.listByKeyRange) {
        throw new Error(
          `defineStore(${def.name}): the configured adapter doesn't support perKey range queries (listByKeyRange missing).`,
        );
      }
      // See `keyedLoadInternal`'s doc comment — same independent lenient lookup,
      // covers both the ambient `getRange()` wrapper and this method's explicit
      // callers (e.g. `useKeyedStoreRange.ts`, aggregation sources).
      const previousCryptoHandle = keys?.getPreviousCryptoHandle?.() ?? null;
      const rows = await storage.listByKeyRange(
        def.name,
        userId,
        keyColumn,
        range.from,
        range.to,
      );
      const results: Array<{ key: string; data: T }> = [];
      for (const { key, record } of rows) {
        const candidates: DecodeCandidate[] = [
          {
            cryptoHandle,
            canonicalAAD: canonicalAADFor(cryptoHandle, key),
            legacyAAD: def.legacyAAD?.(cryptoHandle, key),
          },
        ];
        if (previousCryptoHandle) {
          candidates.push({
            cryptoHandle: previousCryptoHandle,
            canonicalAAD: canonicalAADFor(previousCryptoHandle, key),
            legacyAAD: def.legacyAAD?.(previousCryptoHandle, key),
          });
        }
        const { data, upgraded } = await decodeWithCandidates<T>(
          candidates,
          record,
          def.version,
          migrators,
          empty,
          (migratedRecord) =>
            storage.put(
              def.name,
              userId,
              [{ column: keyColumn, value: key }],
              migratedRecord,
            ),
        );
        if (upgraded) {
          keyedSave(userId, cryptoHandle, key, data).catch((e) =>
            console.error(
              `secure-store(${def.name}): perKey lazy upgrade failed:`,
              e,
            ),
          );
        }
        results.push({ key, data: validateRead(data, `list(key=${key})`) });
      }
      return results;
    },
    async getRange(range) {
      const { cryptoHandle, userId } = resolveAmbientIdentity(def.name);
      return keyed.list(userId, cryptoHandle, range);
    },
    async rotateEpoch(userId, oldHandle, newHandle, newEpoch) {
      const { storage } = getSecureStoreConfig();
      if (!storage.listAll) {
        throw new Error(
          `defineStore(${def.name}): the configured adapter doesn't support perKey enumeration (listAll missing) — required for DEK rotation.`,
        );
      }
      const rows = await storage.listAll(def.name, userId, keyColumn);
      let migrated = 0;
      let alreadyMigrated = 0;
      const failed: Array<{ key: unknown; error: string }> = [];
      for (const { key, record } of rows) {
        const oldAAD = canonicalAADFor(oldHandle, key);
        const newAAD = { ...canonicalAADFor(newHandle, key), epoch: newEpoch };
        try {
          const result = await reencryptRowIfNeeded(
            oldHandle,
            newHandle,
            oldAAD,
            newAAD,
            record,
            def.version,
            migrators,
            empty,
          );
          if (result === "already-migrated") {
            alreadyMigrated++;
            continue;
          }
          await storage.put(
            def.name,
            userId,
            [{ column: keyColumn, value: key }],
            result,
          );
          migrated++;
        } catch (e) {
          failed.push({ key, error: String(e) });
        }
      }
      return { migrated, alreadyMigrated, failed };
    },
  };

  if (def.contentHash) {
    keyed.loadWithHash = keyedLoadInternal;
    keyed.getHashesForKeys = async (userId, keys) => {
      const { storage } = getSecureStoreConfig();
      if (!storage.getHashesByKeys) {
        throw new Error(
          `defineStore(${def.name}): the configured adapter doesn't support batch hash reads (getHashesByKeys missing).`,
        );
      }
      return storage.getHashesByKeys(def.name, userId, keyColumn, keys);
    };
  }

  if (def.optimisticLock) {
    keyed.saveIfMatch = async (
      userId,
      cryptoHandle,
      key,
      data,
      expectedHash,
    ) => {
      const { storage } = getSecureStoreConfig();
      const valid = validateWrite(data, `saveIfMatch(key=${key})`);
      return saveRowIfMatch(
        cryptoHandle,
        storage.putIfMatch
          ? (record, hash) =>
              storage.putIfMatch!(
                def.name,
                userId,
                [{ column: keyColumn, value: key }],
                record,
                hash,
              )
          : undefined,
        canonicalAADFor(cryptoHandle, key),
        valid,
        def.version,
        expectedHash,
        `defineStore(${def.name}): the configured adapter doesn't support optimistic locking (putIfMatch missing).`,
      );
    };
  }

  return keyed;
}

// ── many: collection, framework-generated id; AAD.rowId = id ──────────────────
// Blob = only the encrypted fields (encryptedKeys); plaintextKeys become real
// columns, handled by the adapter alongside the blob. With pure encrypt:"all",
// plaintextKeys = [] → degenerates into the previous behavior (everything in the
// blob, no extra columns).
function buildCollectionStore<S extends z.ZodType>(
  { def, migrators, validateRead, validateWrite }: BuildContext<S>,
  encryptedKeys: string[],
  plaintextKeys: string[],
): CollectionStore<z.infer<S>> {
  type T = z.infer<S>;
  const generateId = def.idGenerator ?? randomId;
  const canonicalAADFor = (cryptoHandle: CryptoHandle, id: string): FieldAAD =>
    canonicalAAD(cryptoHandle, def.name, id);
  // Fallback for a row with a missing/corrupt blob: {} (never a genuinely valid
  // record, but `many` has no domain-level "empty value" — validateRead will
  // reject it with an explicit Zod error instead of failing the store's
  // definition for a default we'd never actually use, e.g. a required portfolioId).
  const emptyEncPart: Record<string, unknown> = {};
  const splitWrite = (data: T) => {
    const rec = data as Record<string, unknown>;
    return {
      plain: pick(rec, plaintextKeys),
      encPart: pick(rec, encryptedKeys),
    };
  };
  const mergeRead = (
    plain: Record<string, unknown>,
    encPart: Record<string, unknown>,
  ): T => ({ ...encPart, ...plain }) as T;

  const manyUpdate = async (
    userId: string,
    cryptoHandle: CryptoHandle,
    id: string,
    data: T,
  ): Promise<void> => {
    const valid = validateWrite(data, `update(id=${id})`);
    const { storage } = getSecureStoreConfig();
    if (!storage.updateById) {
      throw new Error(
        `defineStore(${def.name}): the configured adapter doesn't support 'many' (updateById missing).`,
      );
    }
    const { plain, encPart } = splitWrite(valid);
    const record = await encodeBlob(
      cryptoHandle,
      canonicalAADFor(cryptoHandle, id),
      encPart,
      def.version,
      def.contentHash,
    );
    await storage.updateById(def.name, userId, id, record, plain);
  };

  const collection: CollectionStore<T> = {
    name: def.name,
    version: def.version,
    async list(userId, cryptoHandle) {
      const { storage, keys } = getSecureStoreConfig();
      if (!storage.list) {
        throw new Error(
          `defineStore(${def.name}): the configured adapter doesn't support 'many' (list missing).`,
        );
      }
      // See `buildKeyedStore`'s `keyedLoadInternal`/`list` doc comments — same
      // independent lenient lookup, covers both the ambient `get()` wrapper and
      // this method's explicit callers.
      const previousCryptoHandle = keys?.getPreviousCryptoHandle?.() ?? null;
      const rows = await storage.list(def.name, userId, plaintextKeys);
      const results: Array<{ id: string; data: T; hash: string | null }> = [];
      for (const { id, record, plain } of rows) {
        const persistMigrated = (migratedRecord: BlobRecord) => {
          if (!storage.updateById) {
            throw new Error(
              `defineStore(${def.name}): legacyAAD/rotation migration for id=${id} succeeded, but the ` +
                `configured adapter doesn't support 'many' (updateById missing) — can't persist it.`,
            );
          }
          return storage.updateById(
            def.name,
            userId,
            id,
            migratedRecord,
            plain,
          );
        };
        const candidates: DecodeCandidate[] = [
          {
            cryptoHandle,
            canonicalAAD: canonicalAADFor(cryptoHandle, id),
            legacyAAD: def.legacyAAD?.(cryptoHandle, id),
          },
        ];
        if (previousCryptoHandle) {
          candidates.push({
            cryptoHandle: previousCryptoHandle,
            canonicalAAD: canonicalAADFor(previousCryptoHandle, id),
            legacyAAD: def.legacyAAD?.(previousCryptoHandle, id),
          });
        }
        const { data: encPart, upgraded } = await decodeWithCandidates<
          Record<string, unknown>
        >(
          candidates,
          record,
          def.version,
          migrators,
          emptyEncPart,
          persistMigrated,
        );
        const merged = mergeRead(plain, encPart);
        if (upgraded) {
          manyUpdate(userId, cryptoHandle, id, merged as T).catch((e) =>
            console.error(
              `secure-store(${def.name}): many lazy upgrade failed:`,
              e,
            ),
          );
        }
        results.push({
          id,
          data: validateRead(merged, `list(id=${id})`),
          hash: record?.contentHash ?? null,
        });
      }
      return results;
    },
    async create(userId, cryptoHandle, data) {
      const valid = validateWrite(data, "create");
      const { storage } = getSecureStoreConfig();
      if (!storage.insert) {
        throw new Error(
          `defineStore(${def.name}): the configured adapter doesn't support 'many' (insert missing).`,
        );
      }
      const id = generateId();
      const { plain, encPart } = splitWrite(valid);
      const record = await encodeBlob(
        cryptoHandle,
        canonicalAADFor(cryptoHandle, id),
        encPart,
        def.version,
        def.contentHash,
      );
      await storage.insert(def.name, userId, id, record, plain);
      return id;
    },
    update: manyUpdate,
    async remove(userId, cryptoHandle, id) {
      const { storage } = getSecureStoreConfig();
      if (!storage.deleteById) {
        throw new Error(
          `defineStore(${def.name}): the configured adapter doesn't support 'many' (deleteById missing).`,
        );
      }
      await storage.deleteById(def.name, userId, id);
    },
    async get() {
      const { cryptoHandle, userId } = resolveAmbientIdentity(def.name);
      return collection.list(userId, cryptoHandle);
    },
    async add(data) {
      const { cryptoHandle, userId } = resolveAmbientIdentity(def.name);
      return collection.create(userId, cryptoHandle, data);
    },
    async discard(id) {
      const { cryptoHandle, userId } = resolveAmbientIdentity(def.name);
      await collection.remove(userId, cryptoHandle, id);
    },
    async rotateEpoch(userId, oldHandle, newHandle, newEpoch) {
      const { storage } = getSecureStoreConfig();
      if (!storage.list) {
        throw new Error(
          `defineStore(${def.name}): the configured adapter doesn't support 'many' (list missing).`,
        );
      }
      if (!storage.updateById) {
        throw new Error(
          `defineStore(${def.name}): the configured adapter doesn't support 'many' (updateById missing).`,
        );
      }
      const rows = await storage.list(def.name, userId, plaintextKeys);
      let migrated = 0;
      let alreadyMigrated = 0;
      const failed: Array<{ key: unknown; error: string }> = [];
      for (const { id, record, plain } of rows) {
        const oldAAD = canonicalAADFor(oldHandle, id);
        const newAAD = { ...canonicalAADFor(newHandle, id), epoch: newEpoch };
        try {
          const result = await reencryptRowIfNeeded(
            oldHandle,
            newHandle,
            oldAAD,
            newAAD,
            record,
            def.version,
            migrators,
            emptyEncPart,
          );
          if (result === "already-migrated") {
            alreadyMigrated++;
            continue;
          }
          await storage.updateById(def.name, userId, id, result, plain);
          migrated++;
        } catch (e) {
          failed.push({ key: id, error: String(e) });
        }
      }
      return { migrated, alreadyMigrated, failed };
    },
  };

  if (def.optimisticLock) {
    collection.updateIfMatch = async (
      userId,
      cryptoHandle,
      id,
      data,
      expectedHash,
    ) => {
      const { storage } = getSecureStoreConfig();
      if (!storage.updateByIdIfMatch) {
        throw new Error(
          `defineStore(${def.name}): the configured adapter doesn't support optimistic locking (updateByIdIfMatch missing).`,
        );
      }
      const valid = validateWrite(data, `updateIfMatch(id=${id})`);
      const { plain, encPart } = splitWrite(valid);
      const record = await encodeBlob(
        cryptoHandle,
        canonicalAADFor(cryptoHandle, id),
        encPart,
        def.version,
        true,
      );
      const ok = await storage.updateByIdIfMatch(
        def.name,
        userId,
        id,
        record,
        plain,
        expectedHash,
      );
      return { ok, hash: ok ? (record.contentHash ?? null) : null };
    };
  }

  return collection;
}

// ── perUser: one blob per user ──────────────────────────────────────────────────
/**
 * Pushes a fresh `{data, hash}` entry into the configured `CacheAdapter` right after a
 * successful ambient write (`set()`/`mutate()`), using the SAME cache-key scheme the
 * React bindings (`useStore`/`useKeyedStore`) already use. No-op if no cache is
 * configured (Node/script/test contexts). This is what makes a service calling
 * `.mutate()` directly (outside any React hook) keep every mounted `useStore`/
 * `useKeyedStore` consumer for that store in sync — previously only the hooks'
 * own `save()` touched the cache, so an ambient write left them stale.
 */
function writeThroughCache<T>(
  cacheKey: string,
  data: T,
  hash: string | null,
): void {
  const { cache } = getSecureStoreConfig();
  cache?.set(cacheKey, { data, hash });
}

function buildPerUserStore<S extends z.ZodType>({
  def,
  validateRead,
  validateWrite,
}: BuildContext<S>): Store<z.infer<S>> {
  type T = z.infer<S>;
  const empty = resolveEmpty(def);
  const cacheKeyFor = (userId: string): string => `${def.name}:${userId}`;
  const inner = defineBlobStore<T>({
    name: def.name,
    version: def.version,
    empty,
    migrators: def.migrators,
    contentHash: def.contentHash,
    optimisticLock: def.optimisticLock,
    legacyAAD: def.legacyAAD
      ? (cryptoHandle) => def.legacyAAD!(cryptoHandle, cryptoHandle.pid)
      : undefined,
  });

  const perUserLoadInternal = async (
    userId: string,
    cryptoHandle: CryptoHandle,
  ): Promise<{ data: T; hash: string | null }> =>
    loadRevalidated({
      contentHash: def.contentHash,
      cacheKey: cacheKeyFor(userId),
      collection: def.name,
      userId,
      extraKeys: [],
      loadFull: async () => {
        if (inner.loadWithHash) return inner.loadWithHash(userId, cryptoHandle);
        return { data: await inner.load(userId, cryptoHandle), hash: null };
      },
    });

  const store: Store<T> = {
    name: def.name,
    version: def.version,
    async load(userId, cryptoHandle) {
      const { data } = await perUserLoadInternal(userId, cryptoHandle);
      return validateRead(data, "load");
    },
    async save(userId, cryptoHandle, data) {
      await inner.save(userId, cryptoHandle, validateWrite(data, "save"));
    },
    async get() {
      const { cryptoHandle, userId } = resolveAmbientIdentity(def.name);
      const { data } = await perUserLoadInternal(userId, cryptoHandle);
      return validateRead(data, "get");
    },
    async set(data) {
      if (def.optimisticLock) {
        throw new Error(
          `${def.name}.set(): refuses to run on an optimisticLock store — a blind overwrite ` +
            `would bypass the conflict protection this store declares. Use mutate() instead.`,
        );
      }
      const { cryptoHandle, userId } = resolveAmbientIdentity(def.name);
      const valid = validateWrite(data, "set");
      await inner.save(userId, cryptoHandle, valid);
      const hash = def.contentHash
        ? await cryptoHandle.hashContent!(toEnvelope(valid, def.version))
        : null;
      writeThroughCache(cacheKeyFor(userId), valid, hash);
    },
    async mutate(fn, options) {
      const { cryptoHandle, userId } = resolveAmbientIdentity(def.name);
      const maxAttempts = Math.max(1, options?.retryOnConflict ?? 1);
      for (let attempt = 1; attempt <= maxAttempts; attempt++) {
        const { data: rawCurrent, hash } = await perUserLoadInternal(
          userId,
          cryptoHandle,
        );
        const current = validateRead(rawCurrent, "mutate");
        const next = await fn(current);
        if (store.saveIfMatch) {
          const result = await store.saveIfMatch(
            userId,
            cryptoHandle,
            next,
            hash,
          );
          if (result.ok) {
            writeThroughCache(cacheKeyFor(userId), next, result.hash);
            return next;
          }
          if (attempt === maxAttempts) {
            throw new OptimisticLockConflictError(def.name);
          }
          continue;
        }
        const validated = validateWrite(next, "mutate");
        const nextHash = def.contentHash
          ? await cryptoHandle.hashContent!(toEnvelope(validated, def.version))
          : null;
        if (def.contentHash && hash !== null && nextHash === hash) return next;
        await inner.save(userId, cryptoHandle, validated);
        writeThroughCache(cacheKeyFor(userId), next, nextHash);
        return next;
      }
      // Unreachable — the loop above always returns or throws on its last iteration.
      throw new OptimisticLockConflictError(def.name);
    },
    async rotateEpoch(userId, oldHandle, newHandle, newEpoch) {
      const { storage } = getSecureStoreConfig();
      const record = await storage.get(def.name, userId, []);
      if (!record) return { migrated: 0, alreadyMigrated: 0, failed: [] };
      const oldAAD = canonicalAAD(oldHandle, def.name);
      const newAAD = { ...canonicalAAD(newHandle, def.name), epoch: newEpoch };
      try {
        const result = await reencryptRowIfNeeded(
          oldHandle,
          newHandle,
          oldAAD,
          newAAD,
          record,
          def.version,
          def.migrators ?? [],
          empty,
        );
        if (result === "already-migrated") {
          return { migrated: 0, alreadyMigrated: 1, failed: [] };
        }
        await storage.put(def.name, userId, [], result);
        return { migrated: 1, alreadyMigrated: 0, failed: [] };
      } catch (e) {
        return {
          migrated: 0,
          alreadyMigrated: 0,
          failed: [{ key: userId, error: String(e) }],
        };
      }
    },
  };

  if (def.contentHash) {
    store.loadWithHash = async (userId, cryptoHandle) => {
      const { data, hash } = await perUserLoadInternal(userId, cryptoHandle);
      return { data: validateRead(data, "loadWithHash"), hash };
    };
  }

  if (def.optimisticLock) {
    store.saveIfMatch = async (userId, cryptoHandle, data, expectedHash) => {
      return inner.saveIfMatch!(
        userId,
        cryptoHandle,
        validateWrite(data, "saveIfMatch"),
        expectedHash,
      );
    };
  }

  return store;
}

/** Explicit `empty`, or derived from the schema's defaults (`.default()`). */
type CachedEntry<T> = { data: T; hash: string | null };

/**
 * Cache-first load with hash revalidation. Serves the cached entry ONLY after
 * the server's content_hash matched it — the core has no staleTime concept, a
 * cached entry is never trusted blindly. Falls back to a full load (and
 * refreshes the cache slot) in every other case. No-op passthrough when the
 * store has no contentHash, no cache is configured, or the adapter can't do
 * hash-only reads.
 */
async function loadRevalidated<T>(opts: {
  contentHash: boolean | undefined;
  cacheKey: string;
  collection: string;
  userId: string;
  extraKeys: KeyColumn[];
  loadFull: () => Promise<CachedEntry<T>>;
}): Promise<CachedEntry<T>> {
  const { cache, storage } = getSecureStoreConfig();
  if (!opts.contentHash || !cache || !storage.getHash) return opts.loadFull();
  const cached = cache.get<CachedEntry<T>>(opts.cacheKey);
  if (cached !== undefined && cached.hash !== null) {
    const serverHash = await storage.getHash(
      opts.collection,
      opts.userId,
      opts.extraKeys,
    );
    if (serverHash !== null && serverHash === cached.hash) return cached;
  }
  const fresh = await opts.loadFull();
  cache.set(opts.cacheKey, fresh);
  return fresh;
}

function resolveEmpty<S extends z.ZodType>(def: StoreDef<S>): z.infer<S> {
  if (def.empty !== undefined) return def.empty;
  const fromUndefined = def.schema.safeParse(undefined);
  if (fromUndefined.success) return fromUndefined.data as z.infer<S>;
  const fromEmptyObject = def.schema.safeParse({});
  if (fromEmptyObject.success) return fromEmptyObject.data as z.infer<S>;
  throw new Error(
    `defineStore(${def.name}): unable to derive 'empty' from the schema — ` +
      `provide 'empty' in the def, or add .default() to the fields.`,
  );
}

function pick(
  obj: Record<string, unknown>,
  keys: string[],
): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const k of keys) out[k] = obj[k];
  return out;
}
