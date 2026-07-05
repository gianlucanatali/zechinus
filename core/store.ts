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
import { decodeWithLegacyFallback } from "./legacyFallback.ts";
import { getSecureStoreConfig } from "./config.ts";
import { randomId } from "./randomId.ts";
import type { BlobMigrator } from "./versioning.ts";
import { collectEncryptedKeys } from "./encryption.ts";
import { fingerprintSchema } from "./schemaFingerprint.ts";
import type { CryptoHandle, FieldAAD } from "./types.ts";
import { OptimisticLockConflictError } from "./errors.ts";

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
    throw new Error(`${storeName}: no active session (locked)`);
  }
  return { cryptoHandle, userId };
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
   * internally (SHA-256 of the plaintext envelope, see `core/contentHash.ts`), no
   * app-supplied function needed: hashing JSON is fully generic, unlike
   * `StorageAdapter`/`KeyProvider` which genuinely need app-specific knowledge.
   * Omit (or `false`) for tables without the column.
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
   */
  mutate(fn: (current: T) => T | Promise<T>): Promise<T>;
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
  /** Load → transform → save for the given key, no `userId`/`CryptoHandle` in sight — see `Store.mutate`. */
  mutate(key: string, fn: (current: T) => T | Promise<T>): Promise<T>;
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
function buildKeyedStore<S extends z.ZodType>(
  { def, migrators, validateRead, validateWrite }: BuildContext<S>,
  keyColumn: string,
): KeyedStore<z.infer<S>> {
  type T = z.infer<S>;
  const empty = resolveEmpty(def);
  const canonicalAADFor = (cryptoHandle: CryptoHandle, key: string): FieldAAD =>
    canonicalAAD(cryptoHandle, def.name, key);

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
  ): Promise<{ data: T; hash: string | null }> => {
    const { storage } = getSecureStoreConfig();
    const { data, hash } = await loadRow(
      cryptoHandle,
      {
        get: () =>
          storage.get(def.name, userId, [{ column: keyColumn, value: key }]),
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
    );
    return { data: validateRead(data, `load(key=${key})`), hash };
  };

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
      await keyedSave(userId, cryptoHandle, key, data);
    },
    async mutate(key, fn) {
      const { cryptoHandle, userId } = resolveAmbientIdentity(def.name);
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
        if (!result.ok) {
          throw new OptimisticLockConflictError(def.name);
        }
        return next;
      }
      const current = (await keyedLoadInternal(userId, cryptoHandle, key)).data;
      const next = await fn(current);
      await keyedSave(userId, cryptoHandle, key, next);
      return next;
    },
    async list(userId, cryptoHandle, range) {
      const { storage } = getSecureStoreConfig();
      if (!storage.listByKeyRange) {
        throw new Error(
          `defineStore(${def.name}): the configured adapter doesn't support perKey range queries (listByKeyRange missing).`,
        );
      }
      const rows = await storage.listByKeyRange(
        def.name,
        userId,
        keyColumn,
        range.from,
        range.to,
      );
      const results: Array<{ key: string; data: T }> = [];
      for (const { key, record } of rows) {
        const { data, upgraded } = await decodeWithLegacyFallback<T>({
          cryptoHandle,
          record,
          canonicalAAD: canonicalAADFor(cryptoHandle, key),
          legacyAAD: def.legacyAAD?.(cryptoHandle, key),
          version: def.version,
          migrators,
          empty,
          persistMigrated: (migratedRecord) =>
            storage.put(
              def.name,
              userId,
              [{ column: keyColumn, value: key }],
              migratedRecord,
            ),
        });
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
  };

  if (def.contentHash) {
    keyed.loadWithHash = keyedLoadInternal;
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
      const { storage } = getSecureStoreConfig();
      if (!storage.list) {
        throw new Error(
          `defineStore(${def.name}): the configured adapter doesn't support 'many' (list missing).`,
        );
      }
      const rows = await storage.list(def.name, userId, plaintextKeys);
      const results: Array<{ id: string; data: T; hash: string | null }> = [];
      for (const { id, record, plain } of rows) {
        const { data: encPart, upgraded } = await decodeWithLegacyFallback<
          Record<string, unknown>
        >({
          cryptoHandle,
          record,
          canonicalAAD: canonicalAADFor(cryptoHandle, id),
          legacyAAD: def.legacyAAD?.(cryptoHandle, id),
          version: def.version,
          migrators,
          empty: emptyEncPart,
          persistMigrated: (migratedRecord) => {
            if (!storage.updateById) {
              throw new Error(
                `defineStore(${def.name}): legacyAAD migration for id=${id} succeeded, but the ` +
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
          },
        });
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
function buildPerUserStore<S extends z.ZodType>({
  def,
  validateRead,
  validateWrite,
}: BuildContext<S>): Store<z.infer<S>> {
  type T = z.infer<S>;
  const empty = resolveEmpty(def);
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
  const store: Store<T> = {
    name: def.name,
    version: def.version,
    async load(userId, cryptoHandle) {
      return validateRead(await inner.load(userId, cryptoHandle), "load");
    },
    async save(userId, cryptoHandle, data) {
      await inner.save(userId, cryptoHandle, validateWrite(data, "save"));
    },
    async get() {
      const { cryptoHandle, userId } = resolveAmbientIdentity(def.name);
      return validateRead(await inner.load(userId, cryptoHandle), "get");
    },
    async set(data) {
      if (def.optimisticLock) {
        throw new Error(
          `${def.name}.set(): refuses to run on an optimisticLock store — a blind overwrite ` +
            `would bypass the conflict protection this store declares. Use mutate() instead.`,
        );
      }
      const { cryptoHandle, userId } = resolveAmbientIdentity(def.name);
      await inner.save(userId, cryptoHandle, validateWrite(data, "set"));
    },
    async mutate(fn) {
      const { cryptoHandle, userId } = resolveAmbientIdentity(def.name);
      if (store.saveIfMatch) {
        const { data: current, hash } = await store.loadWithHash!(
          userId,
          cryptoHandle,
        );
        const next = await fn(current);
        const result = await store.saveIfMatch(
          userId,
          cryptoHandle,
          next,
          hash,
        );
        if (!result.ok) {
          throw new OptimisticLockConflictError(def.name);
        }
        return next;
      }
      const current = validateRead(
        await inner.load(userId, cryptoHandle),
        "mutate",
      );
      const next = await fn(current);
      await inner.save(userId, cryptoHandle, validateWrite(next, "mutate"));
      return next;
    },
  };

  if (def.contentHash) {
    store.loadWithHash = async (userId, cryptoHandle) => {
      const { data, hash } = await inner.loadWithHash!(userId, cryptoHandle);
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
