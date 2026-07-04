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
   * (pre-DataCloak) AAD shape for a given row — `rowKey` is `dek.pid` for `perUser`,
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
  legacyAAD?: (dek: CryptoHandle, rowKey: string) => FieldAAD;
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
}

/** `perUser`-cardinality store: one blob per user. */
export interface Store<T> {
  readonly name: string;
  readonly version: number;
  load(userId: string, dek: CryptoHandle): Promise<T>;
  save(userId: string, dek: CryptoHandle, data: T): Promise<void>;
  /** Present only when the store declares `contentHash: true`. */
  loadWithHash?(
    userId: string,
    dek: CryptoHandle,
  ): Promise<{ data: T; hash: string | null }>;
  /**
   * Present only when the store declares `optimisticLock: true`. See `StoreDef.optimisticLock`.
   * On success, `hash` is the new content_hash — pass it straight into the next
   * `saveIfMatch` call, no extra fetch needed. `null` on conflict (`ok:false`).
   */
  saveIfMatch?(
    userId: string,
    dek: CryptoHandle,
    data: T,
    expectedHash: string | null,
  ): Promise<{ ok: boolean; hash: string | null }>;
}

/** `perKey`-cardinality store: one blob per `(user, domain key)`. */
export interface KeyedStore<T> {
  readonly name: string;
  readonly version: number;
  load(userId: string, dek: CryptoHandle, key: string): Promise<T>;
  save(userId: string, dek: CryptoHandle, key: string, data: T): Promise<void>;
  /** Range query over sortable keys (e.g. `year_month`) — needs `listByKeyRange` on the adapter. */
  list(
    userId: string,
    dek: CryptoHandle,
    range: { from: string; to: string },
  ): Promise<Array<{ key: string; data: T }>>;
  /** Present only when the store declares `contentHash: true`. */
  loadWithHash?(
    userId: string,
    dek: CryptoHandle,
    key: string,
  ): Promise<{ data: T; hash: string | null }>;
  /**
   * Present only when the store declares `optimisticLock: true`. See `StoreDef.optimisticLock`.
   * On success, `hash` is the new content_hash — pass it straight into the next
   * `saveIfMatch` call, no extra fetch needed. `null` on conflict (`ok:false`).
   */
  saveIfMatch?(
    userId: string,
    dek: CryptoHandle,
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
    dek: CryptoHandle,
  ): Promise<Array<{ id: string; data: T; hash: string | null }>>;
  create(userId: string, dek: CryptoHandle, data: T): Promise<string>;
  update(userId: string, dek: CryptoHandle, id: string, data: T): Promise<void>;
  remove(userId: string, dek: CryptoHandle, id: string): Promise<void>;
  /**
   * Present only when the store declares `optimisticLock: true`. `expectedHash`
   * comes from the `hash` field returned alongside each row in `list()` — see
   * README's "Optimistic locking" section. On success, `hash` is the row's new
   * content_hash — pass it into the next `updateIfMatch` call, no extra fetch
   * needed. `null` on conflict (`ok:false`).
   */
  updateIfMatch?(
    userId: string,
    dek: CryptoHandle,
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

  // ── perKey: one blob per (user, key); AAD.rowId = key ────────────────────────────
  if (typeof identity === "object" && "perKey" in identity) {
    const empty = resolveEmpty(def);
    const keyColumn = identity.perKey;
    const canonicalAADFor = (dek: CryptoHandle, key: string): FieldAAD =>
      canonicalAAD(dek, def.name, key);

    const keyedSave = async (
      userId: string,
      dek: CryptoHandle,
      key: string,
      data: T,
    ): Promise<void> => {
      const valid = validateWrite(data, `save(key=${key})`);
      const { storage } = getSecureStoreConfig();
      await saveRow(
        dek,
        (record) =>
          storage.put(
            def.name,
            userId,
            [{ column: keyColumn, value: key }],
            record,
          ),
        canonicalAADFor(dek, key),
        valid,
        def.version,
        def.contentHash,
      );
    };

    const keyedLoadInternal = async (
      userId: string,
      dek: CryptoHandle,
      key: string,
    ): Promise<{ data: T; hash: string | null }> => {
      const { storage } = getSecureStoreConfig();
      const { data, hash } = await loadRow(
        dek,
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
        canonicalAADFor(dek, key),
        {
          storeName: def.name,
          rowLabel: "perKey ",
          version: def.version,
          migrators,
          empty,
          legacyAAD: def.legacyAAD?.(dek, key),
        },
        (upgradedData) => keyedSave(userId, dek, key, upgradedData),
      );
      return { data: validateRead(data, `load(key=${key})`), hash };
    };

    const keyed: KeyedStore<T> = {
      name: def.name,
      version: def.version,
      async load(userId, dek, key) {
        return (await keyedLoadInternal(userId, dek, key)).data;
      },
      save: keyedSave,
      async list(userId, dek, range) {
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
            dek,
            record,
            canonicalAAD: canonicalAADFor(dek, key),
            legacyAAD: def.legacyAAD?.(dek, key),
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
            keyedSave(userId, dek, key, data).catch((e) =>
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
    };

    if (def.contentHash) {
      keyed.loadWithHash = keyedLoadInternal;
    }

    if (def.optimisticLock) {
      keyed.saveIfMatch = async (userId, dek, key, data, expectedHash) => {
        const { storage } = getSecureStoreConfig();
        const valid = validateWrite(data, `saveIfMatch(key=${key})`);
        return saveRowIfMatch(
          dek,
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
          canonicalAADFor(dek, key),
          valid,
          def.version,
          expectedHash,
          `defineStore(${def.name}): the configured adapter doesn't support optimistic locking (putIfMatch missing).`,
        );
      };
    }

    return keyed as StoreApi<S, Id>;
  }

  // ── many: collection, framework-generated id; AAD.rowId = id ────────────────────
  // Blob = only the encrypted fields (encryptedKeys); plaintextKeys become real
  // columns, handled by the adapter alongside the blob. With pure encrypt:"all",
  // plaintextKeys = [] → degenerates into the previous behavior (everything in the
  // blob, no extra columns).
  if (identity === "many") {
    const canonicalAADFor = (dek: CryptoHandle, id: string): FieldAAD =>
      canonicalAAD(dek, def.name, id);
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
      dek: CryptoHandle,
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
        dek,
        canonicalAADFor(dek, id),
        encPart,
        def.version,
        def.contentHash,
      );
      await storage.updateById(def.name, userId, id, record, plain);
    };

    const collection: CollectionStore<T> = {
      name: def.name,
      version: def.version,
      async list(userId, dek) {
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
            dek,
            record,
            canonicalAAD: canonicalAADFor(dek, id),
            legacyAAD: def.legacyAAD?.(dek, id),
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
            manyUpdate(userId, dek, id, merged as T).catch((e) =>
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
      async create(userId, dek, data) {
        const valid = validateWrite(data, "create");
        const { storage } = getSecureStoreConfig();
        if (!storage.insert) {
          throw new Error(
            `defineStore(${def.name}): the configured adapter doesn't support 'many' (insert missing).`,
          );
        }
        const id = randomId();
        const { plain, encPart } = splitWrite(valid);
        const record = await encodeBlob(
          dek,
          canonicalAADFor(dek, id),
          encPart,
          def.version,
          def.contentHash,
        );
        await storage.insert(def.name, userId, id, record, plain);
        return id;
      },
      update: manyUpdate,
      async remove(userId, dek, id) {
        const { storage } = getSecureStoreConfig();
        if (!storage.deleteById) {
          throw new Error(
            `defineStore(${def.name}): the configured adapter doesn't support 'many' (deleteById missing).`,
          );
        }
        await storage.deleteById(def.name, userId, id);
      },
    };

    if (def.optimisticLock) {
      collection.updateIfMatch = async (
        userId,
        dek,
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
          dek,
          canonicalAADFor(dek, id),
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

    return collection as StoreApi<S, Id>;
  }

  // ── perUser: one blob per user (the last remaining cardinality) ─────────────────
  const empty = resolveEmpty(def);
  const inner = defineBlobStore<T>({
    name: def.name,
    version: def.version,
    empty,
    migrators: def.migrators,
    contentHash: def.contentHash,
    optimisticLock: def.optimisticLock,
    legacyAAD: def.legacyAAD
      ? (dek) => def.legacyAAD!(dek, dek.pid)
      : undefined,
  });
  const store: Store<T> = {
    name: def.name,
    version: def.version,
    async load(userId, dek) {
      return validateRead(await inner.load(userId, dek), "load");
    },
    async save(userId, dek, data) {
      await inner.save(userId, dek, validateWrite(data, "save"));
    },
  };

  if (def.contentHash) {
    store.loadWithHash = async (userId, dek) => {
      const { data, hash } = await inner.loadWithHash!(userId, dek);
      return { data: validateRead(data, "loadWithHash"), hash };
    };
  }

  if (def.optimisticLock) {
    store.saveIfMatch = async (userId, dek, data, expectedHash) => {
      return inner.saveIfMatch!(
        userId,
        dek,
        validateWrite(data, "saveIfMatch"),
        expectedHash,
      );
    };
  }

  return store as StoreApi<S, Id>;
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
