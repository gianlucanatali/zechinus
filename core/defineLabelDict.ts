/**
 * `defineLabelDict` — recipe (sugar) over a `perKey` blob store, for the recurring
 * "dictionary of labels" pattern: `Record<entityId, label>`, encrypted whole, one
 * dict per (user, dict key) — e.g. all account nicknames, all category names.
 *
 * Zero new mechanics: it's `defineStore({ identity: { perKey }, schema: z.record(...) })`
 * plus load-mutate-save helpers so the caller never touches the raw dict shape by hand.
 * The schema is fixed (`Record<string, string>`), so `schemaFingerprint` never varies —
 * this recipe computes it internally; the caller never sees it.
 *
 * `keyColumn` is the one real extension point here: which DB column identifies WHICH
 * dictionary a row belongs to (EW's convention is `table_name`; another app might call
 * it something else) — injectable, not hardcoded, because it's a naming decision that
 * belongs to the consuming app's schema, not to DataCloak.
 */
import { z } from "zod";
import { defineStore } from "./store.ts";
import { fingerprintSchema } from "./schemaFingerprint.ts";
import type { BlobMigrator } from "./versioning.ts";
import type { CryptoHandle } from "./types.ts";

const DictSchema = z.record(z.string(), z.string());
const DICT_FINGERPRINT = fingerprintSchema(DictSchema, "all");

export interface LabelDictDef {
  /** Table/collection name = the `table` value in the AAD. */
  name: string;
  /** DB column identifying which dictionary a row is (default: `"table_name"`, EW's convention). */
  keyColumn?: string;
  version?: number;
  migrators?: BlobMigrator[];
}

export interface LabelDict {
  getLabel(
    userId: string,
    dek: CryptoHandle,
    dictKey: string,
    entityId: string,
  ): Promise<string | undefined>;
  setLabel(
    userId: string,
    dek: CryptoHandle,
    dictKey: string,
    entityId: string,
    label: string,
  ): Promise<void>;
  deleteLabel(
    userId: string,
    dek: CryptoHandle,
    dictKey: string,
    entityId: string,
  ): Promise<void>;
  getAll(
    userId: string,
    dek: CryptoHandle,
    dictKey: string,
  ): Promise<Record<string, string>>;
}

export function defineLabelDict(def: LabelDictDef): LabelDict {
  const keyColumn = def.keyColumn ?? "table_name";
  const store = defineStore({
    name: def.name,
    identity: { perKey: keyColumn },
    encrypt: "all",
    schema: DictSchema,
    version: def.version ?? 1,
    migrators: def.migrators,
    schemaFingerprint: DICT_FINGERPRINT,
  });

  return {
    async getLabel(userId, dek, dictKey, entityId) {
      const dict = await store.load(userId, dek, dictKey);
      return dict[entityId];
    },
    async setLabel(userId, dek, dictKey, entityId, label) {
      const dict = await store.load(userId, dek, dictKey);
      await store.save(userId, dek, dictKey, { ...dict, [entityId]: label });
    },
    async deleteLabel(userId, dek, dictKey, entityId) {
      const dict = await store.load(userId, dek, dictKey);
      const next = { ...dict };
      delete next[entityId];
      await store.save(userId, dek, dictKey, next);
    },
    async getAll(userId, dek, dictKey) {
      return store.load(userId, dek, dictKey);
    },
  };
}
