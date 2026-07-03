/**
 * Supabase StorageAdapter for blob-mode stores.
 * One row per user: columns (user_id, blob, content_hash?, schema_version, updated_at).
 *
 * The client is injected (not imported from src/) so the core stays agnostic:
 *   configureSecureStore({ storage: supabaseStorageAdapter(getSupabaseClient) })
 */

import type { SupabaseClient } from "@supabase/supabase-js";
import type { StorageAdapter, BlobRecord } from "../core/types.ts";

export function supabaseStorageAdapter(
  getClient: () => SupabaseClient,
): StorageAdapter {
  return {
    async getOne(collection, userId): Promise<BlobRecord | null> {
      const { data, error } = await getClient()
        .from(collection)
        .select("schema_version, blob")
        .eq("user_id", userId)
        .maybeSingle();
      if (error)
        throw new Error(
          `supabaseStorageAdapter.getOne(${collection}, ${userId}): ${error.message}`,
        );
      if (!data) return null;
      return {
        schemaVersion: (data.schema_version as number | null) ?? 1,
        blob: data.blob as string,
      };
    },

    async putOne(collection, userId, record): Promise<void> {
      const row: Record<string, unknown> = {
        user_id: userId,
        blob: record.blob,
        schema_version: record.schemaVersion,
        updated_at: new Date().toISOString(),
      };
      if (record.contentHash !== undefined)
        row.content_hash = record.contentHash;
      const { error } = await getClient()
        .from(collection)
        .upsert(row, { onConflict: "user_id" });
      if (error)
        throw new Error(
          `supabaseStorageAdapter.putOne(${collection}, ${userId}): ${error.message}`,
        );
    },

    async getByKey(
      collection,
      userId,
      keyColumn,
      keyValue,
    ): Promise<BlobRecord | null> {
      const { data, error } = await getClient()
        .from(collection)
        .select("schema_version, blob")
        .eq("user_id", userId)
        .eq(keyColumn, keyValue)
        .maybeSingle();
      if (error)
        throw new Error(
          `supabaseStorageAdapter.getByKey(${collection}, ${userId}, ${keyColumn}=${keyValue}): ${error.message}`,
        );
      if (!data) return null;
      return {
        schemaVersion: (data.schema_version as number | null) ?? 1,
        blob: data.blob as string,
      };
    },

    async putByKey(
      collection,
      userId,
      keyColumn,
      keyValue,
      record,
    ): Promise<void> {
      const row: Record<string, unknown> = {
        user_id: userId,
        [keyColumn]: keyValue,
        blob: record.blob,
        schema_version: record.schemaVersion,
        updated_at: new Date().toISOString(),
      };
      if (record.contentHash !== undefined)
        row.content_hash = record.contentHash;
      const { error } = await getClient()
        .from(collection)
        .upsert(row, { onConflict: `user_id,${keyColumn}` });
      if (error)
        throw new Error(
          `supabaseStorageAdapter.putByKey(${collection}, ${userId}, ${keyColumn}=${keyValue}): ${error.message}`,
        );
    },

    async listByKeyRange(
      collection,
      userId,
      keyColumn,
      from,
      to,
    ): Promise<Array<{ key: string; record: BlobRecord }>> {
      const { data, error } = await getClient()
        .from(collection)
        .select(`${keyColumn}, schema_version, blob`)
        .eq("user_id", userId)
        .gte(keyColumn, from)
        .lte(keyColumn, to)
        .order(keyColumn);
      if (error)
        throw new Error(
          `supabaseStorageAdapter.listByKeyRange(${collection}, ${userId}, ${keyColumn}=[${from},${to}]): ${error.message}`,
        );
      // Dynamic `keyColumn` in the select string → GenericStringError, same as list() above.
      const rows = (data ?? []) as unknown as Record<string, unknown>[];
      return rows.map((row) => ({
        key: row[keyColumn] as string,
        record: {
          schemaVersion: (row.schema_version as number | null) ?? 1,
          blob: row.blob as string,
        },
      }));
    },

    async list(
      collection,
      userId,
      plainColumns,
    ): Promise<
      Array<{ id: string; record: BlobRecord; plain: Record<string, unknown> }>
    > {
      const columns = ["id", "schema_version", "blob", ...plainColumns].join(
        ", ",
      );
      const { data, error } = await getClient()
        .from(collection)
        .select(columns)
        .eq("user_id", userId);
      if (error)
        throw new Error(
          `supabaseStorageAdapter.list(${collection}, ${userId}): ${error.message}`,
        );
      // `columns` is built at runtime (dynamic list of plaintext columns) → `.select()`'s
      // literal type can't validate it, Supabase-js resolves to `GenericStringError`.
      // Explicit cast: the real shape is known (id/schema_version/blob + plainColumns).
      const rows = (data ?? []) as unknown as Record<string, unknown>[];
      return rows.map((row) => {
        const plain: Record<string, unknown> = {};
        for (const col of plainColumns) plain[col] = row[col];
        return {
          id: row.id as string,
          record: {
            schemaVersion: (row.schema_version as number | null) ?? 1,
            blob: row.blob as string,
          },
          plain,
        };
      });
    },

    async insert(collection, userId, id, record, plain): Promise<void> {
      const row: Record<string, unknown> = {
        ...plain,
        id,
        user_id: userId,
        blob: record.blob,
        schema_version: record.schemaVersion,
      };
      if (record.contentHash !== undefined)
        row.content_hash = record.contentHash;
      const { error } = await getClient().from(collection).insert(row);
      if (error)
        throw new Error(
          `supabaseStorageAdapter.insert(${collection}, ${userId}, id=${id}): ${error.message}`,
        );
    },

    async updateById(collection, userId, id, record, plain): Promise<void> {
      const row: Record<string, unknown> = {
        ...plain,
        blob: record.blob,
        schema_version: record.schemaVersion,
        updated_at: new Date().toISOString(),
      };
      if (record.contentHash !== undefined)
        row.content_hash = record.contentHash;
      const { error } = await getClient()
        .from(collection)
        .update(row)
        .eq("user_id", userId)
        .eq("id", id);
      if (error)
        throw new Error(
          `supabaseStorageAdapter.updateById(${collection}, ${userId}, id=${id}): ${error.message}`,
        );
    },

    async deleteById(collection, userId, id): Promise<void> {
      const { error } = await getClient()
        .from(collection)
        .delete()
        .eq("user_id", userId)
        .eq("id", id);
      if (error)
        throw new Error(
          `supabaseStorageAdapter.deleteById(${collection}, ${userId}, id=${id}): ${error.message}`,
        );
    },
  };
}
