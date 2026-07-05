/**
 * Supabase StorageAdapter for blob-mode stores.
 * One row per user: columns (user_id, blob, content_hash?, schema_version, updated_at).
 *
 * The client is injected (not imported from src/) so the core stays agnostic:
 *   configureSecureStore({ storage: supabaseStorageAdapter(getSupabaseClient) })
 */

import type { SupabaseClient } from "@supabase/supabase-js";
import type { StorageAdapter, BlobRecord, KeyColumn } from "../core/types.ts";

async function selectRow(
  client: SupabaseClient,
  collection: string,
  userId: string,
  extraKeys: KeyColumn[],
  columns: string,
): Promise<{
  data: Record<string, unknown> | null;
  error: { message: string } | null;
}> {
  let query = client.from(collection).select(columns).eq("user_id", userId);
  for (const k of extraKeys) query = query.eq(k.column, k.value);
  return query.maybeSingle();
}

function describeKeys(extraKeys: KeyColumn[]): string {
  return extraKeys.map((k) => `, ${k.column}=${k.value}`).join("");
}

function mapBlobRow(data: Record<string, unknown> | null): BlobRecord | null {
  if (!data) return null;
  return {
    schemaVersion: (data.schema_version as number | null) ?? 1,
    blob: data.blob as string,
  };
}

function upsertRow(
  client: SupabaseClient,
  collection: string,
  row: Record<string, unknown>,
  conflictCols: string[],
) {
  return client
    .from(collection)
    .upsert(row, { onConflict: conflictCols.join(",") });
}

export function supabaseStorageAdapter(
  getClient: () => SupabaseClient,
): StorageAdapter {
  return {
    async get(collection, userId, extraKeys): Promise<BlobRecord | null> {
      const { data, error } = await selectRow(
        getClient(),
        collection,
        userId,
        extraKeys,
        "schema_version, blob",
      );
      if (error)
        throw new Error(
          `supabaseStorageAdapter.get(${collection}, ${userId}${describeKeys(extraKeys)}): ${error.message}`,
        );
      return mapBlobRow(data);
    },

    async getHash(collection, userId, extraKeys): Promise<string | null> {
      const { data, error } = await selectRow(
        getClient(),
        collection,
        userId,
        extraKeys,
        "content_hash",
      );
      if (error)
        throw new Error(
          `supabaseStorageAdapter.getHash(${collection}, ${userId}${describeKeys(extraKeys)}): ${error.message}`,
        );
      return (data?.content_hash as string | null) ?? null;
    },

    async put(collection, userId, extraKeys, record): Promise<void> {
      const row: Record<string, unknown> = { user_id: userId };
      for (const k of extraKeys) row[k.column] = k.value;
      row.blob = record.blob;
      row.schema_version = record.schemaVersion;
      row.updated_at = new Date().toISOString();
      if (record.contentHash !== undefined)
        row.content_hash = record.contentHash;
      const { error } = await upsertRow(getClient(), collection, row, [
        "user_id",
        ...extraKeys.map((k) => k.column),
      ]);
      if (error)
        throw new Error(
          `supabaseStorageAdapter.put(${collection}, ${userId}${describeKeys(extraKeys)}): ${error.message}`,
        );
    },

    /**
     * `expectedHash: null` means "I believe there's no REAL content yet" — either the
     * row doesn't exist, or it exists but was never hashed (legacy data from before
     * `content_hash` existed). Tries a plain INSERT first; a unique-constraint
     * violation (Postgres SQLSTATE 23505, surfaced by PostgREST as `error.code`) means
     * the row already exists, so we fall back to a guarded UPDATE that only succeeds
     * if the row's `content_hash` is still null — PostgREST's `.upsert()` can't express
     * a conditional `ON CONFLICT ... WHERE`, so this is two round-trips instead of
     * `pgStorageAdapter`'s single atomic upsert, but the guarded UPDATE re-reads the
     * current state, so no real conflict slips through unnoticed. A REAL hash already
     * present → the guarded UPDATE matches nothing → genuine conflict, `false`, never
     * thrown. `expectedHash` set → `UPDATE ... WHERE ... AND content_hash = expected`,
     * `.select()` to see which rows matched — zero rows back means either the hash
     * didn't match or the row is gone → `false`, same non-throwing contract.
     */
    async putIfMatch(
      collection,
      userId,
      extraKeys,
      record,
      expectedHash,
    ): Promise<boolean> {
      const client = getClient();
      if (expectedHash === null) {
        const row: Record<string, unknown> = { user_id: userId };
        for (const k of extraKeys) row[k.column] = k.value;
        row.blob = record.blob;
        row.schema_version = record.schemaVersion;
        row.updated_at = new Date().toISOString();
        if (record.contentHash !== undefined)
          row.content_hash = record.contentHash;
        const { error } = await client.from(collection).insert(row);
        if (!error) return true;
        if (error.code !== "23505")
          throw new Error(
            `supabaseStorageAdapter.putIfMatch(${collection}, ${userId}${describeKeys(extraKeys)}): ${error.message}`,
          );
        const updateRow: Record<string, unknown> = {
          blob: record.blob,
          schema_version: record.schemaVersion,
          updated_at: new Date().toISOString(),
        };
        if (record.contentHash !== undefined)
          updateRow.content_hash = record.contentHash;
        let legacyQuery = client
          .from(collection)
          .update(updateRow)
          .eq("user_id", userId);
        for (const k of extraKeys)
          legacyQuery = legacyQuery.eq(k.column, k.value);
        const { data: legacyData, error: legacyError } = await legacyQuery
          .is("content_hash", null)
          .select("user_id");
        if (legacyError)
          throw new Error(
            `supabaseStorageAdapter.putIfMatch(${collection}, ${userId}${describeKeys(extraKeys)}): ${legacyError.message}`,
          );
        return (legacyData?.length ?? 0) > 0;
      }
      const row: Record<string, unknown> = {
        blob: record.blob,
        schema_version: record.schemaVersion,
        updated_at: new Date().toISOString(),
      };
      if (record.contentHash !== undefined)
        row.content_hash = record.contentHash;
      let query = client.from(collection).update(row).eq("user_id", userId);
      for (const k of extraKeys) query = query.eq(k.column, k.value);
      const { data, error } = await query
        .eq("content_hash", expectedHash)
        .select("user_id");
      if (error)
        throw new Error(
          `supabaseStorageAdapter.putIfMatch(${collection}, ${userId}${describeKeys(extraKeys)}): ${error.message}`,
        );
      return (data?.length ?? 0) > 0;
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

    /** Conditional variant of `updateById` — same null/hash semantics as `putIfMatch`. */
    async updateByIdIfMatch(
      collection,
      userId,
      id,
      record,
      plain,
      expectedHash,
    ): Promise<boolean> {
      const client = getClient();
      if (expectedHash === null) {
        const row: Record<string, unknown> = {
          ...plain,
          id,
          user_id: userId,
          blob: record.blob,
          schema_version: record.schemaVersion,
        };
        if (record.contentHash !== undefined)
          row.content_hash = record.contentHash;
        const { error } = await client.from(collection).insert(row);
        if (!error) return true;
        if (error.code !== "23505")
          throw new Error(
            `supabaseStorageAdapter.updateByIdIfMatch(${collection}, ${userId}, id=${id}): ${error.message}`,
          );
        const updateRow: Record<string, unknown> = {
          ...plain,
          blob: record.blob,
          schema_version: record.schemaVersion,
          updated_at: new Date().toISOString(),
        };
        if (record.contentHash !== undefined)
          updateRow.content_hash = record.contentHash;
        const { data: legacyData, error: legacyError } = await client
          .from(collection)
          .update(updateRow)
          .eq("user_id", userId)
          .eq("id", id)
          .is("content_hash", null)
          .select("id");
        if (legacyError)
          throw new Error(
            `supabaseStorageAdapter.updateByIdIfMatch(${collection}, ${userId}, id=${id}): ${legacyError.message}`,
          );
        return (legacyData?.length ?? 0) > 0;
      }
      const row: Record<string, unknown> = {
        ...plain,
        blob: record.blob,
        schema_version: record.schemaVersion,
        updated_at: new Date().toISOString(),
      };
      if (record.contentHash !== undefined)
        row.content_hash = record.contentHash;
      const { data, error } = await client
        .from(collection)
        .update(row)
        .eq("user_id", userId)
        .eq("id", id)
        .eq("content_hash", expectedHash)
        .select("id");
      if (error)
        throw new Error(
          `supabaseStorageAdapter.updateByIdIfMatch(${collection}, ${userId}, id=${id}): ${error.message}`,
        );
      return (data?.length ?? 0) > 0;
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
