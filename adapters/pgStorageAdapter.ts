/**
 * Plain-Postgres StorageAdapter — for consumers who talk to Postgres directly
 * (self-hosted, RDS, etc.) instead of through Supabase's PostgREST layer.
 *
 * `supabaseStorageAdapter` is genuinely Supabase-specific: it uses `@supabase/supabase-js`'s
 * query builder, which talks to PostgREST (HTTP + RLS via JWT), not a raw Postgres
 * connection. This adapter implements the exact same `StorageAdapter` interface with real
 * SQL instead, so the same table shape (user_id, blob, schema_version, updated_at,
 * content_hash?, plus id/keyColumn where relevant) works against either.
 *
 * No hard dependency on `pg`/`postgres.js`: the client is duck-typed as `PgClient`
 * (`query(text, params) => { rows }`), matching node-postgres's `Pool`/`Client` shape.
 * The consumer supplies their own client, same pattern as `supabaseStorageAdapter(getClient)`.
 */

import type { StorageAdapter, BlobRecord } from "../core/types.ts";

export interface PgClient {
  query<T extends Record<string, unknown> = Record<string, unknown>>(
    text: string,
    params?: unknown[],
  ): Promise<{ rows: T[] }>;
}

/** Quotes a SQL identifier (table/column name). Values always go through $-params, never here. */
function quoteIdent(name: string): string {
  return `"${name.replace(/"/g, '""')}"`;
}

function paramList(start: number, count: number): string {
  return Array.from({ length: count }, (_, i) => `$${start + i}`).join(", ");
}

export function pgStorageAdapter(getClient: () => PgClient): StorageAdapter {
  return {
    async getOne(collection, userId): Promise<BlobRecord | null> {
      const { rows } = await getClient().query<{
        schema_version: number | null;
        blob: string;
      }>(
        `SELECT schema_version, blob FROM ${quoteIdent(collection)} WHERE user_id = $1 LIMIT 1`,
        [userId],
      );
      const row = rows[0];
      if (!row) return null;
      return { schemaVersion: row.schema_version ?? 1, blob: row.blob };
    },

    async putOne(collection, userId, record): Promise<void> {
      const columns = ["user_id", "blob", "schema_version", "updated_at"];
      const values: unknown[] = [
        userId,
        record.blob,
        record.schemaVersion,
        new Date().toISOString(),
      ];
      if (record.contentHash !== undefined) {
        columns.push("content_hash");
        values.push(record.contentHash);
      }
      const updates = columns
        .filter((c) => c !== "user_id")
        .map((c) => `${quoteIdent(c)} = excluded.${quoteIdent(c)}`)
        .join(", ");
      await getClient().query(
        `INSERT INTO ${quoteIdent(collection)} (${columns.map(quoteIdent).join(", ")}) ` +
          `VALUES (${paramList(1, columns.length)}) ` +
          `ON CONFLICT (user_id) DO UPDATE SET ${updates}`,
        values,
      );
    },

    async getByKey(
      collection,
      userId,
      keyColumn,
      keyValue,
    ): Promise<BlobRecord | null> {
      const { rows } = await getClient().query<{
        schema_version: number | null;
        blob: string;
      }>(
        `SELECT schema_version, blob FROM ${quoteIdent(collection)} ` +
          `WHERE user_id = $1 AND ${quoteIdent(keyColumn)} = $2 LIMIT 1`,
        [userId, keyValue],
      );
      const row = rows[0];
      if (!row) return null;
      return { schemaVersion: row.schema_version ?? 1, blob: row.blob };
    },

    async putByKey(
      collection,
      userId,
      keyColumn,
      keyValue,
      record,
    ): Promise<void> {
      const columns = [
        "user_id",
        keyColumn,
        "blob",
        "schema_version",
        "updated_at",
      ];
      const values: unknown[] = [
        userId,
        keyValue,
        record.blob,
        record.schemaVersion,
        new Date().toISOString(),
      ];
      if (record.contentHash !== undefined) {
        columns.push("content_hash");
        values.push(record.contentHash);
      }
      const updates = columns
        .filter((c) => c !== "user_id" && c !== keyColumn)
        .map((c) => `${quoteIdent(c)} = excluded.${quoteIdent(c)}`)
        .join(", ");
      await getClient().query(
        `INSERT INTO ${quoteIdent(collection)} (${columns.map(quoteIdent).join(", ")}) ` +
          `VALUES (${paramList(1, columns.length)}) ` +
          `ON CONFLICT (user_id, ${quoteIdent(keyColumn)}) DO UPDATE SET ${updates}`,
        values,
      );
    },

    async listByKeyRange(
      collection,
      userId,
      keyColumn,
      from,
      to,
    ): Promise<Array<{ key: string; record: BlobRecord }>> {
      const { rows } = await getClient().query<{
        [k: string]: unknown;
        schema_version: number | null;
        blob: string;
      }>(
        `SELECT ${quoteIdent(keyColumn)}, schema_version, blob FROM ${quoteIdent(collection)} ` +
          `WHERE user_id = $1 AND ${quoteIdent(keyColumn)} >= $2 AND ${quoteIdent(keyColumn)} <= $3 ` +
          `ORDER BY ${quoteIdent(keyColumn)}`,
        [userId, from, to],
      );
      return rows.map((row) => ({
        key: row[keyColumn] as string,
        record: { schemaVersion: row.schema_version ?? 1, blob: row.blob },
      }));
    },

    async list(
      collection,
      userId,
      plainColumns,
    ): Promise<
      Array<{ id: string; record: BlobRecord; plain: Record<string, unknown> }>
    > {
      const columns = ["id", "schema_version", "blob", ...plainColumns];
      const { rows } = await getClient().query<Record<string, unknown>>(
        `SELECT ${columns.map(quoteIdent).join(", ")} FROM ${quoteIdent(collection)} WHERE user_id = $1`,
        [userId],
      );
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
      const plainCols = Object.keys(plain);
      const columns = ["id", "user_id", "blob", "schema_version", ...plainCols];
      const values: unknown[] = [id, userId, record.blob, record.schemaVersion];
      if (record.contentHash !== undefined) {
        columns.splice(4, 0, "content_hash");
        values.push(record.contentHash);
      }
      for (const col of plainCols) values.push(plain[col]);
      await getClient().query(
        `INSERT INTO ${quoteIdent(collection)} (${columns.map(quoteIdent).join(", ")}) ` +
          `VALUES (${paramList(1, columns.length)})`,
        values,
      );
    },

    async updateById(collection, userId, id, record, plain): Promise<void> {
      const plainCols = Object.keys(plain);
      const setColumns = ["blob", "schema_version", "updated_at", ...plainCols];
      const values: unknown[] = [
        record.blob,
        record.schemaVersion,
        new Date().toISOString(),
      ];
      if (record.contentHash !== undefined) {
        setColumns.splice(3, 0, "content_hash");
        values.push(record.contentHash);
      }
      for (const col of plainCols) values.push(plain[col]);
      const setClause = setColumns
        .map((c, i) => `${quoteIdent(c)} = $${i + 1}`)
        .join(", ");
      const userIdParam = values.length + 1;
      const idParam = values.length + 2;
      values.push(userId, id);
      await getClient().query(
        `UPDATE ${quoteIdent(collection)} SET ${setClause} ` +
          `WHERE user_id = $${userIdParam} AND id = $${idParam}`,
        values,
      );
    },

    async deleteById(collection, userId, id): Promise<void> {
      await getClient().query(
        `DELETE FROM ${quoteIdent(collection)} WHERE user_id = $1 AND id = $2`,
        [userId, id],
      );
    },
  };
}
