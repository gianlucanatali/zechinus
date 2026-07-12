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
    async get(collection, userId, extraKeys): Promise<BlobRecord | null> {
      const extra = extraKeys
        .map((k, i) => ` AND ${quoteIdent(k.column)} = $${i + 2}`)
        .join("");
      const { rows } = await getClient().query<{
        content_hash: string | null;
        schema_version: number | null;
        blob: string;
      }>(
        `SELECT schema_version, blob, content_hash FROM ${quoteIdent(collection)} WHERE user_id = $1${extra} LIMIT 1`,
        [userId, ...extraKeys.map((k) => k.value)],
      );
      const row = rows[0];
      if (!row) return null;
      return {
        schemaVersion: row.schema_version ?? 1,
        blob: row.blob,
        contentHash: row.content_hash ?? null,
      };
    },

    async getHash(collection, userId, extraKeys): Promise<string | null> {
      const extra = extraKeys
        .map((k, i) => ` AND ${quoteIdent(k.column)} = $${i + 2}`)
        .join("");
      const { rows } = await getClient().query<{
        content_hash: string | null;
      }>(
        `SELECT content_hash FROM ${quoteIdent(collection)} WHERE user_id = $1${extra} LIMIT 1`,
        [userId, ...extraKeys.map((k) => k.value)],
      );
      return rows[0]?.content_hash ?? null;
    },

    async getHashesByKeys(
      collection,
      userId,
      keyColumn,
      keys,
    ): Promise<Record<string, string | null>> {
      const result: Record<string, string | null> = {};
      for (const k of keys) result[k] = null;
      if (!keys.length) return result;
      const { rows } = await getClient().query<{
        [k: string]: unknown;
        content_hash: string | null;
      }>(
        `SELECT ${quoteIdent(keyColumn)}, content_hash FROM ${quoteIdent(collection)} ` +
          `WHERE user_id = $1 AND ${quoteIdent(keyColumn)} = ANY($2)`,
        [userId, keys],
      );
      for (const row of rows) {
        result[row[keyColumn] as string] = row.content_hash ?? null;
      }
      return result;
    },

    async put(collection, userId, extraKeys, record): Promise<void> {
      const columns = ["user_id", ...extraKeys.map((k) => k.column)];
      const values: unknown[] = [userId, ...extraKeys.map((k) => k.value)];
      columns.push("blob", "schema_version", "updated_at");
      values.push(record.blob, record.schemaVersion, new Date().toISOString());
      if (record.contentHash !== undefined) {
        columns.push("content_hash");
        values.push(record.contentHash);
      }
      const keyColumns = extraKeys.map((k) => k.column);
      const conflictClause = ["user_id", ...keyColumns]
        .map((c, i) => (i === 0 ? c : quoteIdent(c)))
        .join(", ");
      const updates = columns
        .filter((c) => c !== "user_id" && !keyColumns.includes(c))
        .map((c) => `${quoteIdent(c)} = excluded.${quoteIdent(c)}`)
        .join(", ");
      await getClient().query(
        `INSERT INTO ${quoteIdent(collection)} (${columns.map(quoteIdent).join(", ")}) ` +
          `VALUES (${paramList(1, columns.length)}) ` +
          `ON CONFLICT (${conflictClause}) DO UPDATE SET ${updates}`,
        values,
      );
    },

    /**
     * Plain multi-row INSERT — no `ON CONFLICT`, unlike `put` above. A key that
     * already exists surfaces as a unique-constraint violation, failing the
     * whole statement (Postgres inserts are all-or-nothing) rather than
     * silently overwriting it.
     */
    async insertMany(collection, userId, entries): Promise<void> {
      if (!entries.length) return;
      const keyColumns = entries[0].extraKeys.map((k) => k.column);
      const hasContentHash = entries.some(
        ({ record }) => record.contentHash !== undefined,
      );
      const columns = [
        "user_id",
        ...keyColumns,
        "blob",
        "schema_version",
        "updated_at",
        ...(hasContentHash ? ["content_hash"] : []),
      ];

      const values: unknown[] = [];
      const tuples: string[] = [];
      let paramIndex = 1;
      for (const { extraKeys, record } of entries) {
        const rowValues: unknown[] = [
          userId,
          ...extraKeys.map((k) => k.value),
          record.blob,
          record.schemaVersion,
          new Date().toISOString(),
        ];
        if (hasContentHash) rowValues.push(record.contentHash ?? null);
        tuples.push(`(${paramList(paramIndex, rowValues.length)})`);
        values.push(...rowValues);
        paramIndex += rowValues.length;
      }

      await getClient().query(
        `INSERT INTO ${quoteIdent(collection)} (${columns.map(quoteIdent).join(", ")}) VALUES ${tuples.join(", ")}`,
        values,
      );
    },

    /**
     * `expectedHash: null` means "I believe there's no REAL content yet" — either the row
     * doesn't exist, or it exists but was never hashed (legacy data from before
     * `content_hash` existed). Both succeed via a conditional upsert: `ON CONFLICT DO
     * UPDATE ... WHERE content_hash IS NULL` only writes if the pre-existing row (if any)
     * still has no hash — Postgres resolves the race atomically, no separate
     * insert-then-catch round-trip. Zero rows back means a REAL hash was already there
     * (someone else's write beat us to it) → genuine conflict, `false`, never thrown.
     * `expectedHash` set → `UPDATE ... WHERE ... AND content_hash = expected RETURNING` —
     * zero rows back means either the hash didn't match or the row is gone → `false`,
     * same non-throwing contract.
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
        const columns = ["user_id", ...extraKeys.map((k) => k.column)];
        const values: unknown[] = [userId, ...extraKeys.map((k) => k.value)];
        columns.push("blob", "schema_version", "updated_at");
        values.push(
          record.blob,
          record.schemaVersion,
          new Date().toISOString(),
        );
        if (record.contentHash !== undefined) {
          columns.push("content_hash");
          values.push(record.contentHash);
        }
        const keyColumns = extraKeys.map((k) => k.column);
        const conflictClause = ["user_id", ...keyColumns]
          .map((c, i) => (i === 0 ? c : quoteIdent(c)))
          .join(", ");
        const updates = columns
          .filter((c) => c !== "user_id" && !keyColumns.includes(c))
          .map((c) => `${quoteIdent(c)} = excluded.${quoteIdent(c)}`)
          .join(", ");
        const { rows } = await client.query(
          `INSERT INTO ${quoteIdent(collection)} (${columns.map(quoteIdent).join(", ")}) ` +
            `VALUES (${paramList(1, columns.length)}) ` +
            `ON CONFLICT (${conflictClause}) DO UPDATE SET ${updates} ` +
            `WHERE ${quoteIdent(collection)}.${quoteIdent("content_hash")} IS NULL ` +
            `RETURNING user_id`,
          values,
        );
        return rows.length > 0;
      }
      const setColumns = ["blob", "schema_version", "updated_at"];
      const setValues: unknown[] = [
        record.blob,
        record.schemaVersion,
        new Date().toISOString(),
      ];
      if (record.contentHash !== undefined) {
        setColumns.push("content_hash");
        setValues.push(record.contentHash);
      }
      const setClause = setColumns
        .map((c, i) => `${quoteIdent(c)} = $${i + 1}`)
        .join(", ");
      const base = setValues.length;
      const whereParts = [
        `user_id = $${base + 1}`,
        ...extraKeys.map(
          (k, i) => `${quoteIdent(k.column)} = $${base + 2 + i}`,
        ),
        `content_hash = $${base + 2 + extraKeys.length}`,
      ];
      const values = [
        ...setValues,
        userId,
        ...extraKeys.map((k) => k.value),
        expectedHash,
      ];
      const { rows } = await client.query(
        `UPDATE ${quoteIdent(collection)} SET ${setClause} ` +
          `WHERE ${whereParts.join(" AND ")} RETURNING user_id`,
        values,
      );
      return rows.length > 0;
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
        content_hash: string | null;
        schema_version: number | null;
        blob: string;
      }>(
        `SELECT ${quoteIdent(keyColumn)}, schema_version, blob, content_hash FROM ${quoteIdent(collection)} ` +
          `WHERE user_id = $1 AND ${quoteIdent(keyColumn)} >= $2 AND ${quoteIdent(keyColumn)} <= $3 ` +
          `ORDER BY ${quoteIdent(keyColumn)}`,
        [userId, from, to],
      );
      return rows.map((row) => ({
        key: row[keyColumn] as string,
        record: {
          schemaVersion: row.schema_version ?? 1,
          blob: row.blob,
          contentHash: row.content_hash ?? null,
        },
      }));
    },

    async listAll(
      collection,
      userId,
      keyColumn,
    ): Promise<Array<{ key: string; record: BlobRecord }>> {
      const { rows } = await getClient().query<{
        [k: string]: unknown;
        content_hash: string | null;
        schema_version: number | null;
        blob: string;
      }>(
        `SELECT ${quoteIdent(keyColumn)}, schema_version, blob, content_hash FROM ${quoteIdent(collection)} ` +
          `WHERE user_id = $1`,
        [userId],
      );
      return rows.map((row) => ({
        key: row[keyColumn] as string,
        record: {
          schemaVersion: row.schema_version ?? 1,
          blob: row.blob,
          contentHash: row.content_hash ?? null,
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
      const columns = [
        "id",
        "schema_version",
        "blob",
        "content_hash",
        ...plainColumns,
      ];
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
            contentHash: (row.content_hash as string | null) ?? null,
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
      const plainCols = Object.keys(plain);
      if (expectedHash === null) {
        const columns = [
          "id",
          "user_id",
          "blob",
          "schema_version",
          ...plainCols,
        ];
        const values: unknown[] = [
          id,
          userId,
          record.blob,
          record.schemaVersion,
        ];
        if (record.contentHash !== undefined) {
          columns.splice(4, 0, "content_hash");
          values.push(record.contentHash);
        }
        for (const col of plainCols) values.push(plain[col]);
        const updates = columns
          .filter((c) => c !== "id")
          .map((c) => `${quoteIdent(c)} = excluded.${quoteIdent(c)}`)
          .join(", ");
        const { rows } = await client.query(
          `INSERT INTO ${quoteIdent(collection)} (${columns.map(quoteIdent).join(", ")}) ` +
            `VALUES (${paramList(1, columns.length)}) ` +
            `ON CONFLICT (id) DO UPDATE SET ${updates} ` +
            `WHERE ${quoteIdent(collection)}.${quoteIdent("content_hash")} IS NULL ` +
            `RETURNING id`,
          values,
        );
        return rows.length > 0;
      }
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
      const hashParam = values.length + 3;
      values.push(userId, id, expectedHash);
      const { rows } = await client.query(
        `UPDATE ${quoteIdent(collection)} SET ${setClause} ` +
          `WHERE user_id = $${userIdParam} AND id = $${idParam} AND content_hash = $${hashParam} ` +
          `RETURNING id`,
        values,
      );
      return rows.length > 0;
    },

    async deleteById(collection, userId, id): Promise<void> {
      await getClient().query(
        `DELETE FROM ${quoteIdent(collection)} WHERE user_id = $1 AND id = $2`,
        [userId, id],
      );
    },
  };
}
