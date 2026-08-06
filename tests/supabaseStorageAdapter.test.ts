/**
 * Verifies supabaseStorageAdapter's read methods (get/listByKeyRange/list) actually
 * select and map `content_hash` — the exact gap that shipped silently until
 * `optimisticLock: true` was first used against a real Supabase backend
 * (previously "no unit test of its own — only E2E coverage through the app", per
 * pgStorageAdapter.test.ts's header comment). Without content_hash in the SELECT,
 * `mutate()`'s conflict check always reads `hash: null`, so `saveIfMatch` compares
 * against `null` even when the row has a real hash — every write after the first
 * throws `OptimisticLockConflictError`, even with zero concurrent writers
 * (reproduced empirically against local Supabase before this fix).
 */
import assert from "node:assert/strict";
import test from "node:test";
import { supabaseStorageAdapter } from "../adapters/storage/supabaseStorageAdapter.ts";

type Row = Record<string, unknown>;

/** Minimal fake mirroring the chain shape supabaseStorageAdapter actually calls. */
function fakeSupabase(rows: Row[] | Row | null) {
  const calls: Array<{ collection: string; columns: string }> = [];
  const inCalls: Array<{ column: string; values: unknown[] }> = [];
  const builder = {
    _collection: "",
    _columns: "",
    select(columns: string) {
      this._columns = columns;
      calls.push({ collection: this._collection, columns });
      return this;
    },
    eq() {
      return this;
    },
    gte() {
      return this;
    },
    lte() {
      return this;
    },
    in(column: string, values: unknown[]) {
      inCalls.push({ column, values });
      return this;
    },
    order() {
      return this;
    },
    async maybeSingle() {
      return { data: rows as Row | null, error: null };
    },
    then(resolve: (v: { data: Row[] | null; error: null }) => unknown) {
      return resolve({ data: rows as Row[] | null, error: null });
    },
  };
  const client = {
    from(collection: string) {
      builder._collection = collection;
      return builder;
    },
  };
  return { client, calls, inCalls };
}

test("supabaseStorageAdapter.get: selects content_hash and maps it", async () => {
  const { client, calls } = fakeSupabase({
    schema_version: 1,
    blob: "enc:x",
    content_hash: "h1",
  });
  const adapter = supabaseStorageAdapter(() => client as never);

  const result = await adapter.get("portfolio_blobs", "u1", []);

  assert.match(calls[0].columns, /content_hash/);
  assert.deepEqual(result, {
    schemaVersion: 1,
    blob: "enc:x",
    contentHash: "h1",
  });
});

test("supabaseStorageAdapter.get: null content_hash on a legacy row (never hashed)", async () => {
  const { client } = fakeSupabase({
    schema_version: 1,
    blob: "enc:x",
    content_hash: null,
  });
  const adapter = supabaseStorageAdapter(() => client as never);

  const result = await adapter.get("portfolio_blobs", "u1", []);

  assert.deepEqual(result, {
    schemaVersion: 1,
    blob: "enc:x",
    contentHash: null,
  });
});

test("supabaseStorageAdapter.listByKeyRange: selects content_hash and maps it per row", async () => {
  const { client, calls } = fakeSupabase([
    {
      year_month: "2026-06",
      schema_version: 1,
      blob: "enc:a",
      content_hash: "ha",
    },
    {
      year_month: "2026-07",
      schema_version: 1,
      blob: "enc:b",
      content_hash: "hb",
    },
  ]);
  const adapter = supabaseStorageAdapter(() => client as never);

  const rows = await adapter.listByKeyRange!(
    "transaction_blobs",
    "u1",
    "year_month",
    "2026-06",
    "2026-07",
  );

  assert.match(calls[0].columns, /content_hash/);
  assert.deepEqual(rows, [
    {
      key: "2026-06",
      record: { schemaVersion: 1, blob: "enc:a", contentHash: "ha" },
    },
    {
      key: "2026-07",
      record: { schemaVersion: 1, blob: "enc:b", contentHash: "hb" },
    },
  ]);
});

test("supabaseStorageAdapter.listAll: selects content_hash and maps every row for the user, no range filter", async () => {
  const { client, calls } = fakeSupabase([
    {
      year_month: "2024-01",
      schema_version: 1,
      blob: "enc:a",
      content_hash: "ha",
    },
    {
      year_month: "2026-07",
      schema_version: 1,
      blob: "enc:b",
      content_hash: "hb",
    },
  ]);
  const adapter = supabaseStorageAdapter(() => client as never);

  const rows = await adapter.listAll!("transaction_blobs", "u1", "year_month");

  assert.match(calls[0].columns, /content_hash/);
  assert.deepEqual(rows, [
    {
      key: "2024-01",
      record: { schemaVersion: 1, blob: "enc:a", contentHash: "ha" },
    },
    {
      key: "2026-07",
      record: { schemaVersion: 1, blob: "enc:b", contentHash: "hb" },
    },
  ]);
});

test("supabaseStorageAdapter.getHashesByKeys: selects content_hash for the given key column with .in(), maps every requested key", async () => {
  const { client, calls, inCalls } = fakeSupabase([
    { year_month: "__dashboard__", content_hash: "hash-a" },
    { year_month: "__net_worth_series__", content_hash: "hash-b" },
  ]);
  const adapter = supabaseStorageAdapter(() => client as never);

  const result = await adapter.getHashesByKeys!(
    "account_snapshot_blobs",
    "u1",
    "year_month",
    ["__dashboard__", "__net_worth_series__", "__portfolio_series__"],
  );

  assert.match(calls[0].columns, /year_month, content_hash/);
  assert.deepEqual(inCalls[0], {
    column: "year_month",
    values: ["__dashboard__", "__net_worth_series__", "__portfolio_series__"],
  });
  // Every requested key gets an entry — "__portfolio_series__" wasn't in the
  // fake result set, so it must come back null, never omitted.
  assert.deepEqual(result, {
    __dashboard__: "hash-a",
    __net_worth_series__: "hash-b",
    __portfolio_series__: null,
  });
});

test("supabaseStorageAdapter.getHashesByKeys: empty keys array is a no-op (no client call)", async () => {
  const { client, calls } = fakeSupabase([]);
  const adapter = supabaseStorageAdapter(() => client as never);

  const result = await adapter.getHashesByKeys!(
    "account_snapshot_blobs",
    "u1",
    "year_month",
    [],
  );

  assert.deepEqual(result, {});
  assert.equal(calls.length, 0);
});

test("supabaseStorageAdapter.list: selects content_hash and maps it alongside plain columns", async () => {
  const { client, calls } = fakeSupabase([
    {
      id: "row-1",
      schema_version: 1,
      blob: "enc:a",
      content_hash: "h1",
      portfolio_id: "pf-1",
      status: "draft",
    },
  ]);
  const adapter = supabaseStorageAdapter(() => client as never);

  const rows = await adapter.list!("rebalance_simulations", "u1", [
    "portfolio_id",
    "status",
  ]);

  assert.match(calls[0].columns, /content_hash/);
  assert.deepEqual(rows, [
    {
      id: "row-1",
      record: { schemaVersion: 1, blob: "enc:a", contentHash: "h1" },
      plain: { portfolio_id: "pf-1", status: "draft" },
    },
  ]);
});

test("supabaseStorageAdapter.insertMany: a single .insert() call with one row per entry, no upsert", async () => {
  const inserted: Array<{ collection: string; rows: Row[] }> = [];
  const client = {
    from(collection: string) {
      return {
        async insert(rows: Row[]) {
          inserted.push({ collection, rows });
          return { error: null };
        },
      };
    },
  };
  const adapter = supabaseStorageAdapter(() => client as never);

  await adapter.insertMany!("transaction_blobs", "u1", [
    {
      extraKeys: [{ column: "year_month", value: "2026-06" }],
      record: { schemaVersion: 1, blob: "enc:june", contentHash: "h1" },
    },
    {
      extraKeys: [{ column: "year_month", value: "2026-07" }],
      record: { schemaVersion: 1, blob: "enc:july", contentHash: "h2" },
    },
  ]);

  assert.equal(inserted.length, 1);
  assert.equal(inserted[0].collection, "transaction_blobs");
  assert.deepEqual(
    inserted[0].rows.map((r) => r.year_month),
    ["2026-06", "2026-07"],
  );
  assert.deepEqual(
    inserted[0].rows.map((r) => r.blob),
    ["enc:june", "enc:july"],
  );
});

test("supabaseStorageAdapter.insertMany: surfaces a duplicate-key error instead of upserting", async () => {
  const client = {
    from() {
      return {
        async insert() {
          return {
            error: {
              message: "duplicate key value violates unique constraint",
            },
          };
        },
      };
    },
  };
  const adapter = supabaseStorageAdapter(() => client as never);

  await assert.rejects(
    () =>
      adapter.insertMany!("transaction_blobs", "u1", [
        {
          extraKeys: [{ column: "year_month", value: "2026-06" }],
          record: { schemaVersion: 1, blob: "enc:x" },
        },
      ]),
    /duplicate key/,
  );
});

test("supabaseStorageAdapter.insertMany: empty array is a no-op (no client call)", async () => {
  let called = false;
  const client = {
    from() {
      called = true;
      return { async insert() {} };
    },
  };
  const adapter = supabaseStorageAdapter(() => client as never);

  await adapter.insertMany!("transaction_blobs", "u1", []);

  assert.equal(called, false);
});
