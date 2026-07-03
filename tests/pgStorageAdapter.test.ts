/**
 * Verifies the SQL/params pgStorageAdapter builds — no real Postgres needed. A fake
 * `PgClient` records every call; assertions check the query shape and bound params,
 * not a live database. Live correctness is validated by the consuming app's own
 * integration/E2E suite against a real Postgres (same as supabaseStorageAdapter,
 * which has no unit test of its own — only E2E coverage through the app).
 */
import assert from "node:assert/strict";
import test from "node:test";
import {
  pgStorageAdapter,
  type PgClient,
} from "../adapters/pgStorageAdapter.ts";
import type { BlobRecord } from "../core/types.ts";

function fakeClient(rows: Record<string, unknown>[] = []) {
  const calls: Array<{ text: string; params: unknown[] }> = [];
  const client: PgClient = {
    async query<T extends Record<string, unknown>>(
      text: string,
      params: unknown[] = [],
    ) {
      calls.push({ text, params });
      return { rows: rows as T[] };
    },
  };
  return { client, calls };
}

test("pgStorageAdapter.getOne: selects by user_id, returns null on empty result", async () => {
  const { client, calls } = fakeClient([]);
  const adapter = pgStorageAdapter(() => client);

  const result = await adapter.getOne("portfolio_blobs", "u1");

  assert.equal(result, null);
  assert.match(
    calls[0].text,
    /SELECT schema_version, blob FROM "portfolio_blobs" WHERE user_id = \$1/,
  );
  assert.deepEqual(calls[0].params, ["u1"]);
});

test("pgStorageAdapter.getOne: maps a found row", async () => {
  const { client } = fakeClient([{ schema_version: 2, blob: "enc:x" }]);
  const adapter = pgStorageAdapter(() => client);

  const result = await adapter.getOne("portfolio_blobs", "u1");

  assert.deepEqual(result, { schemaVersion: 2, blob: "enc:x" });
});

test("pgStorageAdapter.putOne: upserts on user_id, includes content_hash only when present", async () => {
  const { client, calls } = fakeClient();
  const adapter = pgStorageAdapter(() => client);
  const record: BlobRecord = {
    schemaVersion: 1,
    blob: "enc:y",
    contentHash: "abc",
  };

  await adapter.putOne("portfolio_blobs", "u1", record);

  const { text, params } = calls[0];
  assert.match(text, /INSERT INTO "portfolio_blobs"/);
  assert.match(text, /ON CONFLICT \(user_id\) DO UPDATE SET/);
  assert.match(text, /"content_hash" = excluded\."content_hash"/);
  assert.deepEqual(params, ["u1", "enc:y", 1, params[3], "abc"]);
});

test("pgStorageAdapter.putOne: omits content_hash entirely when not provided", async () => {
  const { client, calls } = fakeClient();
  const adapter = pgStorageAdapter(() => client);

  await adapter.putOne("portfolio_blobs", "u1", {
    schemaVersion: 1,
    blob: "enc:y",
  });

  assert.equal(calls[0].params.length, 4);
  assert.ok(!calls[0].text.includes("content_hash"));
});

test("pgStorageAdapter.getByKey / putByKey: quote the dynamic key column, upsert on (user_id, key)", async () => {
  const { client, calls } = fakeClient();
  const adapter = pgStorageAdapter(() => client);

  await adapter.getByKey!("transaction_blobs", "u1", "year_month", "2026-07");
  assert.match(calls[0].text, /AND "year_month" = \$2/);
  assert.deepEqual(calls[0].params, ["u1", "2026-07"]);

  await adapter.putByKey!("transaction_blobs", "u1", "year_month", "2026-07", {
    schemaVersion: 1,
    blob: "enc:z",
  });
  assert.match(
    calls[1].text,
    /ON CONFLICT \(user_id, "year_month"\) DO UPDATE SET/,
  );
  assert.deepEqual(calls[1].params.slice(0, 2), ["u1", "2026-07"]);
});

test("pgStorageAdapter.listByKeyRange: quotes the key column, binds from/to, orders by key", async () => {
  const { client, calls } = fakeClient([
    { year_month: "2026-06", schema_version: 1, blob: "enc:a" },
    { year_month: "2026-07", schema_version: 1, blob: "enc:b" },
  ]);
  const adapter = pgStorageAdapter(() => client);

  const rows = await adapter.listByKeyRange!(
    "transaction_blobs",
    "u1",
    "year_month",
    "2026-06",
    "2026-07",
  );

  assert.match(
    calls[0].text,
    /SELECT "year_month", schema_version, blob FROM "transaction_blobs" WHERE user_id = \$1 AND "year_month" >= \$2 AND "year_month" <= \$3 ORDER BY "year_month"/,
  );
  assert.deepEqual(calls[0].params, ["u1", "2026-06", "2026-07"]);
  assert.deepEqual(rows, [
    { key: "2026-06", record: { schemaVersion: 1, blob: "enc:a" } },
    { key: "2026-07", record: { schemaVersion: 1, blob: "enc:b" } },
  ]);
});

test("pgStorageAdapter.list: selects id/schema_version/blob plus the given plain columns", async () => {
  const { client, calls } = fakeClient([
    {
      id: "row-1",
      schema_version: 1,
      blob: "enc:a",
      portfolio_id: "pf-1",
      status: "draft",
    },
  ]);
  const adapter = pgStorageAdapter(() => client);

  const rows = await adapter.list!("rebalance_simulations", "u1", [
    "portfolio_id",
    "status",
  ]);

  assert.match(
    calls[0].text,
    /SELECT "id", "schema_version", "blob", "portfolio_id", "status" FROM "rebalance_simulations" WHERE user_id = \$1/,
  );
  assert.deepEqual(rows, [
    {
      id: "row-1",
      record: { schemaVersion: 1, blob: "enc:a" },
      plain: { portfolio_id: "pf-1", status: "draft" },
    },
  ]);
});

test("pgStorageAdapter.insert: binds id/user_id/blob/schema_version plus plain columns", async () => {
  const { client, calls } = fakeClient();
  const adapter = pgStorageAdapter(() => client);

  await adapter.insert!(
    "rebalance_simulations",
    "u1",
    "row-1",
    { schemaVersion: 1, blob: "enc:a" },
    {
      portfolio_id: "pf-1",
      status: "draft",
    },
  );

  assert.match(
    calls[0].text,
    /INSERT INTO "rebalance_simulations" \("id", "user_id", "blob", "schema_version", "portfolio_id", "status"\)/,
  );
  assert.deepEqual(calls[0].params, [
    "row-1",
    "u1",
    "enc:a",
    1,
    "pf-1",
    "draft",
  ]);
});

test("pgStorageAdapter.updateById: scopes the WHERE to user_id + id, updates plain columns too", async () => {
  const { client, calls } = fakeClient();
  const adapter = pgStorageAdapter(() => client);

  await adapter.updateById!(
    "rebalance_simulations",
    "u1",
    "row-1",
    { schemaVersion: 1, blob: "enc:b" },
    { portfolio_id: "pf-1", status: "executed" },
  );

  const { text, params } = calls[0];
  assert.match(text, /WHERE user_id = \$\d+ AND id = \$\d+/);
  // last two bound params must be userId then id, matching the WHERE clause order
  assert.deepEqual(params.slice(-2), ["u1", "row-1"]);
  assert.ok(params.includes("pf-1") && params.includes("executed"));
});

test("pgStorageAdapter.deleteById: scopes to user_id + id", async () => {
  const { client, calls } = fakeClient();
  const adapter = pgStorageAdapter(() => client);

  await adapter.deleteById!("rebalance_simulations", "u1", "row-1");

  assert.match(
    calls[0].text,
    /DELETE FROM "rebalance_simulations" WHERE user_id = \$1 AND id = \$2/,
  );
  assert.deepEqual(calls[0].params, ["u1", "row-1"]);
});

test("pgStorageAdapter: quotes identifiers defensively (embedded double quote doesn't break the query)", async () => {
  const { client, calls } = fakeClient([]);
  const adapter = pgStorageAdapter(() => client);

  await adapter.getOne('weird"table', "u1");

  assert.match(calls[0].text, /FROM "weird""table"/);
});
