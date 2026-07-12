/**
 * Verifies the SQL/params pgStorageAdapter builds — no real Postgres needed. A fake
 * `PgClient` records every call; assertions check the query shape and bound params,
 * not a live database. Live correctness is validated by the consuming app's own
 * integration/E2E suite against a real Postgres. See supabaseStorageAdapter.test.ts
 * for the equivalent coverage on the other shipped adapter.
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

test("pgStorageAdapter.get: selects by user_id, returns null on empty result", async () => {
  const { client, calls } = fakeClient([]);
  const adapter = pgStorageAdapter(() => client);

  const result = await adapter.get("portfolio_blobs", "u1", []);

  assert.equal(result, null);
  assert.match(
    calls[0].text,
    /SELECT schema_version, blob, content_hash FROM "portfolio_blobs" WHERE user_id = \$1/,
  );
  assert.deepEqual(calls[0].params, ["u1"]);
});

test("pgStorageAdapter.get: maps a found row", async () => {
  const { client } = fakeClient([{ schema_version: 2, blob: "enc:x" }]);
  const adapter = pgStorageAdapter(() => client);

  const result = await adapter.get("portfolio_blobs", "u1", []);

  assert.deepEqual(result, {
    schemaVersion: 2,
    blob: "enc:x",
    contentHash: null,
  });
});

// REGRESSIONE: get() non selezionava content_hash — mutate()/saveIfMatch usava
// sempre hash:null anche su una riga con un hash reale, facendo fallire ogni
// scrittura successiva con OptimisticLockConflictError anche senza un vero
// secondo scrittore (riprodotto empiricamente contro Supabase locale).
test("pgStorageAdapter.get: maps content_hash when present", async () => {
  const { client } = fakeClient([
    { schema_version: 2, blob: "enc:x", content_hash: "h1" },
  ]);
  const adapter = pgStorageAdapter(() => client);

  const result = await adapter.get("portfolio_blobs", "u1", []);

  assert.deepEqual(result, {
    schemaVersion: 2,
    blob: "enc:x",
    contentHash: "h1",
  });
});

test("pgStorageAdapter.put: upserts on user_id, includes content_hash only when present", async () => {
  const { client, calls } = fakeClient();
  const adapter = pgStorageAdapter(() => client);
  const record: BlobRecord = {
    schemaVersion: 1,
    blob: "enc:y",
    contentHash: "abc",
  };

  await adapter.put("portfolio_blobs", "u1", [], record);

  const { text, params } = calls[0];
  assert.match(text, /INSERT INTO "portfolio_blobs"/);
  assert.match(text, /ON CONFLICT \(user_id\) DO UPDATE SET/);
  assert.match(text, /"content_hash" = excluded\."content_hash"/);
  assert.deepEqual(params, ["u1", "enc:y", 1, params[3], "abc"]);
});

test("pgStorageAdapter.put: omits content_hash entirely when not provided", async () => {
  const { client, calls } = fakeClient();
  const adapter = pgStorageAdapter(() => client);

  await adapter.put("portfolio_blobs", "u1", [], {
    schemaVersion: 1,
    blob: "enc:y",
  });

  assert.equal(calls[0].params.length, 4);
  assert.ok(!calls[0].text.includes("content_hash"));
});

test("pgStorageAdapter.get / put with extraKeys: quote the dynamic key column, upsert on (user_id, key)", async () => {
  const { client, calls } = fakeClient();
  const adapter = pgStorageAdapter(() => client);

  await adapter.get("transaction_blobs", "u1", [
    { column: "year_month", value: "2026-07" },
  ]);
  assert.match(calls[0].text, /AND "year_month" = \$2/);
  assert.deepEqual(calls[0].params, ["u1", "2026-07"]);

  await adapter.put(
    "transaction_blobs",
    "u1",
    [{ column: "year_month", value: "2026-07" }],
    { schemaVersion: 1, blob: "enc:z" },
  );
  assert.match(
    calls[1].text,
    /ON CONFLICT \(user_id, "year_month"\) DO UPDATE SET/,
  );
  assert.deepEqual(calls[1].params.slice(0, 2), ["u1", "2026-07"]);
});

test("pgStorageAdapter.insertMany: a single plain INSERT (no ON CONFLICT) with one VALUES tuple per entry", async () => {
  const { client, calls } = fakeClient();
  const adapter = pgStorageAdapter(() => client);

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

  assert.equal(calls.length, 1);
  const { text, params } = calls[0];
  assert.match(text, /INSERT INTO "transaction_blobs"/);
  assert.ok(!text.includes("ON CONFLICT"));
  // Two VALUES tuples, one per entry.
  assert.equal((text.match(/\(\$/g) ?? []).length, 2);
  assert.deepEqual(
    params.filter((p) => typeof p === "string" && p.startsWith("enc:")),
    ["enc:june", "enc:july"],
  );
  assert.deepEqual(
    params.filter((p) => p === "2026-06" || p === "2026-07"),
    ["2026-06", "2026-07"],
  );
});

test("pgStorageAdapter.insertMany: a duplicate key surfaces as a rejected unique-constraint violation, not silently overwritten", async () => {
  const client: PgClient = {
    async query() {
      throw new Error(
        'duplicate key value violates unique constraint "transaction_blobs_pkey"',
      );
    },
  };
  const adapter = pgStorageAdapter(() => client);

  await assert.rejects(
    () =>
      adapter.insertMany!("transaction_blobs", "u1", [
        {
          extraKeys: [{ column: "year_month", value: "2026-06" }],
          record: { schemaVersion: 1, blob: "enc:june" },
        },
      ]),
    /unique constraint/,
  );
});

test("pgStorageAdapter.insertMany: empty array is a no-op (no query issued)", async () => {
  const { client, calls } = fakeClient();
  const adapter = pgStorageAdapter(() => client);

  await adapter.insertMany!("transaction_blobs", "u1", []);

  assert.equal(calls.length, 0);
});

test("pgStorageAdapter.getHashesByKeys: quotes the key column, binds userId + key array via = ANY($2)", async () => {
  const { client, calls } = fakeClient([
    { year_month: "__dashboard__", content_hash: "hash-a" },
    { year_month: "__net_worth_series__", content_hash: "hash-b" },
  ]);
  const adapter = pgStorageAdapter(() => client);

  const result = await adapter.getHashesByKeys!(
    "account_snapshot_blobs",
    "u1",
    "year_month",
    ["__dashboard__", "__net_worth_series__", "__portfolio_series__"],
  );

  assert.match(
    calls[0].text,
    /SELECT "year_month", content_hash FROM "account_snapshot_blobs" WHERE user_id = \$1 AND "year_month" = ANY\(\$2\)/,
  );
  assert.deepEqual(calls[0].params, [
    "u1",
    ["__dashboard__", "__net_worth_series__", "__portfolio_series__"],
  ]);
  // Every requested key gets an entry — "__portfolio_series__" wasn't in the
  // fake result set, so it must come back null, never omitted.
  assert.deepEqual(result, {
    __dashboard__: "hash-a",
    __net_worth_series__: "hash-b",
    __portfolio_series__: null,
  });
});

test("pgStorageAdapter.getHashesByKeys: empty keys array is a no-op (no query issued)", async () => {
  const { client, calls } = fakeClient([]);
  const adapter = pgStorageAdapter(() => client);

  const result = await adapter.getHashesByKeys!(
    "account_snapshot_blobs",
    "u1",
    "year_month",
    [],
  );

  assert.deepEqual(result, {});
  assert.equal(calls.length, 0);
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
    /SELECT "year_month", schema_version, blob, content_hash FROM "transaction_blobs" WHERE user_id = \$1 AND "year_month" >= \$2 AND "year_month" <= \$3 ORDER BY "year_month"/,
  );
  assert.deepEqual(calls[0].params, ["u1", "2026-06", "2026-07"]);
  assert.deepEqual(rows, [
    {
      key: "2026-06",
      record: { schemaVersion: 1, blob: "enc:a", contentHash: null },
    },
    {
      key: "2026-07",
      record: { schemaVersion: 1, blob: "enc:b", contentHash: null },
    },
  ]);
});

test("pgStorageAdapter.listAll: quotes the key column, binds only user_id, no range filter", async () => {
  const { client, calls } = fakeClient([
    { year_month: "2024-01", schema_version: 1, blob: "enc:a" },
    { year_month: "2026-07", schema_version: 1, blob: "enc:b" },
  ]);
  const adapter = pgStorageAdapter(() => client);

  const rows = await adapter.listAll!("transaction_blobs", "u1", "year_month");

  assert.match(
    calls[0].text,
    /SELECT "year_month", schema_version, blob, content_hash FROM "transaction_blobs" WHERE user_id = \$1/,
  );
  assert.deepEqual(calls[0].params, ["u1"]);
  assert.deepEqual(rows, [
    {
      key: "2024-01",
      record: { schemaVersion: 1, blob: "enc:a", contentHash: null },
    },
    {
      key: "2026-07",
      record: { schemaVersion: 1, blob: "enc:b", contentHash: null },
    },
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
    /SELECT "id", "schema_version", "blob", "content_hash", "portfolio_id", "status" FROM "rebalance_simulations" WHERE user_id = \$1/,
  );
  assert.deepEqual(rows, [
    {
      id: "row-1",
      record: { schemaVersion: 1, blob: "enc:a", contentHash: null },
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

  await adapter.get('weird"table', "u1", []);

  assert.match(calls[0].text, /FROM "weird""table"/);
});

test("pgStorageAdapter.putIfMatch: expectedHash null → conditional upsert, succeeds when no row exists yet or the existing row has no hash (legacy)", async () => {
  const { client, calls } = fakeClient([{ user_id: "u1" }]); // RETURNING matched a row
  const adapter = pgStorageAdapter(() => client);

  const ok = await adapter.putIfMatch!(
    "portfolio_blobs",
    "u1",
    [],
    { schemaVersion: 1, blob: "enc:y", contentHash: "h1" },
    null,
  );

  assert.equal(ok, true);
  assert.match(calls[0].text, /INSERT INTO "portfolio_blobs"/);
  assert.match(calls[0].text, /ON CONFLICT \(user_id\) DO UPDATE SET/);
  assert.match(
    calls[0].text,
    /WHERE "portfolio_blobs"\."content_hash" IS NULL/,
  );
  assert.match(calls[0].text, /RETURNING user_id/);
  assert.deepEqual(calls[0].params, [
    "u1",
    "enc:y",
    1,
    params0Timestamp(calls),
    "h1",
  ]);
});

test("pgStorageAdapter.putIfMatch: expectedHash null → conflict (false, not thrown) when the existing row already has a real hash", async () => {
  const { client } = fakeClient([]); // WHERE content_hash IS NULL excluded the row → 0 rows RETURNING
  const adapter = pgStorageAdapter(() => client);

  const ok = await adapter.putIfMatch!(
    "portfolio_blobs",
    "u1",
    [],
    { schemaVersion: 1, blob: "enc:y", contentHash: "h2" },
    null,
  );

  assert.equal(ok, false);
});

test("pgStorageAdapter.putIfMatch: expectedHash null + a genuine different error → rethrown", async () => {
  const client: PgClient = {
    async query() {
      const err = new Error("syntax error");
      (err as Error & { code: string }).code = "42601";
      throw err;
    },
  };
  const adapter = pgStorageAdapter(() => client);

  await assert.rejects(
    () =>
      adapter.putIfMatch!(
        "portfolio_blobs",
        "u1",
        [],
        { schemaVersion: 1, blob: "enc:y" },
        null,
      ),
    /syntax error/,
  );
});

test("pgStorageAdapter.putIfMatch: expectedHash non-null → conditional UPDATE, true when a row matches", async () => {
  const { client, calls } = fakeClient([{ user_id: "u1" }]);
  const adapter = pgStorageAdapter(() => client);

  const ok = await adapter.putIfMatch!(
    "portfolio_blobs",
    "u1",
    [],
    { schemaVersion: 1, blob: "enc:y2", contentHash: "h2" },
    "h1",
  );

  assert.equal(ok, true);
  assert.match(calls[0].text, /UPDATE "portfolio_blobs" SET/);
  assert.match(calls[0].text, /WHERE user_id = \$\d+ AND content_hash = \$\d+/);
  assert.match(calls[0].text, /RETURNING/);
  assert.ok(calls[0].params.includes("h1"));
});

test("pgStorageAdapter.putIfMatch: expectedHash non-null → false (no throw) when zero rows match", async () => {
  const { client } = fakeClient([]); // UPDATE ... RETURNING matched nothing
  const adapter = pgStorageAdapter(() => client);

  const ok = await adapter.putIfMatch!(
    "portfolio_blobs",
    "u1",
    [],
    { schemaVersion: 1, blob: "enc:y2" },
    "stale-hash",
  );

  assert.equal(ok, false);
});

test("pgStorageAdapter.putIfMatch: with an extra key (perKey), scopes both the INSERT and the UPDATE WHERE", async () => {
  const { client: insertClient, calls: insertCalls } = fakeClient();
  const insertAdapter = pgStorageAdapter(() => insertClient);
  await insertAdapter.putIfMatch!(
    "transaction_blobs",
    "u1",
    [{ column: "year_month", value: "2026-07" }],
    { schemaVersion: 1, blob: "enc:z" },
    null,
  );
  assert.match(
    insertCalls[0].text,
    /INSERT INTO "transaction_blobs" \("user_id", "year_month", "blob"/,
  );
  assert.deepEqual(insertCalls[0].params.slice(0, 2), ["u1", "2026-07"]);

  const { client: updateClient, calls: updateCalls } = fakeClient([
    { user_id: "u1" },
  ]);
  const updateAdapter = pgStorageAdapter(() => updateClient);
  await updateAdapter.putIfMatch!(
    "transaction_blobs",
    "u1",
    [{ column: "year_month", value: "2026-07" }],
    { schemaVersion: 1, blob: "enc:z2" },
    "h1",
  );
  assert.match(
    updateCalls[0].text,
    /WHERE user_id = \$\d+ AND "year_month" = \$\d+ AND content_hash = \$\d+/,
  );
});

test("pgStorageAdapter.updateByIdIfMatch: expectedHash null → conditional upsert with the given id, succeeds when absent or legacy (no hash)", async () => {
  const { client, calls } = fakeClient([{ id: "row-1" }]); // RETURNING matched a row
  const adapter = pgStorageAdapter(() => client);

  const ok = await adapter.updateByIdIfMatch!(
    "rebalance_simulations",
    "u1",
    "row-1",
    { schemaVersion: 1, blob: "enc:a", contentHash: "h1" },
    { portfolio_id: "pf-1" },
    null,
  );

  assert.equal(ok, true);
  assert.match(
    calls[0].text,
    /INSERT INTO "rebalance_simulations" \("id", "user_id"/,
  );
  assert.match(calls[0].text, /ON CONFLICT \(id\) DO UPDATE SET/);
  assert.match(
    calls[0].text,
    /WHERE "rebalance_simulations"\."content_hash" IS NULL/,
  );
  assert.match(calls[0].text, /RETURNING id/);
  assert.deepEqual(calls[0].params.slice(0, 2), ["row-1", "u1"]);
});

test("pgStorageAdapter.updateByIdIfMatch: expectedHash null → conflict (false, not thrown) when the existing row already has a real hash", async () => {
  const { client } = fakeClient([]); // WHERE content_hash IS NULL excluded the row → 0 rows RETURNING
  const adapter = pgStorageAdapter(() => client);

  const ok = await adapter.updateByIdIfMatch!(
    "rebalance_simulations",
    "u1",
    "row-1",
    { schemaVersion: 1, blob: "enc:a" },
    {},
    null,
  );

  assert.equal(ok, false);
});

test("pgStorageAdapter.updateByIdIfMatch: conditional UPDATE scoped to user_id + id + content_hash", async () => {
  const { client, calls } = fakeClient([{ id: "row-1" }]);
  const adapter = pgStorageAdapter(() => client);

  const ok = await adapter.updateByIdIfMatch!(
    "rebalance_simulations",
    "u1",
    "row-1",
    { schemaVersion: 1, blob: "enc:b", contentHash: "h2" },
    { portfolio_id: "pf-1", status: "executed" },
    "h1",
  );

  assert.equal(ok, true);
  assert.match(calls[0].text, /UPDATE "rebalance_simulations" SET/);
  assert.match(
    calls[0].text,
    /WHERE user_id = \$\d+ AND id = \$\d+ AND content_hash = \$\d+/,
  );
  assert.ok(calls[0].params.includes("h1"));
});

test("pgStorageAdapter.updateByIdIfMatch: false (no throw) when zero rows match (stale hash or wrong id)", async () => {
  const { client } = fakeClient([]);
  const adapter = pgStorageAdapter(() => client);

  const ok = await adapter.updateByIdIfMatch!(
    "rebalance_simulations",
    "u1",
    "row-1",
    { schemaVersion: 1, blob: "enc:b" },
    { portfolio_id: "pf-1" },
    "stale-hash",
  );

  assert.equal(ok, false);
});

test("pgStorageAdapter.getHash: selects content_hash by user_id, returns the value when present", async () => {
  const { client, calls } = fakeClient([{ content_hash: "h1" }]);
  const adapter = pgStorageAdapter(() => client);

  const hash = await adapter.getHash!("portfolio_blobs", "u1", []);

  assert.equal(hash, "h1");
  assert.match(
    calls[0].text,
    /SELECT content_hash FROM "portfolio_blobs" WHERE user_id = \$1/,
  );
  assert.deepEqual(calls[0].params, ["u1"]);
});

test("pgStorageAdapter.getHash: returns null when no row matches", async () => {
  const { client } = fakeClient([]);
  const adapter = pgStorageAdapter(() => client);

  const hash = await adapter.getHash!("portfolio_blobs", "u1", []);

  assert.equal(hash, null);
});

test("pgStorageAdapter.getHash: returns null when the row's content_hash column is null", async () => {
  const { client } = fakeClient([{ content_hash: null }]);
  const adapter = pgStorageAdapter(() => client);

  const hash = await adapter.getHash!("portfolio_blobs", "u1", []);

  assert.equal(hash, null);
});

test("pgStorageAdapter.getHash: with an extra key (perKey), scopes the WHERE to it too", async () => {
  const { client, calls } = fakeClient([{ content_hash: "h1" }]);
  const adapter = pgStorageAdapter(() => client);

  await adapter.getHash!("transaction_blobs", "u1", [
    { column: "year_month", value: "2026-07" },
  ]);

  assert.match(calls[0].text, /AND "year_month" = \$2/);
  assert.deepEqual(calls[0].params, ["u1", "2026-07"]);
});

function params0Timestamp(calls: Array<{ params: unknown[] }>): unknown {
  return calls[0].params[3];
}
