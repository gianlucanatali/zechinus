/**
 * `onSourceWrite` (Task 6 of the "aggregazioni dichiarative persistite" plan) —
 * the write-REACTION primitive for monthly snapshot rebuilds, exercised against a
 * SELF-CONTAINED toy domain (a "transactions" KeyedStore + a "snapshot" KeyedStore
 * at one sentinel key) that mirrors the real app's `transaction_blobs` /
 * `account_snapshot_blobs` shape closely enough for the scenarios below to be
 * meaningful, without this package depending on `src/` (DataCloak's own tests never
 * import app code — see `testKeyHandle.ts`).
 *
 * Scenarios (CT1-CT4 from the task brief; CT5 — completeness across the app's real
 * 6 ex-call-sites — is covered at the app layer, `tests/transactions/
 * onSourceWriteCoverage.test.ts`, since it needs the REAL `txStore`/`rebuildMonths`):
 *  CT1 — coalescing: two writes to different months inside the debounce window ->
 *        exactly one handler call, carrying both months.
 *  CT2 — single-flight: a write arriving while the handler is still running never
 *        starts a second concurrent handler call — it queues and reruns once after.
 *  CT3 — fail-loud: a cross-writer optimistic-lock conflict inside the handler
 *        propagates (never swallowed) and is surfaced loudly; a subsequent write
 *        (retry) succeeds normally afterward.
 *  CT4 — byte parity: the snapshot blob after a reaction-triggered rebuild is
 *        byte-identical (same `contentHash`, over the plaintext envelope — see
 *        `hashContent`'s doc comment in `keyDerivation.ts`) to the blob after an
 *        equivalent MANUAL rebuild call, given the same transactions.
 */
import assert from "node:assert/strict";
import test from "node:test";
import { randomBytes } from "@noble/ciphers/utils.js";
import { z } from "zod";

import { createDekHandle } from "./testKeyHandle.ts";
import {
  configureSecureStore,
  __resetSecureStoreConfig,
  defineStore,
  fingerprintSchema,
  onSourceWrite,
  OptimisticLockConflictError,
  type StorageAdapter,
  type BlobRecord,
  type CacheAdapter,
  type CryptoHandle,
  type KeyProvider,
} from "../index.ts";

function fixedKeyProvider(cryptoHandle: CryptoHandle): KeyProvider {
  return {
    getCryptoHandle: () => cryptoHandle,
    getUserId: () => "u1",
    subscribe: () => () => {},
  };
}

/** Real subscribable in-memory CacheAdapter — `set()` synchronously invokes
 * subscribers, exactly like `tanstackAdapter`'s production `QueryCache` behavior
 * (see `keyedWriteKeysCacheKey`'s doc comment in `core/store.ts` for why this
 * synchronous-notify guarantee is what makes "last write's keys" always correct,
 * never lost to a race). Mirrors `aggregation.test.ts`'s own `memoryCache()`. */
function memoryCache(): CacheAdapter {
  const data = new Map<string, unknown>();
  const subs = new Map<string, Set<() => void>>();
  return {
    get: (key) => data.get(key) as never,
    set: (key, value) => {
      data.set(key, value);
      for (const cb of subs.get(key) ?? []) cb();
    },
    subscribe: (key, cb) => {
      if (!subs.has(key)) subs.set(key, new Set());
      subs.get(key)!.add(cb);
      return () => subs.get(key)?.delete(cb);
    },
    clear: () => data.clear(),
  };
}

/** In-memory adapter supporting everything BOTH toy stores need: `get`/`put`
 * (plain), `putIfMatch` (optimisticLock `mutate()`), `insertMany` (`createMany()`
 * bulk-create), `listByKeyRange` (range read, the "load affected months"
 * half of a rebuild). One instance backs BOTH stores, keyed by `collection` name
 * (matches the two distinct real tables), same as `aggregation.test.ts`'s own
 * `memoryAdapter()` comment explains. */
function memoryAdapter(): StorageAdapter & { rows: Map<string, BlobRecord> } {
  const rows = new Map<string, BlobRecord>();
  const keyOf = (
    collection: string,
    userId: string,
    extraKeys: { value: string }[],
  ) => `${collection}:${userId}:${extraKeys[0]?.value}`;
  return {
    rows,
    async get(collection, userId, extraKeys) {
      return rows.get(keyOf(collection, userId, extraKeys)) ?? null;
    },
    async put(collection, userId, extraKeys, record) {
      rows.set(keyOf(collection, userId, extraKeys), record);
    },
    async putIfMatch(collection, userId, extraKeys, record, expectedHash) {
      const key = keyOf(collection, userId, extraKeys);
      const current = rows.get(key) ?? null;
      if (expectedHash === null) {
        if (current) return false;
        rows.set(key, record);
        return true;
      }
      if (!current || current.contentHash !== expectedHash) return false;
      rows.set(key, record);
      return true;
    },
    async insertMany(collection, userId, entries) {
      for (const { extraKeys, record } of entries) {
        rows.set(keyOf(collection, userId, extraKeys), record);
      }
    },
    async listByKeyRange(collection, userId, _keyColumn, from, to) {
      const prefix = `${collection}:${userId}:`;
      const out: Array<{ key: string; record: BlobRecord }> = [];
      for (const [rowKey, record] of rows) {
        if (!rowKey.startsWith(prefix)) continue;
        const key = rowKey.slice(prefix.length);
        if (key >= from && key <= to) out.push({ key, record });
      }
      return out.sort((a, b) => a.key.localeCompare(b.key));
    },
  };
}

async function waitFor(
  predicate: () => boolean | Promise<boolean>,
  timeoutMs = 2000,
): Promise<void> {
  const start = Date.now();
  while (!(await predicate())) {
    if (Date.now() - start > timeoutMs) {
      throw new Error("waitFor: timed out waiting for the reaction");
    }
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
}

// ─── Toy domain: "transactions" (perKey by month) + "snapshot" (one sentinel key) ──

const TxSchema = z.object({ id: z.string(), amount: z.number() });
const TxMonthSchema = z.array(TxSchema).default([]);

const SnapshotSchema = z.object({
  months: z.record(z.string(), z.number()).default({}),
});
const SNAP_KEY = "__store__";

function makeStores() {
  const txStore = defineStore({
    name: "toy_tx_blobs",
    identity: { perKey: "month" },
    encrypt: "all",
    schema: TxMonthSchema,
    version: 1,
    schemaFingerprint: fingerprintSchema(TxMonthSchema, "all"),
    empty: [],
    contentHash: true,
    optimisticLock: true,
  });

  const snapshotStore = defineStore({
    name: "toy_snapshot_blobs",
    identity: { perKey: "key" },
    encrypt: "all",
    schema: SnapshotSchema,
    version: 1,
    schemaFingerprint: fingerprintSchema(SnapshotSchema, "all"),
    contentHash: true,
    optimisticLock: true,
  });

  /** Toy analogue of `snapshotService.ts`'s `rebuildMonths` — pure per-month delta
   * (sum of amounts) applied to the FRESH snapshot inside `mutate()`, exactly the
   * same "read range, compute per-month, apply to fresh blob" shape. */
  async function rebuildMonths(months: string[]): Promise<void> {
    if (!months.length) return;
    const from = months[0];
    const to = months[months.length - 1];
    const range = await txStore.getRange({ from, to });
    const byMonth = new Map(range.map(({ key, data }) => [key, data]));
    await snapshotStore.mutate(SNAP_KEY, (current) => {
      const next = { months: { ...current.months } };
      for (const m of months) {
        const txs = byMonth.get(m) ?? [];
        next.months[m] = txs.reduce((sum, t) => sum + t.amount, 0);
      }
      return next;
    });
  }

  return { txStore, snapshotStore, rebuildMonths };
}

test.beforeEach(() => __resetSecureStoreConfig());

// ─── CT1 — coalescing ──────────────────────────────────────────────────────────

test("CT1: two writes to different months inside the debounce window -> exactly ONE handler call, both months", async () => {
  const adapter = memoryAdapter();
  const cache = memoryCache();
  const cryptoHandle = createDekHandle(randomBytes(32));
  configureSecureStore({
    storage: adapter,
    keys: fixedKeyProvider(cryptoHandle),
    cache,
  });
  const { txStore, snapshotStore, rebuildMonths } = makeStores();

  const handlerCalls: string[][] = [];
  const unsubscribe = onSourceWrite(
    txStore,
    async ({ keys }) => {
      handlerCalls.push([...keys].sort());
      const sorted = [...keys].sort();
      await rebuildMonths(sorted);
    },
    { debounceMs: 30, coalesce: true },
  );

  await txStore.mutate("2026-03", () => [{ id: "a", amount: 100 }]);
  await txStore.mutate("2026-05", () => [{ id: "b", amount: 50 }]);

  await waitFor(() => handlerCalls.length > 0, 1000);
  // Give a settle window in case a second (unwanted) call would fire.
  await new Promise((r) => setTimeout(r, 80));

  assert.equal(
    handlerCalls.length,
    1,
    "two writes inside the debounce window must coalesce into ONE handler call",
  );
  assert.deepEqual(handlerCalls[0], ["2026-03", "2026-05"]);

  const { data } = await snapshotStore.loadWithHash!(
    "u1",
    cryptoHandle,
    SNAP_KEY,
  );
  assert.deepEqual(data.months, { "2026-03": 100, "2026-05": 50 });
  // ONE snapshot write for the whole coalesced batch, not one per month.
  assert.equal(adapter.rows.size, 3); // 2 tx months + 1 snapshot row

  unsubscribe();
});

// ─── CT2 — single-flight ───────────────────────────────────────────────────────

test("CT2: a write arriving while the handler is in flight never runs a second concurrent handler — it queues and reruns after", async () => {
  const adapter = memoryAdapter();
  const cache = memoryCache();
  const cryptoHandle = createDekHandle(randomBytes(32));
  configureSecureStore({
    storage: adapter,
    keys: fixedKeyProvider(cryptoHandle),
    cache,
  });
  const { txStore, snapshotStore, rebuildMonths } = makeStores();

  let concurrent = 0;
  let maxConcurrent = 0;
  const handlerCalls: string[][] = [];
  let releaseFirst: (() => void) | null = null;
  const firstGate = new Promise<void>((resolve) => {
    releaseFirst = resolve;
  });

  const unsubscribe = onSourceWrite(
    txStore,
    async ({ keys }) => {
      concurrent++;
      maxConcurrent = Math.max(maxConcurrent, concurrent);
      handlerCalls.push([...keys].sort());
      if (handlerCalls.length === 1) {
        await firstGate; // hold the first call "in flight" deliberately
      }
      await rebuildMonths([...keys].sort());
      concurrent--;
    },
    { debounceMs: 10, coalesce: true },
  );

  await txStore.mutate("2026-01", () => [{ id: "a", amount: 10 }]);
  await waitFor(() => handlerCalls.length === 1, 1000);

  // A second write arrives WHILE the first handler call is still in flight (gated).
  await txStore.mutate("2026-02", () => [{ id: "b", amount: 20 }]);
  // Debounce window for the second write elapses too — but single-flight must
  // absorb it as a queued rerun, never a second concurrent handler call.
  await new Promise((r) => setTimeout(r, 60));
  assert.equal(
    handlerCalls.length,
    1,
    "no second handler call may start while the first is in flight",
  );

  releaseFirst!();
  // Wait for the QUEUED rerun's own rebuildMonths (not just the handler's first
  // synchronous line) to actually finish persisting — `handlerCalls.length`
  // increments the instant the rerun STARTS, not once its own `await` settles.
  await waitFor(async () => {
    const { data } = await snapshotStore.loadWithHash!(
      "u1",
      cryptoHandle,
      SNAP_KEY,
    );
    return data.months["2026-02"] === 20;
  }, 1000);

  assert.equal(handlerCalls.length, 2);
  assert.equal(maxConcurrent, 1, "handler calls must never overlap");
  assert.deepEqual(handlerCalls[0], ["2026-01"]);
  assert.deepEqual(handlerCalls[1], ["2026-02"]);

  const { data } = await snapshotStore.loadWithHash!(
    "u1",
    cryptoHandle,
    SNAP_KEY,
  );
  assert.deepEqual(data.months, { "2026-01": 10, "2026-02": 20 });

  unsubscribe();
});

// ─── CT3 — fail-loud conflict, never swallowed, retry succeeds ────────────────

test("CT3: a cross-writer optimistic-lock conflict propagates (never swallowed) and a subsequent write retries successfully", async () => {
  const adapter = memoryAdapter();
  const cache = memoryCache();
  const cryptoHandle = createDekHandle(randomBytes(32));
  configureSecureStore({
    storage: adapter,
    keys: fixedKeyProvider(cryptoHandle),
    cache,
  });
  const { txStore, snapshotStore } = makeStores();

  const originalConsoleError = console.error;
  const loggedErrors: unknown[][] = [];
  console.error = (...args: unknown[]) => {
    loggedErrors.push(args);
  };

  let releaseGate: (() => void) | null = null;
  const gate = new Promise<void>((resolve) => {
    releaseGate = resolve;
  });

  const handlerCalls: string[][] = [];
  const unsubscribe = onSourceWrite(
    txStore,
    async ({ keys }) => {
      handlerCalls.push([...keys].sort());
      // Same shape `rebuildMonths` uses (mutate() over the fresh snapshot) — the
      // `fn` callback is awaited BETWEEN mutate()'s own internal read and its
      // conditional write, so pausing here (only on the FIRST call) opens the
      // exact race window a genuinely concurrent "other writer" would exploit.
      await snapshotStore.mutate(SNAP_KEY, async (current) => {
        if (handlerCalls.length === 1) await gate;
        return {
          months: {
            ...current.months,
            [keys[0]]: keys[0] === "2026-01" ? 999 : 5,
          },
        };
      });
    },
    { debounceMs: 10, coalesce: true },
  );

  await txStore.mutate("2026-01", () => [{ id: "a", amount: 1 }]);
  await waitFor(() => handlerCalls.length === 1, 1000);

  // "Another writer" bumps the snapshot's version WHILE our mutate() is paused
  // inside `fn`, mid-`mutate()` — the same race CT3 describes.
  await snapshotStore.mutate(SNAP_KEY, (current) => ({
    months: { ...current.months, "2026-09": 1 },
  }));

  releaseGate!();
  // Give the rejected handler promise a tick to be caught/logged.
  await new Promise((r) => setTimeout(r, 30));

  assert.equal(
    loggedErrors.length,
    1,
    "the conflict must be surfaced (logged), never silently discarded",
  );
  assert.ok(
    loggedErrors[0][1] instanceof OptimisticLockConflictError,
    "the REAL OptimisticLockConflictError must reach the log call, not a stringified/generic error",
  );

  // The snapshot must show the winning ("other writer") value — our conflicting
  // write never landed, was never partially applied, never silently "won" instead.
  const afterConflict = await snapshotStore.loadWithHash!(
    "u1",
    cryptoHandle,
    SNAP_KEY,
  );
  assert.deepEqual(afterConflict.data.months, { "2026-09": 1 });

  // Retry: a fresh write triggers the reaction again; this time nothing else
  // races it, so it must succeed normally.
  await txStore.mutate("2026-02", () => [{ id: "b", amount: 2 }]);
  await waitFor(async () => {
    const { data } = await snapshotStore.loadWithHash!(
      "u1",
      cryptoHandle,
      SNAP_KEY,
    );
    return data.months["2026-02"] === 5;
  }, 1000);
  assert.equal(handlerCalls.length, 2);

  const afterRetry = await snapshotStore.loadWithHash!(
    "u1",
    cryptoHandle,
    SNAP_KEY,
  );
  assert.deepEqual(afterRetry.data.months, { "2026-09": 1, "2026-02": 5 });

  console.error = originalConsoleError;
  unsubscribe();
});

// ─── CT4 — byte parity: reaction-triggered vs. manual rebuild ─────────────────

test("CT4: the snapshot blob after a reaction-triggered rebuild is byte-identical (same contentHash) to a manual rebuildMonths call", async () => {
  const seedTxs: Array<{
    month: string;
    txs: { id: string; amount: number }[];
  }> = [
    {
      month: "2026-03",
      txs: [
        { id: "a", amount: 100 },
        { id: "b", amount: -30 },
      ],
    },
    { month: "2026-04", txs: [{ id: "c", amount: 25 }] },
  ];

  // ── Scenario A: reaction-triggered ──
  const cryptoHandle = createDekHandle(randomBytes(32));
  let hashA: string | null = null;
  let dataA: unknown;
  {
    const adapter = memoryAdapter();
    const cache = memoryCache();
    configureSecureStore({
      storage: adapter,
      keys: fixedKeyProvider(cryptoHandle),
      cache,
    });
    const { txStore, snapshotStore, rebuildMonths } = makeStores();
    const unsubscribe = onSourceWrite(
      txStore,
      async ({ keys }) => {
        const sorted = [...keys].sort();
        await rebuildMonths(sorted);
      },
      { debounceMs: 20, coalesce: true },
    );

    await txStore.createMany(
      seedTxs.map(({ month, txs }) => ({ key: month, data: txs })),
    );

    await new Promise((resolve) => setTimeout(resolve, 80));
    const loaded = await snapshotStore.loadWithHash!(
      "u1",
      cryptoHandle,
      SNAP_KEY,
    );
    dataA = loaded.data;
    hashA = loaded.hash;
    unsubscribe();
    __resetSecureStoreConfig();
  }

  // ── Scenario B: manual rebuild, no reaction at all ──
  let hashB: string | null = null;
  let dataB: unknown;
  {
    const adapter = memoryAdapter();
    configureSecureStore({
      storage: adapter,
      keys: fixedKeyProvider(cryptoHandle),
    });
    const { txStore, snapshotStore, rebuildMonths } = makeStores();

    await txStore.createMany(
      seedTxs.map(({ month, txs }) => ({ key: month, data: txs })),
    );
    await rebuildMonths(["2026-03", "2026-04"]);

    const loaded = await snapshotStore.loadWithHash!(
      "u1",
      cryptoHandle,
      SNAP_KEY,
    );
    dataB = loaded.data;
    hashB = loaded.hash;
    __resetSecureStoreConfig();
  }

  assert.deepEqual(
    dataA,
    dataB,
    "the decoded snapshot content must be identical between the two paths",
  );
  assert.ok(hashA, "scenario A must have produced a contentHash");
  assert.equal(
    hashA,
    hashB,
    "contentHash is a deterministic hash of the PLAINTEXT envelope bytes (see " +
      "hashContent's doc comment) — equal hashes is the byte-for-byte proof, " +
      "since ciphertext bytes themselves differ every encryption (random nonce)",
  );
});
