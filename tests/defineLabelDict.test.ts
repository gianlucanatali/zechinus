import assert from "node:assert/strict";
import test from "node:test";
import { randomBytes } from "@noble/ciphers/utils.js";

import { createDekHandle } from "../../crypto/passkey-prf.ts";
import { configureSecureStore } from "../core/config.ts";
import { defineLabelDict } from "../core/defineLabelDict.ts";
import type { BlobRecord, StorageAdapter } from "../core/types.ts";

function keyedMemoryAdapter(): StorageAdapter & {
  rows: Map<string, BlobRecord>;
} {
  const rows = new Map<string, BlobRecord>();
  return {
    rows,
    async getOne() {
      return null;
    },
    async putOne() {},
    async getByKey(collection, userId, _keyColumn, keyValue) {
      return rows.get(`${collection}:${userId}:${keyValue}`) ?? null;
    },
    async putByKey(collection, userId, _keyColumn, keyValue, record) {
      rows.set(`${collection}:${userId}:${keyValue}`, record);
    },
  };
}

test("defineLabelDict: getLabel on an unset entity returns undefined, no data written yet", async () => {
  const adapter = keyedMemoryAdapter();
  configureSecureStore({ storage: adapter });
  const dek = createDekHandle(randomBytes(32));

  const labels = defineLabelDict({ name: "user_label_dicts" });

  const value = await labels.getLabel("u1", dek, "accounts", "acc-1");
  assert.equal(value, undefined);
  assert.equal(adapter.rows.size, 0);
});

test("defineLabelDict: setLabel then getLabel roundtrip", async () => {
  const adapter = keyedMemoryAdapter();
  configureSecureStore({ storage: adapter });
  const dek = createDekHandle(randomBytes(32));

  const labels = defineLabelDict({ name: "user_label_dicts" });

  await labels.setLabel("u1", dek, "accounts", "acc-1", "Conto corrente");
  const value = await labels.getLabel("u1", dek, "accounts", "acc-1");

  assert.equal(value, "Conto corrente");
  const raw = adapter.rows.get("user_label_dicts:u1:accounts");
  assert.ok(raw!.blob.startsWith("enc:"));
  assert.ok(
    !raw!.blob.includes("Conto corrente"),
    "plaintext NOT in the ciphertext",
  );
});

test("defineLabelDict: setLabel merges into the existing dict, doesn't clobber other entries", async () => {
  const adapter = keyedMemoryAdapter();
  configureSecureStore({ storage: adapter });
  const dek = createDekHandle(randomBytes(32));

  const labels = defineLabelDict({ name: "user_label_dicts" });
  await labels.setLabel("u1", dek, "accounts", "acc-1", "Conto corrente");
  await labels.setLabel("u1", dek, "accounts", "acc-2", "Conto risparmio");

  assert.deepEqual(await labels.getAll("u1", dek, "accounts"), {
    "acc-1": "Conto corrente",
    "acc-2": "Conto risparmio",
  });
});

test("defineLabelDict: deleteLabel removes only that entity, keeps the rest", async () => {
  const adapter = keyedMemoryAdapter();
  configureSecureStore({ storage: adapter });
  const dek = createDekHandle(randomBytes(32));

  const labels = defineLabelDict({ name: "user_label_dicts" });
  await labels.setLabel("u1", dek, "accounts", "acc-1", "Conto corrente");
  await labels.setLabel("u1", dek, "accounts", "acc-2", "Conto risparmio");

  await labels.deleteLabel("u1", dek, "accounts", "acc-1");

  assert.deepEqual(await labels.getAll("u1", dek, "accounts"), {
    "acc-2": "Conto risparmio",
  });
});

test("defineLabelDict: different dict keys (e.g. 'accounts' vs 'categories') are independent", async () => {
  const adapter = keyedMemoryAdapter();
  configureSecureStore({ storage: adapter });
  const dek = createDekHandle(randomBytes(32));

  const labels = defineLabelDict({ name: "user_label_dicts" });
  await labels.setLabel("u1", dek, "accounts", "acc-1", "Conto corrente");
  await labels.setLabel("u1", dek, "categories", "cat-1", "Spesa");

  assert.deepEqual(await labels.getAll("u1", dek, "accounts"), {
    "acc-1": "Conto corrente",
  });
  assert.deepEqual(await labels.getAll("u1", dek, "categories"), {
    "cat-1": "Spesa",
  });
});

test("defineLabelDict: keyColumn is an injectable extension point (defaults to 'table_name')", async () => {
  const adapter: StorageAdapter & { calls: string[] } = {
    calls: [],
    async getOne() {
      return null;
    },
    async putOne() {},
    async getByKey(_c, _u, keyColumn) {
      adapter.calls.push(`getByKey:${keyColumn}`);
      return null;
    },
    async putByKey(_c, _u, keyColumn) {
      adapter.calls.push(`putByKey:${keyColumn}`);
    },
  };
  configureSecureStore({ storage: adapter });
  const dek = createDekHandle(randomBytes(32));

  const defaultLabels = defineLabelDict({ name: "user_label_dicts" });
  await defaultLabels.getLabel("u1", dek, "accounts", "acc-1");
  assert.equal(adapter.calls[0], "getByKey:table_name");

  const customLabels = defineLabelDict({
    name: "other_dicts",
    keyColumn: "dict_key",
  });
  await customLabels.setLabel("u1", dek, "accounts", "acc-1", "x");
  // setLabel does a load (getByKey) then a save (putByKey) — both under the custom column
  assert.equal(adapter.calls[1], "getByKey:dict_key");
  assert.equal(adapter.calls[2], "putByKey:dict_key");
});
