import assert from "node:assert/strict";
import test from "node:test";
import { randomBytes } from "@noble/ciphers/utils.js";

import { createDekHandle } from "./testKeyHandle.ts";
import { configureSecureStore } from "../core/config.ts";
import { defineLabelDict } from "../core/defineLabelDict.ts";
import type { BlobRecord, StorageAdapter } from "../core/types.ts";

function keyedMemoryAdapter(): StorageAdapter & {
  rows: Map<string, BlobRecord>;
} {
  const rows = new Map<string, BlobRecord>();
  return {
    rows,
    async get(collection, userId, extraKeys) {
      return rows.get(`${collection}:${userId}:${extraKeys[0]?.value}`) ?? null;
    },
    async put(collection, userId, extraKeys, record) {
      rows.set(`${collection}:${userId}:${extraKeys[0]?.value}`, record);
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
    async get(_c, _u, extraKeys) {
      adapter.calls.push(`get:${extraKeys[0]?.column}`);
      return null;
    },
    async put(_c, _u, extraKeys) {
      adapter.calls.push(`put:${extraKeys[0]?.column}`);
    },
  };
  configureSecureStore({ storage: adapter });
  const dek = createDekHandle(randomBytes(32));

  const defaultLabels = defineLabelDict({ name: "user_label_dicts" });
  await defaultLabels.getLabel("u1", dek, "accounts", "acc-1");
  assert.equal(adapter.calls[0], "get:table_name");

  const customLabels = defineLabelDict({
    name: "other_dicts",
    keyColumn: "dict_key",
  });
  await customLabels.setLabel("u1", dek, "accounts", "acc-1", "x");
  // setLabel does a load (get) then a save (put) — both under the custom column
  assert.equal(adapter.calls[1], "get:dict_key");
  assert.equal(adapter.calls[2], "put:dict_key");
});
