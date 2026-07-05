/**
 * Shared single-row orchestration (encode/decode/legacy-fallback/optimistic-lock)
 * used by BOTH `perUser` (blobStore.ts) and `perKey` (store.ts) cardinalities — the
 * two are structurally identical row stores, differing only in how many coordinates
 * address the row: perUser's row is the only one for a user (`get(table,userId,[])`),
 * perKey's is one of many (`get(table,userId,[{column,value}])`). `many` is
 * NOT unified here — it lists many rows at once and splits plain/enc fields, a
 * genuinely different shape, not just a different address arity.
 */

import { encodeBlob } from "./blobCodec.ts";
import { decodeWithLegacyFallback } from "./legacyFallback.ts";
import type { BlobMigrator } from "./versioning.ts";
import type { BlobRecord, CryptoHandle, FieldAAD } from "./types.ts";

export interface RowReadIO {
  get(): Promise<BlobRecord | null>;
  put(record: BlobRecord): Promise<void>;
}

/**
 * The one AAD shape every store cardinality converges on: `field` is always
 * "data" (the canonical, non-legacy field name), `rowId` addresses the row
 * (the user's own pid for `perUser`, the key for `perKey`, the row id for
 * `many`). Exported so app tests that need to write a row directly with
 * `encodeBlob` (bypassing a store's own schema validation — e.g. to simulate
 * data from before a field existed) don't have to reconstruct this shape by
 * hand.
 */
export function canonicalAAD(
  cryptoHandle: CryptoHandle,
  table: string,
  rowId: string = cryptoHandle.pid,
): FieldAAD {
  return { userId: cryptoHandle.pid, table, field: "data", rowId };
}

export interface LoadRowOpts<T> {
  storeName: string;
  /** Prefixes the lazy-upgrade failure log — "" for perUser, "perKey " for perKey. */
  rowLabel: string;
  version: number;
  migrators: BlobMigrator[];
  empty: T;
  legacyAAD?: FieldAAD;
}

/**
 * Read + legacy-AAD fallback + lazy re-encrypt-under-canonical-AAD on a version/AAD
 * upgrade. `onUpgraded` is fire-and-forget (errors logged, never thrown) — callers
 * decide what "save" means for them (perKey validates via Zod first, perUser doesn't
 * have schema access at this layer and skips it).
 */
export async function loadRow<T>(
  cryptoHandle: CryptoHandle,
  io: RowReadIO,
  aad: FieldAAD,
  opts: LoadRowOpts<T>,
  onUpgraded: (data: T) => void | Promise<void>,
): Promise<{ data: T; hash: string | null }> {
  const record = await io.get();
  const { data, upgraded } = await decodeWithLegacyFallback<T>({
    cryptoHandle,
    record,
    canonicalAAD: aad,
    legacyAAD: opts.legacyAAD,
    version: opts.version,
    migrators: opts.migrators,
    empty: opts.empty,
    persistMigrated: (migratedRecord) => io.put(migratedRecord),
  });
  if (upgraded) {
    Promise.resolve(onUpgraded(data)).catch((e) =>
      console.error(
        `secure-store(${opts.storeName}): ${opts.rowLabel}lazy upgrade failed:`,
        e,
      ),
    );
  }
  return { data, hash: record?.contentHash ?? null };
}

export async function saveRow<T>(
  cryptoHandle: CryptoHandle,
  put: (record: BlobRecord) => Promise<void>,
  aad: FieldAAD,
  data: T,
  version: number,
  contentHash: boolean | undefined,
): Promise<void> {
  const record = await encodeBlob(
    cryptoHandle,
    aad,
    data,
    version,
    contentHash,
  );
  await put(record);
}

/**
 * Conditional write for optimistic locking. `putIfMatch` is `undefined` when the
 * configured adapter lacks the capability — throws immediately with `missingCapabilityMsg`
 * rather than silently falling back to an unconditional write.
 *
 * On success, `hash` is the new content_hash — already computed here (deterministically,
 * client-side, from `data`) before the write even happens, so the caller never needs a
 * follow-up fetch to learn it (that's what lets `useStore`/`useKeyedStore`/`useCollectionStore`
 * thread the hash through the cache without an extra round-trip after every save). On
 * conflict (`ok:false`), `hash` is `null` — the write didn't happen, so there's no new
 * hash to report; returning the stale one back would be misleading.
 */
export async function saveRowIfMatch<T>(
  cryptoHandle: CryptoHandle,
  putIfMatch:
    | ((record: BlobRecord, expectedHash: string | null) => Promise<boolean>)
    | undefined,
  aad: FieldAAD,
  data: T,
  version: number,
  expectedHash: string | null,
  missingCapabilityMsg: string,
): Promise<{ ok: boolean; hash: string | null }> {
  if (!putIfMatch) {
    throw new Error(missingCapabilityMsg);
  }
  const record = await encodeBlob(cryptoHandle, aad, data, version, true);
  const ok = await putIfMatch(record, expectedHash);
  return { ok, hash: ok ? (record.contentHash ?? null) : null };
}
