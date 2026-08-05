/**
 * Versioning + lazy upgrade of encrypted blobs (part of the Zechinus framework).
 *
 * The version is embedded INSIDE the encrypted payload (toEnvelope/fromEnvelope):
 * AES-GCM guarantees its integrity, so it's authenticated. The DB column
 * `schema_version` remains only as a fallback for pre-envelope blobs (old format).
 *
 * migrators[i] transforms from version (i+1) to (i+2): migrators[0] = v1→v2, etc.
 */

export type BlobMigrator = (data: any) => any;

export type BlobMigrationResult<T> = {
  data: T;
  /** true if at least one migration was applied (the blob needs rewriting) */
  upgraded: boolean;
};

/** Encrypted payload with the authenticated version embedded. */
export type VersionedEnvelope<T> = { _v: number; d: T };

/** Wraps the payload with the version before encryption. */
export function toEnvelope<T>(data: T, version: number): VersionedEnvelope<T> {
  return { _v: version, d: data };
}

/**
 * Extracts the authenticated version and data from a decrypted blob.
 * Pre-envelope blobs (without _v) fall back to dbVersion.
 */
export function fromEnvelope<T>(
  raw: unknown,
  dbVersion: number,
): { data: T; authenticatedVersion: number } {
  const obj = raw as Record<string, unknown>;
  if ("_v" in obj && "d" in obj && typeof obj._v === "number") {
    return { data: obj.d as T, authenticatedVersion: obj._v };
  }
  return { data: raw as T, authenticatedVersion: dbVersion };
}

/**
 * Applies the migrator chain from `fromVersion` to `currentVersion`.
 * Always uses the authenticated version (from fromEnvelope), never the DB column.
 */
export function runMigrations<T>(
  data: unknown,
  fromVersion: number,
  currentVersion: number,
  migrators: BlobMigrator[],
): BlobMigrationResult<T> {
  if (fromVersion === currentVersion) {
    return { data: data as T, upgraded: false };
  }
  if (fromVersion > currentVersion) {
    throw new Error(
      `secure-store/versioning: schema_version ${fromVersion} > code version ${currentVersion} — update the app`,
    );
  }

  let result = data;
  for (let v = fromVersion; v < currentVersion; v++) {
    const migrator = migrators[v - 1]; // migrators[0] = v1→v2
    if (!migrator) {
      throw new Error(
        `secure-store/versioning: missing migrator for v${v} → v${v + 1}`,
      );
    }
    result = migrator(result);
  }

  return { data: result as T, upgraded: true };
}
