/**
 * Pure patching logic for sync-fingerprints.mjs — separated so it's unit-testable
 * without any dynamic import/execution machinery.
 *
 * Known limit (documented, not silently assumed): patches the FIRST
 * `schemaFingerprint: "..."` occurrence in the file, or inserts one right after
 * the first `version: <n>,` line if none exists. Correct as long as a file has
 * exactly one `defineStore(...)` call — today's convention across every ported
 * service. A file with multiple `defineStore` calls needs manual disambiguation
 * (or this function extended to take a store name anchor) — not built until a
 * real second-store-per-file case exists.
 */

const FINGERPRINT_RE = /schemaFingerprint:\s*["'`][0-9a-f]*["'`]/;
const VERSION_LINE_RE = /^(\s*)version:\s*[^\n,]+,\s*$/m;

export function patchFingerprint(source, correctValue) {
  if (FINGERPRINT_RE.test(source)) {
    return source.replace(
      FINGERPRINT_RE,
      `schemaFingerprint: "${correctValue}"`,
    );
  }
  const match = source.match(VERSION_LINE_RE);
  if (!match) return source; // caller must detect this as "couldn't patch"
  const indent = match[1];
  const insertion = `${match[0]}\n${indent}schemaFingerprint: "${correctValue}",`;
  return (
    source.slice(0, match.index) +
    insertion +
    source.slice(match.index + match[0].length)
  );
}
