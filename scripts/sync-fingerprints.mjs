#!/usr/bin/env node
/**
 * Auto-fix tool for the `schemaFingerprint` guardrail — NOT the enforcement itself.
 * The enforcement is `defineStore()` throwing at import time in every environment
 * (tests, CI, the running app); this script only removes the "compute it by hand,
 * copy-paste from the error message" step once you've already decided the change
 * is safe. Deliberately NOT wired into an automatic pre-commit fix: the guardrail's
 * whole point is a conscious stop-and-decide moment (does this need a `version`
 * bump + migrator, or is it safe?) — auto-fixing on every commit would silently
 * remove that moment. Run it yourself, after deciding, not before.
 *
 * Usage:
 *   npx tsx datacloak/scripts/sync-fingerprints.mjs <file1.ts> [file2.ts ...]
 *
 * Exit code 0 if every file is OK (already correct, or successfully patched).
 * Exit code 1 if a file has a real error unrelated to schemaFingerprint, or a
 * fingerprint mismatch this script couldn't locate/patch — never silently skips.
 */
import { readFileSync, writeFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { resolve } from "node:path";
import { patchFingerprint } from "./patchFingerprint.mjs";

const MISSING_RE = /schemaFingerprint: "([0-9a-f]+)" to the def/;
const MISMATCH_RE = /computed "([0-9a-f]+)"\)/;
const MAX_ATTEMPTS = 5;

const files = process.argv.slice(2);
if (files.length === 0) {
  console.error("usage: sync-fingerprints.mjs <file.ts> [file2.ts ...]");
  process.exit(1);
}

let hadRealError = false;

for (const file of files) {
  const absPath = resolve(file);
  let attempt = 0;
  let done = false;
  while (attempt < MAX_ATTEMPTS && !done) {
    attempt++;
    try {
      await import(`${pathToFileURL(absPath).href}?t=${Date.now()}-${attempt}`);
      console.log(`OK    ${file}`);
      done = true;
    } catch (e) {
      const message = e instanceof Error ? e.message : String(e);
      const valueMatch =
        message.match(MISSING_RE) ?? message.match(MISMATCH_RE);
      if (!valueMatch) {
        console.error(`FAIL  ${file}: ${message}`);
        hadRealError = true;
        done = true;
        break;
      }
      const correctValue = valueMatch[1];
      const source = readFileSync(absPath, "utf8");
      const patched = patchFingerprint(source, correctValue);
      if (patched === source) {
        console.error(
          `FAIL  ${file}: schemaFingerprint drift detected (should be "${correctValue}") ` +
            `but couldn't locate where to patch it — fix manually.`,
        );
        hadRealError = true;
        done = true;
        break;
      }
      writeFileSync(absPath, patched);
      console.log(`FIXED ${file}: schemaFingerprint → "${correctValue}"`);
      // loop: re-import to confirm the patch actually resolved it
    }
  }
  if (!done) {
    console.error(
      `FAIL  ${file}: did not converge after ${MAX_ATTEMPTS} attempts.`,
    );
    hadRealError = true;
  }
}

process.exit(hadRealError ? 1 : 0);
