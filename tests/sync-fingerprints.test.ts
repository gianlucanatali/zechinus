/**
 * Integration test for sync-fingerprints.mjs: real subprocess (`node`), real
 * files, real defineStore() throwing — no mocking of the guardrail itself, since
 * the whole point is verifying the CLI reacts correctly to the ACTUAL error shape
 * store.ts throws today. A future change to those error messages should break this
 * test, not silently desync the tool from the guardrail it patches.
 *
 * Fixtures MUST live inside the repo tree (not os.tmpdir()): the script dynamically
 * imports the target file by path, and bare imports inside it ("zod") resolve via
 * node_modules lookup starting from the file's own directory — a file outside the
 * repo can never find them. This mirrors real usage: the tool only ever runs
 * against files that are already part of the project.
 */
import assert from "node:assert/strict";
import test from "node:test";
import { writeFileSync, readFileSync, rmSync, mkdirSync } from "node:fs";
import { randomUUID } from "node:crypto";
import { join } from "node:path";
import { execFileSync } from "node:child_process";

const SCRIPT = join(import.meta.dirname, "../scripts/sync-fingerprints.mjs");
const REPO_ROOT = join(import.meta.dirname, "../..");
const FIXTURES_DIR = join(import.meta.dirname, "fixtures");
mkdirSync(FIXTURES_DIR, { recursive: true });

function writeFixture(body: string): string {
  const path = join(FIXTURES_DIR, `tmp-${randomUUID()}.ts`);
  writeFileSync(
    path,
    [
      'import { z } from "zod";',
      'import { defineStore, type BlobMigrator } from "../../index.ts";',
      "",
      'const Schema = z.object({ value: z.string().default("x") });',
      "",
      body,
    ].join("\n"),
  );
  return path;
}

function runScript(file: string): { status: number; output: string } {
  try {
    const output = execFileSync("npx", ["tsx", SCRIPT, file], {
      cwd: REPO_ROOT,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    });
    return { status: 0, output };
  } catch (e) {
    const err = e as { status: number; stdout: string; stderr: string };
    return { status: err.status, output: err.stdout + err.stderr };
  }
}

test("sync-fingerprints: patches a stale (wrong) fingerprint and converges", (t) => {
  const file = writeFixture(
    [
      "const store = defineStore({",
      '  name: "fixture_blobs",',
      '  identity: "perUser",',
      '  encrypt: "all",',
      "  schema: Schema,",
      "  version: 1,",
      "  migrators: [] as BlobMigrator[],",
      '  schemaFingerprint: "deadbeef",',
      "});",
      "export { store };",
    ].join("\n"),
  );
  t.after(() => rmSync(file, { force: true }));

  const { status, output } = runScript(file);

  assert.equal(status, 0, output);
  assert.match(output, /FIXED/);
  const patched = readFileSync(file, "utf8");
  assert.doesNotMatch(patched, /deadbeef/);
  assert.match(patched, /schemaFingerprint: "[0-9a-f]+"/);

  // re-running against the now-correct file must report OK, not patch again
  const second = runScript(file);
  assert.equal(second.status, 0, second.output);
  assert.match(second.output, /OK/);
});

test("sync-fingerprints: inserts a missing fingerprint field and converges", (t) => {
  const file = writeFixture(
    [
      "const store = defineStore({",
      '  name: "fixture_blobs",',
      '  identity: "perUser",',
      '  encrypt: "all",',
      "  schema: Schema,",
      "  version: 1,",
      "  migrators: [] as BlobMigrator[],",
      "});",
      "export { store };",
    ].join("\n"),
  );
  t.after(() => rmSync(file, { force: true }));

  const { status, output } = runScript(file);

  assert.equal(status, 0, output);
  assert.match(output, /FIXED/);
  const patched = readFileSync(file, "utf8");
  assert.match(patched, /schemaFingerprint: "[0-9a-f]+"/);
});

test("sync-fingerprints: an unrelated real error is reported and exits non-zero, not silently skipped", (t) => {
  const file = join(FIXTURES_DIR, `tmp-${randomUUID()}.ts`);
  writeFileSync(file, 'throw new Error("boom: unrelated failure");\n');
  t.after(() => rmSync(file, { force: true }));

  const { status, output } = runScript(file);

  assert.equal(status, 1);
  assert.match(output, /FAIL/);
  assert.match(output, /boom: unrelated failure/);
});
