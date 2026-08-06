// tsc doesn't rename .js -> .cjs, and with "type": "module" Node tells CJS from ESM by extension.
// Renaming the files alone isn't enough: tsc's own emitted `require("./foo.js")` calls
// (from `rewriteRelativeImportExtensions`, inherited from tsconfig.build.json) still say
// `.js` — real bug found running this for the first time, not something `tsc` warns about,
// since the ORIGINAL .js files (that the require calls correctly pointed to) simply don't
// exist anymore once renamed. Every relative require needs the same `.js` -> `.cjs` rewrite
// the filenames just got.
import { readdir, readFile, writeFile, rename } from "node:fs/promises";
import { join } from "node:path";

async function collectJsFiles(dir, out = []) {
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) await collectJsFiles(full, out);
    else if (entry.name.endsWith(".js")) out.push(full);
  }
  return out;
}

const jsFiles = await collectJsFiles("./dist-cjs");

for (const file of jsFiles) {
  const source = await readFile(file, "utf8");
  const rewritten = source.replace(
    /require\((["'])(\.[^"']+)\.js\1\)/g,
    (_match, quote, specifier) => `require(${quote}${specifier}.cjs${quote})`,
  );
  if (rewritten !== source) await writeFile(file, rewritten, "utf8");
}

for (const file of jsFiles) {
  await rename(file, file.replace(/\.js$/, ".cjs"));
}

console.log(`Renamed dist-cjs/**/*.js -> *.cjs (${jsFiles.length} files, requires rewritten)`);
