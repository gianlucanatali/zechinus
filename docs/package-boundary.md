# Package boundary — never import your own package name from inside `zechinus/`

Read this before adding an export, touching `index.ts`/`react/index.ts`, or adding a new
adapter file. Back to [README.md](../README.md).

`zechinus/` is a real npm package (`"name": "zechinus"`). When consumed via an npm
workspace (`"workspaces": ["zechinus"]` in the root `package.json`),
`node_modules/zechinus` is a real symlink, not a bundler path alias. It also has its
own standalone `tsconfig.json` (no `paths` at all, no reliance on a consumer's config).
Any file under `zechinus/` — including tests — must import the rest
of the package via **relative paths** (`../core/types.ts`, `./testKeyHandle.ts`), never
its own package name (`zechinus`/`zechinus/*`) — that specifier is only meaningful for
code OUTSIDE the package. Run `npm run typecheck` before declaring work done on
anything inside `zechinus/` — it type-checks the package standalone and fails
immediately if a file crossed this boundary by accident (this caught 4 real violations
the first time it was written).

Also: `zechinus` (the bare barrel, `index.ts`) exports **only `core/`** — never an
adapter. `supabaseStorageAdapter`, `pgStorageAdapter`, `webauthnKeyProvider`,
`mnemonicRecovery`, `workerKeyHandle` each live at their own file path
(`zechinus/adapters/<port>/<name>.ts`, grouped by port type since Task 1 of the
docs/adapters restructure — see [docs/adapters.md](adapters.md)) so importing `zechinus`
for `defineStore` never drags in Supabase, a Postgres driver, or the WebAuthn browser
API. The React binding (`useStore`/`tanstackAdapter`/...) is its own separate sub-entry,
`zechinus/react`, for the same reason (never pulls React into a non-React consumer). See
below for the consumer-facing version of this rule.

## A real npm workspace, not a path alias

`zechinus` is a real, standalone npm package (`"name": "zechinus"`) — a consuming app
takes a dependency on it exactly like any other npm package (see the README's
"Installation" section) and imports it as a bare specifier: `import { defineStore } from
"zechinus"`. There is **no bundler-specific path alias** — resolution goes entirely
through the package's own `exports` map. A consumer that happens to be a monorepo can
instead pull this package in as an npm workspace member (`node_modules/zechinus` becomes
a symlink instead of a real copy) — nothing about how you import from it changes either
way.

`zechinus/package.json`'s `exports` map governs what's importable from outside:

```json
"exports": {
  ".": "./index.ts",
  "./react": "./react/index.ts",
  "./node": "./node/index.ts",
  "./aggregate": "./aggregate/index.ts",
  "./adapters/*": "./adapters/*",
  "./core/*": "./core/*"
}
```

It also declares the real dependency split: `zod`/`@noble/ciphers`/`@noble/hashes` are
hard `dependencies` (the core needs them unconditionally); `@supabase/supabase-js`,
`react`, `@tanstack/react-query` are `peerDependencies`, all marked `optional: true` in
`peerDependenciesMeta` — a consumer using only `pgStorageAdapter` needs none of them
installed (`pgStorageAdapter` itself has zero package dependency at all, not even `pg` —
see above).

To make that real, **`zechinus` (the bare barrel, `index.ts`) exports ONLY `core/` —
zero adapters.** Importing `zechinus` for `defineStore` must never pull Supabase,
TanStack, or the WebAuthn browser API into the module graph. Import an adapter from its
own file instead — the same `.ts`-extension-inclusive style used everywhere else in this
codebase (`allowImportingTsExtensions`):

```ts
import { supabaseStorageAdapter } from "zechinus/adapters/storage/supabaseStorageAdapter.ts";
import { pgStorageAdapter } from "zechinus/adapters/storage/pgStorageAdapter.ts";
import { webauthnKeyProvider } from "zechinus/adapters/keyproviders/webauthnKeyProvider.ts";
import { mnemonicRecovery } from "zechinus/adapters/keyproviders/mnemonicRecovery.ts";
import { createWorkerKeyHandle } from "zechinus/adapters/keyhandles/workerKeyHandle.ts";
import { tanstackAdapter } from "zechinus/react"; // React binding only, not the bare barrel
```

**`zechinus/tsconfig.json`** is a second, standalone compiler config with no `paths` at
all — no reliance on the host app's `tsconfig.json`. It's the actual self-containment
check: if `zechinus/`'s own code (including its tests) only imports itself via relative
paths (`../core/...`, `./testKeyHandle.ts`, ...) — never its own package name — this
passes. Run it with `npm run typecheck`. Any file inside `zechinus/` that
imports `zechinus`/`zechinus/*` (its own external-facing package name, only meaningful
from OUTSIDE the package) instead of a relative path breaks this check — that's the
signal a boundary was crossed by accident.
