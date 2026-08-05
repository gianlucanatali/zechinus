# Package boundary — never import your own package name from inside `datacloak/`

Read this before adding an export, touching `index.ts`/`react/index.ts`, or adding a new
adapter file.

`datacloak/` is a real npm package (`"name": "datacloak"`). When consumed via an npm
workspace (`"workspaces": ["datacloak"]` in the root `package.json`),
`node_modules/datacloak` is a real symlink, not a bundler path alias. It also has its
own standalone `tsconfig.json` (no `paths` at all, no reliance on a consumer's config).
Any file under `datacloak/` — including tests — must import the rest
of the package via **relative paths** (`../core/types.ts`, `./testKeyHandle.ts`), never
its own package name (`datacloak`/`datacloak/*`) — that specifier is only meaningful for
code OUTSIDE the package. Run `npm run datacloak:typecheck` before declaring work done on
anything inside `datacloak/` — it type-checks the package standalone and fails
immediately if a file crossed this boundary by accident (this caught 4 real violations
the first time it was written).

Also: `datacloak` (the bare barrel, `index.ts`) exports **only `core/`** — never an
adapter. `supabaseStorageAdapter`, `pgStorageAdapter`, `webauthnKeyProvider`,
`mnemonicRecovery`, `workerKeyHandle` each live at their own file path
(`datacloak/adapters/<name>.ts`) so importing `datacloak` for `defineStore` never drags
in Supabase, a Postgres driver, or the WebAuthn browser API. The React binding
(`useStore`/`tanstackAdapter`/...) is its own separate sub-entry, `datacloak/react`, for
the same reason (never pulls React into a non-React consumer). See README's "Package
boundary" section for the consumer-facing version of this rule.
