# Package boundary — never import your own package name from inside `zechinus/`

Read this before adding an export, touching `index.ts`/`react/index.ts`, or adding a new
adapter file.

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
(`zechinus/adapters/<name>.ts`) so importing `zechinus` for `defineStore` never drags
in Supabase, a Postgres driver, or the WebAuthn browser API. The React binding
(`useStore`/`tanstackAdapter`/...) is its own separate sub-entry, `zechinus/react`, for
the same reason (never pulls React into a non-React consumer). See README's "Package
boundary" section for the consumer-facing version of this rule.
