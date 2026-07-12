# Porting an existing table (legacy AAD)

Read this only when porting an existing table that already has data encrypted under a
different AAD convention than DataCloak's canonical one — omit entirely for a brand-new
store.

Declare `legacyAAD: (dek, rowKey) => ({...})` on `defineStore` — a function returning the
FULL old AAD (not just the `field` piece; it can differ in `rowId` too, e.g. an old table
that pinned `rowId: pid` for what is now a `perKey` store). The framework never guesses at
historical conventions — the caller supplies the complete old shape.

Behavior: **read-old-if-needed, always-write-canonical**, same pattern as
`version`/migrators. Every read tries the canonical AAD first — that's the only attempt
in the common case (new data, or an already-migrated row), one decrypt, forever. Only on
failure does it retry under `legacyAAD`; a successful legacy decrypt is immediately
re-encrypted under canonical AAD and persisted — that row converges permanently from then
on. Writes (`save`/`create`/`update`) ALWAYS use canonical AAD, never the legacy one. If
both attempts fail, the canonical error propagates (never masked). No live migration
script needed — rows convert lazily, one at a time, exactly when touched.

The underlying primitive, `migrateLegacyAAD` (still exported for one-shot scripts outside
the `defineStore` read path), does only the generic decrypt-old/re-encrypt-new mechanics;
a record that exists with a missing/malformed blob throws — never reported as
`migrated: false` (reserved for a genuinely absent record).
