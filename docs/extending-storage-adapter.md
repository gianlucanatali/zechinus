# Extending `StorageAdapter`

Read this before adding a capability the current adapters don't have (a new way to
address rows, a new batch operation, etc).

If a new access pattern needs a capability the adapter doesn't have:

1. Add the method as **optional** (`method?:`) on `StorageAdapter` in `core/types.ts` —
   never required, so existing adapters keep compiling.
2. Implement it in `adapters/supabaseStorageAdapter.ts` (or your own adapter). Any
   query/update/delete should filter by the owning user id explicitly, even when
   row-level security also enforces it — index usage, not just correctness.
3. In `defineStore` (`core/store.ts`), the code path using the new capability must throw an
   explicit, descriptive error if `storage.<method>` is undefined — mirror the existing
   pattern (`the configured adapter doesn't support 'many' (list missing)`). Never
   silently no-op or fall back.
4. Write a TDD test in `tests/` **before** the implementation: an in-memory `StorageAdapter`
   double (copy the pattern from `defineStoreMany.test.ts` or `defineStorePerKey.test.ts`),
   4+ cases (roundtrip, AAD-per-row not movable across rows/keys/ids,
   adapter-missing-capability → explicit error, Zod validation rejects bad writes).

`getHashesByKeys` (`core/types.ts`) is a real, already-shipped example of this exact
recipe — a batch hash-only read for several keys of one `perKey` store in one round trip,
implemented in both shipped adapters (`supabaseStorageAdapter.ts`/`pgStorageAdapter.ts`),
consumed by `defineAggregation`'s cold-session check (see `aggregation-extras.md`). Use it
as the template.
