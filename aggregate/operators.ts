/**
 * `datacloak/aggregate` — descriptor factories for the SECOND, declarative form of
 * `defineAggregation`'s `compute` field (see `core/aggregation.ts`'s `ComputeFn` doc
 * comment). Calling `sum(...)`/`sumWith(...)`/`expr(...)`/`lastDelta(...)`/`custom(...)`
 * does NOT compute anything — each just returns a plain descriptor object; `compile.ts`'s
 * `compileFieldOperators` is what turns a `Record<string, FieldOperator>` into a single
 * function shaped exactly like the pure-function `compute` form.
 *
 * Deliberately ONLY these five operators (YAGNI — see the plan): no `avg`/`count`/`min`/
 * `max`/`groupBy`, however tempting in the abstract. None of them contain domain logic —
 * `sumWith`/`custom` are iterators/escape-hatches that call a `fn` the CALLER supplies
 * (typically from `shared/domain/*`); this module never computes a real-world formula
 * itself.
 */

/** A single row read from a source array/collection — loosely typed on purpose (this
 * kit has no static knowledge of a source's actual schema, see `README.md`'s note on
 * `defineAggregation`'s `TSources` generic being resolved at the `sources` boundary, not
 * inside a field operator). */
export type Row = Record<string, unknown>;

interface WhereFilter {
  /** Optional exact-match filter — a row is kept only if EVERY listed field equals the
   * given value (`===`), never a partial/fuzzy match. */
  where?: Partial<Row>;
}

export interface SumOperator extends WhereFilter {
  readonly kind: "sum";
  readonly sourceName: string;
  readonly field: string;
}

export interface SumWithOperator extends WhereFilter {
  readonly kind: "sumWith";
  readonly sourceName: string;
  readonly fn: (row: Row) => number;
}

export interface ExprOperator {
  readonly kind: "expr";
  /** Receives the aggregate's OTHER fields, already computed — never the raw sources.
   * `compile.ts` resolves the dependency order via retry (see its doc comment), so this
   * `fn` can freely reference any other field regardless of declaration order in the
   * `compute` record literal. */
  readonly fn: (fields: Record<string, unknown>) => unknown;
}

export interface LastDeltaOperator {
  readonly kind: "lastDelta";
  readonly sourceName: string;
  readonly field: string;
}

export interface CustomOperator {
  readonly kind: "custom";
  /** Escape hatch: receives the fields already computed by every OTHER operator in this
   * record, plus the raw `sources` object — `fn` itself must be the caller's real domain
   * function (e.g. `computeEffScore` from `shared/domain/*`), never inline logic here. */
  readonly fn: (
    fields: Record<string, unknown>,
    sources: Record<string, unknown>,
  ) => unknown;
}

export type FieldOperator =
  | SumOperator
  | SumWithOperator
  | ExprOperator
  | LastDeltaOperator
  | CustomOperator;

export type FieldOperatorsRecord = Record<string, FieldOperator>;

/** Sums `field` across every row of the `sourceName` source, optionally restricted to
 * rows matching `where` exactly. */
export function sum(
  sourceName: string,
  field: string,
  opts?: { where?: Partial<Row> },
): SumOperator {
  return { kind: "sum", sourceName, field, where: opts?.where };
}

/** Like `sum`, but the per-row value comes from `fn(row)` instead of reading `field`
 * directly — for reductions that need real logic (e.g. "residual debt as of now"). That
 * logic belongs to the caller's `fn` (typically `shared/domain/*`), never to this
 * operator. */
export function sumWith(
  sourceName: string,
  fn: (row: Row) => number,
  opts?: { where?: Partial<Row> },
): SumWithOperator {
  return { kind: "sumWith", sourceName, fn, where: opts?.where };
}

/** The field's value is `fn` applied to the aggregate's OTHER already-computed fields —
 * dependencies are resolved in topological order regardless of declaration order; a
 * cycle fails with a context-carrying error (see `compile.ts`). */
export function expr(
  fn: (fields: Record<string, unknown>) => unknown,
): ExprOperator {
  return { kind: "expr", fn };
}

/** Reads `field` off the LAST row of `sourceName` — typically an ordered time series
 * (e.g. "the latest net-worth delta"). Fails fast if the source has no rows at all. */
export function lastDelta(
  sourceName: string,
  field: string,
): LastDeltaOperator {
  return { kind: "lastDelta", sourceName, field };
}

/** Escape hatch for anything the other four operators don't cover. `fn` is the caller's
 * real domain function — this operator is only ever a pass-through, never a place to
 * inline a formula. */
export function custom(
  fn: (
    fields: Record<string, unknown>,
    sources: Record<string, unknown>,
  ) => unknown,
): CustomOperator {
  return { kind: "custom", fn };
}
