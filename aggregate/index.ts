/**
 * `zechinus/aggregate` — public entry point for the declarative operator kit (Task 3
 * of the "aggregazioni dichiarative persistite" plan): a SECOND, declarative form of
 * `defineAggregation`'s `compute` field, alongside the pure-function form `core/
 * aggregation.ts` already accepted. Standalone sub-entry, same pattern as `zechinus/
 * react` and `zechinus/node` — importing `zechinus` for just `defineStore`/
 * `defineAggregation` never pulls this in, and vice versa.
 *
 * Usage (see the plan's target example):
 *
 * ```ts
 * import * as agg from "zechinus/aggregate";
 *
 * defineAggregation({
 *   // ...
 *   compute: {
 *     liquidita: agg.sum("banche", "saldo"),
 *     immobili: agg.sum("assets", "valore", { where: { tipo: "immobile" } }),
 *     totaleAttivi: agg.expr((f) => f.liquidita + f.immobili),
 *     varEur: agg.lastDelta("storicoPatrimonio", "valore"),
 *     effScore: agg.custom((f, src) => computeEffScore(f)),
 *   },
 * });
 * ```
 */
export {
  sum,
  sumWith,
  expr,
  lastDelta,
  custom,
  type Row,
  type FieldOperator,
  type FieldOperatorsRecord,
  type SumOperator,
  type SumWithOperator,
  type ExprOperator,
  type LastDeltaOperator,
  type CustomOperator,
} from "./operators.ts";

export { compileFieldOperators, type FieldOperators } from "./compile.ts";
