/**
 * `compileFieldOperators` — turns a declarative `Record<string, FieldOperator>` (built
 * from `operators.ts`'s `sum`/`sumWith`/`expr`/`lastDelta`/`custom`) into a plain function
 * shaped exactly like `core/aggregation.ts`'s pure-function `ComputeFn` — the SAME shape
 * `defineAggregation`'s `compute` field already accepted before this module existed. This
 * is a one-time, definition-time compile-to-function (see `defineAggregation`'s doc
 * comment on `AggregationDef.compute`); the core never runs a second, different code path
 * for the two forms.
 *
 * Only `import type` reaches back into `core/aggregation.ts` from here (erased at build)
 * — so `core/aggregation.ts` importing THIS module's `compileFieldOperators` as a runtime
 * value creates no real circular module dependency, only a type-only one.
 */
import type { z } from "zod";
import type { ComputeFn, ExternalInput, Source } from "../core/aggregation.ts";
import type { FieldOperator, FieldOperatorsRecord, Row } from "./operators.ts";

/** The declarative form of `compute` — one operator per output field. `_TSources`/`_TExt`
 * are carried only for parity with the pure-function `ComputeFn<TSchema, TSources, TExt>`
 * signature (so `AggregationDef.compute`'s union has matching arity on both sides); this
 * kit itself resolves everything by plain string keys at runtime, deliberately not
 * cross-checked against a source's real schema (see `operators.ts`'s `Row` doc comment). */
export type FieldOperators<
  TSchema extends z.ZodType,
  _TSources extends Record<string, Source> = Record<string, Source>,
  _TExt extends Record<string, ExternalInput<any>> = Record<string, never>,
> = {
  [K in keyof z.infer<TSchema>]: FieldOperator;
};

/** Internal control-flow signal used ONLY inside this function's `expr` resolution loop
 * below — never thrown across this module's public boundary, never caught anywhere
 * else. Any OTHER error thrown by a caller-supplied `fn` (a real bug, a typo'd field
 * name, bad input data) propagates as-is — never swallowed, per AGENTS.md's "no silent
 * catch" rule. */
class FieldNotReadyError extends Error {
  constructor(readonly fieldName: string) {
    super(`field "${fieldName}" not computed yet`);
  }
}

function matchesWhere(row: Row, where: Partial<Row> | undefined): boolean {
  if (!where) return true;
  return Object.entries(where).every(([key, value]) => row[key] === value);
}

function asFiniteNumber(value: unknown, context: string): number {
  const n = typeof value === "number" ? value : Number(value);
  if (!Number.isFinite(n)) {
    throw new Error(
      `aggregate.${context}: expected a finite number, got ${JSON.stringify(value)}.`,
    );
  }
  return n;
}

function readRows(
  sources: Record<string, unknown>,
  sourceName: string,
  opName: string,
): Row[] {
  const rows = sources[sourceName];
  if (!Array.isArray(rows)) {
    throw new Error(
      `aggregate.${opName}: source "${sourceName}" is not an array (got ${typeof rows}) — ` +
        `${opName} only supports array/collection sources.`,
    );
  }
  return rows as Row[];
}

/**
 * Compiles the declarative record into a `ComputeFn`. Resolution happens in three
 * phases, run in this fixed order every time the compiled function is called:
 *
 *  1. `sum`/`sumWith`/`lastDelta` — read directly from the raw `sources`, no dependency
 *     on any other field, so these always resolve first regardless of declaration order.
 *  2. `expr` — each may reference any OTHER field (from phase 1 or another `expr`).
 *     Resolved via retry: repeatedly attempt every still-pending `expr` field; a field
 *     whose `fn` touches a not-yet-computed field throws internally (caught, deferred to
 *     the next pass); a pass that makes zero progress with fields still pending means a
 *     cycle — thrown as a real error naming every field still stuck (never a hang).
 *  3. `custom` — the escape hatch, run LAST (in declaration order) once every other field
 *     is computed, so `fn(fields, sources)` always sees "everything else" as promised by
 *     the operator's doc comment.
 *
 * Note: an `expr` cannot depend on a `custom` field — `custom` runs strictly after phase
 * 2, so that field never becomes available during the retry loop, and the loop reports it
 * the same way it reports a genuine cycle (a real field name, never a hang or a silent
 * `undefined`). If this ordering constraint ever needs lifting, it is a deliberate,
 * separate change — not a bug in this phase's retry logic.
 */
export function compileFieldOperators<
  TSchema extends z.ZodType,
  TSources extends Record<string, Source> = Record<string, Source>,
  TExt extends Record<string, ExternalInput<any>> = Record<string, never>,
>(operators: FieldOperatorsRecord): ComputeFn<TSchema, TSources, TExt> {
  const fieldNames = Object.keys(operators);

  return ({ sources }) => {
    const rawSources = sources as unknown as Record<string, unknown>;
    const computed: Record<string, unknown> = {};
    const exprNames: string[] = [];
    const customNames: string[] = [];

    // ── Phase 1: sum / sumWith / lastDelta ──────────────────────────────────────────
    for (const name of fieldNames) {
      const op: FieldOperator = operators[name];
      switch (op.kind) {
        case "sum": {
          const rows = readRows(rawSources, op.sourceName, "sum").filter((r) =>
            matchesWhere(r, op.where),
          );
          computed[name] = rows.reduce(
            (acc, row) =>
              acc +
              asFiniteNumber(
                row[op.field],
                `sum("${op.sourceName}", "${op.field}")`,
              ),
            0,
          );
          break;
        }
        case "sumWith": {
          const rows = readRows(rawSources, op.sourceName, "sumWith").filter(
            (r) => matchesWhere(r, op.where),
          );
          computed[name] = rows.reduce(
            (acc, row) =>
              acc + asFiniteNumber(op.fn(row), `sumWith("${op.sourceName}")`),
            0,
          );
          break;
        }
        case "lastDelta": {
          const rows = readRows(rawSources, op.sourceName, "lastDelta");
          if (rows.length === 0) {
            throw new Error(
              `aggregate.lastDelta: source "${op.sourceName}" has no rows — cannot read ` +
                `field "${op.field}" from its last element.`,
            );
          }
          computed[name] = rows[rows.length - 1][op.field];
          break;
        }
        case "expr":
          exprNames.push(name);
          break;
        case "custom":
          customNames.push(name);
          break;
      }
    }

    // ── Phase 2: expr, topological (retry-based) ────────────────────────────────────
    const pending = new Set(exprNames);
    const fieldsProxy = new Proxy(computed, {
      get(target, prop) {
        if (typeof prop !== "string") return undefined;
        if (prop in target) return target[prop];
        if (fieldNames.includes(prop)) throw new FieldNotReadyError(prop);
        throw new Error(
          `aggregate.expr: field "${prop}" is not declared in this aggregate's compute record.`,
        );
      },
    });
    while (pending.size > 0) {
      let progressed = false;
      for (const name of pending) {
        const op = operators[name] as ExprOperatorLike;
        try {
          computed[name] = op.fn(fieldsProxy);
          pending.delete(name);
          progressed = true;
        } catch (e) {
          if (!(e instanceof FieldNotReadyError)) throw e;
          // Still blocked on `e.fieldName` — retried next pass.
        }
      }
      if (!progressed) {
        throw new Error(
          `aggregate.expr: circular dependency detected among fields: ${[...pending].join(", ")}.`,
        );
      }
    }

    // ── Phase 3: custom, escape hatch, runs last ────────────────────────────────────
    for (const name of customNames) {
      const op = operators[name] as CustomOperatorLike;
      computed[name] = op.fn({ ...computed }, rawSources);
    }

    return computed as z.infer<TSchema>;
  };
}

// Narrow local aliases so the phase-2/3 loops above don't need a `switch` just to
// satisfy the compiler about which member of `FieldOperator` they're holding — `kind`
// was already checked when each name was queued into `exprNames`/`customNames`.
type ExprOperatorLike = { fn: (fields: Record<string, unknown>) => unknown };
type CustomOperatorLike = {
  fn: (
    fields: Record<string, unknown>,
    sources: Record<string, unknown>,
  ) => unknown;
};
