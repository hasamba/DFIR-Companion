/**
 * The server's heavy-read gate with its memory budget and its coalescer (#2846), built from the
 * route context: the forensic index counts a case's events (the count the import memory guard uses),
 * and admitted imports' reservations count against the budget. Without a state store (some tests)
 * the gate is the count-only gate it was before.
 */
import type { Express } from "express";
import type { RouteContext } from "../routes/context.js";
import { HeavyReadGate, mountHeavyReadGate } from "./heavyReadGate.js";
import { HeavyReadCoalescer } from "./heavyReadCoalescer.js";
import { createHeavyReadBudget } from "./heavyReadMemoryBudget.js";

export function mountCaseHeavyReadGate(app: Express, ctx: RouteContext): void {
  const stateStore = ctx.options.stateStore;
  if (!stateStore) return mountHeavyReadGate(app);
  const guard = ctx.options.importMemoryGuard;
  const budget = createHeavyReadBudget({
    countEvents: async (caseId) =>
      (await stateStore.queryForensicTimeline(caseId, { limit: 1, includeTotal: true })).total,
    importReservedBytes: guard ? () => guard.reservedBytes() : undefined,
  });
  mountHeavyReadGate(app, new HeavyReadGate(undefined, budget), new HeavyReadCoalescer());
}
