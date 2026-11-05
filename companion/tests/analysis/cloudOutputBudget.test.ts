import { describe, it, expect } from "vitest";
import {
  createOutputBudget,
  defaultBudgets,
  type OutputBudgets,
} from "../../src/analysis/cloudOutputBudget.js";
import type { MappedEvent } from "../../src/analysis/siemImport.js";
import type { Severity } from "../../src/analysis/stateTypes.js";
import { MEDIUM_INDIVIDUAL_MAX } from "../../src/analysis/cloudStreamLimits.js";

// #2303 — the bounded output: Critical/High individual, Medium budgeted, Low/Info aggregated, every
// step counted in the disclosure.

const row = (severity: Severity, user: string, ip = "192.0.2.1", op = "UserLoginFailed"): MappedEvent => ({
  timestamp: "2026-10-01T00:00:00Z",
  description: `M365 AzureActiveDirectory: ${op} by ${user} from ${ip}`,
  severity,
  mitre: [],
  aggKey: `m365|aad|${op}|${user}|${ip}`.toLowerCase(),
});
const facts = (user: string, ip = "192.0.2.1", op = "UserLoginFailed") => ({ rule: op, actor: user, ip });
const small = (over: Partial<OutputBudgets> = {}): OutputBudgets => ({
  mediumPerRuleActor: 2,
  mediumMax: 10,
  aggregateGroupsMax: 5,
  coarseGroupsMax: 3,
  superRows: 4,
  ...over,
});

describe("createOutputBudget (#2303)", () => {
  it("keeps every Critical and High row individually, whatever the budgets", () => {
    const b = createOutputBudget({ budgets: small({ mediumMax: 0 }) });
    for (let i = 0; i < 50; i++)
      b.route(row(i % 2 ? "High" : "Critical", "admin@example.com"), facts("admin@example.com"));
    const { individual, aggregates, disclosure } = b.finish();
    expect(individual).toHaveLength(50);
    expect(aggregates).toHaveLength(0);
    expect(disclosure.individual).toEqual({ critical: 25, high: 25, medium: 0 });
  });

  it("bounds a spray against a million distinct accounts: budgeted individuals, then per-address groups", () => {
    const b = createOutputBudget({ budgets: small() });
    const ips = ["192.0.2.1", "192.0.2.2", "198.51.100.3"];
    for (let i = 0; i < 1_000; i++) {
      const u = `spray${i}@example.com`;
      b.route(row("Medium", u, ips[i % 3]), facts(u, ips[i % 3]));
    }
    const { individual, aggregates, disclosure } = b.finish();
    expect(individual).toHaveLength(10); // mediumMax
    expect(aggregates).toHaveLength(3); // one per (rule, source address)
    expect(aggregates.reduce((n, e) => n + (e.count ?? 1), 0)).toBe(990);
    expect(disclosure.mediumOverflow).toEqual({ ruleActorBudget: 0, importBudget: 990 });
    expect(aggregates[0].description).toMatch(
      /^UserLoginFailed from 192\.0\.2\.\d|^UserLoginFailed from 198/,
    );
    expect(aggregates[0].description).toContain("Medium budget for this import reached");
  });

  it("aggregates one heavy actor's Medium rows per (rule, actor) once its budget is spent", () => {
    const b = createOutputBudget({ budgets: small() });
    for (let i = 0; i < 7; i++) b.route(row("Medium", "admin@example.com"), facts("admin@example.com"));
    const { individual, aggregates, disclosure } = b.finish();
    expect(individual).toHaveLength(2);
    expect(aggregates).toHaveLength(1);
    expect(aggregates[0].count).toBe(5);
    expect(aggregates[0].description).toContain("Medium budget per rule and actor reached");
    expect(disclosure.mediumOverflow.ruleActorBudget).toBe(5);
  });

  it("writes Info to the super-timeline while room lasts, then aggregates, then falls back to coarse groups", () => {
    const b = createOutputBudget({
      budgets: small({ superRows: 4, aggregateGroupsMax: 2, coarseGroupsMax: 1 }),
    });
    const decisions = Array.from({ length: 12 }, (_, i) =>
      b.route(
        row("Info", `u${i}@example.com`, "192.0.2.9", i % 2 ? "FileAccessed" : "UserLoggedIn"),
        facts(`u${i}`, "", i % 2 ? "FileAccessed" : "UserLoggedIn"),
      ),
    );
    expect(decisions.slice(0, 4)).toEqual(["super", "super", "super", "super"]);
    expect(decisions.slice(4).every((x) => x === "aggregate")).toBe(true);
    const { aggregates, disclosure } = b.finish();
    expect(disclosure.superIndividual).toBe(4);
    expect(disclosure.superBudgetExceeded).toBe(8);
    expect(disclosure.groups).toEqual({ detailed: 2, coarse: 1, catchAll: 1 });
    expect(aggregates.reduce((n, e) => n + (e.count ?? 1), 0)).toBe(8);
  });

  it("aggregates Low rows in the forensic record and also offers them to the super-timeline", () => {
    const b = createOutputBudget({ budgets: small() });
    expect(b.route(row("Low", "a"), facts("a"))).toBe("super+aggregate");
    expect(b.finish().aggregates).toHaveLength(1);
  });

  it("drops rows below the import floor and counts them", () => {
    const b = createOutputBudget({ budgets: small(), minSeverity: "Medium" });
    expect(b.route(row("Low", "a"), facts("a"))).toBe("below-floor");
    expect(b.finish().disclosure.belowFloor).toBe(1);
  });

  it("names the default budgets from the constants", () => {
    expect(defaultBudgets(7)).toMatchObject({ mediumMax: MEDIUM_INDIVIDUAL_MAX, superRows: 7 });
  });
});
