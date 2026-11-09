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
    // Seven DISTINCT rows (different source addresses): matching rows would merge in detail (#2502).
    for (let i = 0; i < 7; i++)
      b.route(row("Medium", "admin@example.com", `192.0.2.${i + 1}`), facts("admin@example.com"));
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

  it("leaves a one-row detailed group's description untouched (#2475)", () => {
    const b = createOutputBudget({ budgets: small() });
    const input = row("Low", "a");
    b.route(input, facts("a"));
    const { aggregates, disclosure } = b.finish();
    expect(aggregates).toHaveLength(1);
    expect(aggregates[0].description).toBe(input.description);
    expect(aggregates[0].description).not.toContain("[aggregated:");
    expect(disclosure.aggregatedRows.low).toBe(1);
    expect(disclosure.groups.detailed).toBe(1);
  });

  it("keeps the note on a detailed group of two or more rows (#2475)", () => {
    const b = createOutputBudget({ budgets: small() });
    b.route(row("Low", "a"), facts("a"));
    b.route(row("Low", "a"), facts("a"));
    const { aggregates } = b.finish();
    expect(aggregates).toHaveLength(1);
    expect(aggregates[0].description).toContain("[aggregated: 2 row(s)");
    expect(aggregates[0].description).toContain("Low rows are aggregated");
  });

  it("keeps the note on a one-row coarse group (#2475)", () => {
    const b = createOutputBudget({ budgets: small({ aggregateGroupsMax: 0 }) });
    b.route(row("Low", "a"), facts("a"));
    const { aggregates, disclosure } = b.finish();
    expect(disclosure.groups.coarse).toBe(1);
    expect(aggregates[0].description).toContain("[aggregated: 1 row(s)");
  });

  it("drops rows below the import floor and counts them", () => {
    const b = createOutputBudget({ budgets: small(), minSeverity: "Medium" });
    expect(b.route(row("Low", "a"), facts("a"))).toBe("below-floor");
    expect(b.finish().disclosure.belowFloor).toBe(1);
  });

  describe("matching Medium rows merge in detail, like a small-file import (#2502)", () => {
    const at = (r: MappedEvent, timestamp: string, ref?: string): MappedEvent => ({
      ...r,
      timestamp,
      ...(ref ? { recordRefs: [ref], sourceRecordId: ref } : {}),
    });

    it("13 rows sharing one grouping key become one counted row with the full span", () => {
      const b = createOutputBudget({ budgets: small({ mediumPerRuleActor: 25 }) });
      // Newest-first, as Entra exports arrive.
      for (let i = 12; i >= 0; i--) {
        const t = `2026-11-07T${String(8 + i).padStart(2, "0")}:00:00Z`;
        expect(b.route(at(row("Medium", "user@example.com"), t), facts("user@example.com"))).toBe("forensic");
      }
      const { individual, aggregates, disclosure } = b.finish();
      expect(aggregates).toHaveLength(0);
      expect(individual).toHaveLength(1);
      expect(individual[0].count).toBe(13);
      expect(individual[0].timestamp).toBe("2026-11-07T08:00:00Z");
      expect(individual[0].endTimestamp).toBe("2026-11-07T20:00:00Z");
      expect(individual[0].description).not.toContain("[aggregated:");
      expect(disclosure.individual.medium).toBe(13);
      expect(disclosure.mediumMerged).toBe(12);
    });

    it("a merged row spends the budget once, so the next distinct row still fits", () => {
      const b = createOutputBudget({ budgets: small({ mediumPerRuleActor: 2 }) });
      for (let i = 0; i < 5; i++) b.route(row("Medium", "u", "192.0.2.1"), facts("u"));
      expect(b.route(row("Medium", "u", "192.0.2.2"), facts("u"))).toBe("forensic");
      expect(b.route(row("Medium", "u", "192.0.2.3"), facts("u"))).toBe("aggregate");
      const { individual, aggregates, disclosure } = b.finish();
      expect(individual.map((e) => e.count ?? 1).sort()).toEqual([1, 5]);
      expect(aggregates).toHaveLength(1);
      expect(disclosure.mediumOverflow.ruleActorBudget).toBe(1);
    });

    it("a matching row after both budgets are spent joins its detail row, not an overflow group", () => {
      const b = createOutputBudget({ budgets: small({ mediumPerRuleActor: 1, mediumMax: 1 }) });
      b.route(row("Medium", "u", "192.0.2.1"), facts("u"));
      expect(b.route(row("Medium", "u", "192.0.2.9"), facts("u"))).toBe("aggregate");
      expect(b.route(row("Medium", "v", "192.0.2.9"), facts("v"))).toBe("aggregate");
      expect(b.route(row("Medium", "u", "192.0.2.1"), facts("u"))).toBe("forensic");
      const { individual, aggregates } = b.finish();
      expect(individual).toHaveLength(1);
      expect(individual[0].count).toBe(2);
      expect(aggregates.reduce((n, e) => n + (e.count ?? 1), 0)).toBe(2);
    });

    it("the per-import budget counts distinct rows", () => {
      const b = createOutputBudget({ budgets: small({ mediumPerRuleActor: 100, mediumMax: 3 }) });
      for (let i = 0; i < 9; i++) b.route(row("Medium", `u${i % 3}`), facts(`u${i % 3}`));
      const { individual, aggregates, disclosure } = b.finish();
      expect(individual).toHaveLength(3);
      expect(aggregates).toHaveLength(0);
      expect(disclosure.mediumOverflow.importBudget).toBe(0);
    });

    it("merges by the importer's grouping key, not strict identity — the first row is shown", () => {
      const b = createOutputBudget({ budgets: small() });
      const first = { ...row("Medium", "u"), description: "Set-Mailbox on mailbox-a by u" };
      const second = { ...row("Medium", "u"), description: "Set-Mailbox on mailbox-b by u" };
      b.route(first, facts("u"));
      b.route(second, facts("u"));
      const { individual } = b.finish();
      expect(individual).toHaveLength(1);
      expect(individual[0].count).toBe(2);
      expect(individual[0].description).toBe("Set-Mailbox on mailbox-a by u");
    });

    it("keeps every member's record in the provenance relation, even past both budgets", () => {
      const members: { group: string; ref: string }[] = [];
      const b = createOutputBudget({
        budgets: small({ mediumPerRuleActor: 1, mediumMax: 1 }),
        provenance: {
          groupOf: (k) => `g:${k}`,
          onMember: (group, ref) => members.push({ group, ref }),
        },
      });
      for (let i = 0; i < 14; i++)
        b.route(
          at(row("Medium", "u"), `2026-11-07T${String(10 + (i % 5)).padStart(2, "0")}:00:00Z`, `rec-${i}`),
          facts("u"),
        );
      const { individual } = b.finish();
      expect(individual).toHaveLength(1);
      const e = individual[0];
      expect(e.count).toBe(14);
      expect(e.sourceRecordId).toBeUndefined();
      expect(e.sourceRecords?.count).toBe(14);
      expect(e.sourceRecords?.refs.length).toBeLessThanOrEqual(10);
      expect(new Set(members.map((m) => m.group)).size).toBe(1);
      expect(members.map((m) => m.ref)).toEqual(Array.from({ length: 14 }, (_, i) => `rec-${i}`));
      expect(e.timestamp).toBe("2026-11-07T10:00:00Z");
      expect(e.endTimestamp).toBe("2026-11-07T14:00:00Z");
    });

    it("Critical and High rows sharing a key still stay one event each", () => {
      const b = createOutputBudget({ budgets: small() });
      for (let i = 0; i < 4; i++) b.route(row("High", "u"), facts("u"));
      expect(b.finish().individual).toHaveLength(4);
    });
  });

  it("names the default budgets from the constants", () => {
    expect(defaultBudgets(7)).toMatchObject({ mediumMax: MEDIUM_INDIVIDUAL_MAX, superRows: 7 });
  });
});
