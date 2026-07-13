import { describe, it, expect } from "vitest";
import {
  compileRuleset,
  matchEvent,
  MATCHABLE_FIELDS,
  type CompiledRule,
} from "../../src/analysis/taggerRules.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

function ev(p: Partial<ForensicEvent> & { id: string }): ForensicEvent {
  return {
    timestamp: "2026-06-01T00:00:00Z",
    description: "d",
    severity: "Info",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    ...p,
  };
}

// Compile a single rule and return it (rulesets are keyed by id).
function one(rule: unknown): CompiledRule {
  return compileRuleset({ r: rule }).rules[0];
}

describe("compileRuleset — validation", () => {
  it("rejects an unknown field (load error, not a silent no-op)", () => {
    expect(() =>
      compileRuleset({ r: { any: [{ field: "key_path", contains: "x" }], tags: ["t"] } }),
    ).toThrow(/key_path/);
  });

  it("lists a valid ForensicEvent field in MATCHABLE_FIELDS", () => {
    expect(MATCHABLE_FIELDS).toContain("message");
    expect(MATCHABLE_FIELDS).toContain("sources");
    expect(MATCHABLE_FIELDS).toContain("port");
  });

  it("rejects a rule with no condition block", () => {
    expect(() => compileRuleset({ r: { tags: ["t"] } })).toThrow();
  });

  it("rejects a rule with no action (nothing to apply)", () => {
    expect(() => compileRuleset({ r: { any: [{ field: "message", contains: "x" }] } })).toThrow();
  });

  it("rejects a condition with two operators", () => {
    expect(() =>
      compileRuleset({ r: { any: [{ field: "message", contains: "a", equals: "b" }], tags: ["t"] } }),
    ).toThrow();
  });

  it("rejects a condition with no operator", () => {
    expect(() =>
      compileRuleset({ r: { any: [{ field: "message" }], tags: ["t"] } }),
    ).toThrow();
  });

  it("rejects an invalid regex pattern", () => {
    expect(() =>
      compileRuleset({ r: { any: [{ field: "message", regex: "(" }], tags: ["t"] } }),
    ).toThrow();
  });

  it("rejects an invalid severity", () => {
    expect(() =>
      compileRuleset({ r: { any: [{ field: "message", contains: "x" }], severity: "Nope" } }),
    ).toThrow();
  });

  it("accepts a well-formed ruleset and preserves rule ids", () => {
    const rs = compileRuleset({
      win_service: { any: [{ field: "message", contains: ["7045", "4697"] }], tags: ["persistence"] },
    });
    expect(rs.rules).toHaveLength(1);
    expect(rs.rules[0].id).toBe("win_service");
  });
});

describe("matchEvent — operators", () => {
  it("contains is case-insensitive and a list is OR", () => {
    const r = one({ any: [{ field: "message", contains: ["7045", "4697"] }], tags: ["t"] });
    expect(matchEvent(ev({ id: "e", message: "Service ID 7045 installed" }), r)).toBe(true);
    expect(matchEvent(ev({ id: "e", message: "event 4697 here" }), r)).toBe(true);
    expect(matchEvent(ev({ id: "e", message: "nothing" }), r)).toBe(false);
  });

  it("equals matches a scalar field exactly (case-insensitive)", () => {
    const r = one({ any: [{ field: "severity", equals: "High" }], tags: ["t"] });
    expect(matchEvent(ev({ id: "e", severity: "High" }), r)).toBe(true);
    expect(matchEvent(ev({ id: "e", severity: "Low" }), r)).toBe(false);
  });

  it("contains/equals scan each element of an array field (sources)", () => {
    const r = one({ any: [{ field: "sources", equals: "Chainsaw" }], tags: ["t"] });
    expect(matchEvent(ev({ id: "e", sources: ["EVTX", "Chainsaw"] }), r)).toBe(true);
    expect(matchEvent(ev({ id: "e", sources: ["EVTX"] }), r)).toBe(false);
  });

  it("regex honours flags", () => {
    const r = one({ any: [{ field: "path", regex: "\\\\temp\\\\", flags: "i" }], tags: ["t"] });
    expect(matchEvent(ev({ id: "e", path: "C:\\\\Windows\\\\TEMP\\\\x.exe" }), r)).toBe(true);
  });

  it("exists true requires a non-empty value; exists false requires absence", () => {
    const present = one({ any: [{ field: "sha256", exists: true }], tags: ["t"] });
    const absent = one({ any: [{ field: "sha256", exists: false }], tags: ["t"] });
    expect(matchEvent(ev({ id: "e", sha256: "abc" }), present)).toBe(true);
    expect(matchEvent(ev({ id: "e" }), present)).toBe(false);
    expect(matchEvent(ev({ id: "e" }), absent)).toBe(true);
    expect(matchEvent(ev({ id: "e", sha256: "abc" }), absent)).toBe(false);
  });

  it("matches a numeric field via contains", () => {
    const r = one({ any: [{ field: "port", equals: "3389" }], tags: ["t"] });
    expect(matchEvent(ev({ id: "e", port: 3389 }), r)).toBe(true);
    expect(matchEvent(ev({ id: "e", port: 445 }), r)).toBe(false);
  });
});

describe("matchEvent — any/all/none semantics", () => {
  it("all requires every condition; any requires at least one; none forbids all", () => {
    const r = one({
      all: [{ field: "asset", exists: true }],
      any: [{ field: "message", contains: "7045" }, { field: "message", contains: "4697" }],
      none: [{ field: "message", contains: "svchost.exe -k" }],
      tags: ["t"],
    });
    expect(matchEvent(ev({ id: "e", asset: "HOST1", message: "id 7045" }), r)).toBe(true);
    // none blocks it
    expect(matchEvent(ev({ id: "e", asset: "HOST1", message: "7045 svchost.exe -k netsvcs" }), r)).toBe(false);
    // all fails (no asset)
    expect(matchEvent(ev({ id: "e", message: "id 7045" }), r)).toBe(false);
    // any fails
    expect(matchEvent(ev({ id: "e", asset: "HOST1", message: "id 1234" }), r)).toBe(false);
  });

  it("a rule with only an all block and no any/none still matches", () => {
    const r = one({ all: [{ field: "processName", equals: "mimikatz.exe" }], tags: ["t"] });
    expect(matchEvent(ev({ id: "e", processName: "mimikatz.exe" }), r)).toBe(true);
    expect(matchEvent(ev({ id: "e", processName: "cmd.exe" }), r)).toBe(false);
  });
});
