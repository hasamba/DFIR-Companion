import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { loadBundledSigmaRuleSet, readDisabledList } from "../../src/analysis/sigmaBundledRules.js";

// The rules shipped in companion/data/sigma (#2202). The inventory is pinned so a rule update or a
// mapping change that silently drops coverage shows up here, with the rule names, not in a case.

const { set, problem, dir } = loadBundledSigmaRuleSet();

function tally(): Record<string, number> {
  const out: Record<string, number> = {};
  for (const e of set.inventory) {
    const key = `${e.source ?? "-"}:${e.outcome}`;
    out[key] = (out[key] ?? 0) + 1;
  }
  return out;
}

describe("bundled Sigma rules", () => {
  it("loads from data/sigma with the pinned release", () => {
    expect(problem).toBeUndefined();
    expect(dir).toMatch(/data[\\/]sigma$/);
    expect(set.release).toBe("r2026-07-01");
    expect(set.commit).toBe("552f3fee420ef232a8e5790c4fae591847e32347");
  });

  it("has the expected inventory per log source", () => {
    expect(tally()).toEqual({
      "aws-cloudtrail:loaded": 28,
      "aws-cloudtrail:status": 13,
      "-:refused": 1,
      "azure-signinlogs:loaded": 12,
      "azure-signinlogs:disabled": 5,
      "azure-signinlogs:refused": 3,
      "azure-auditlogs:loaded": 17,
      "azure-auditlogs:disabled": 1,
      "azure-auditlogs:refused": 26,
      "web-server:loaded": 76,
      "web-server:status": 5,
      "web-server:refused": 2,
      "web-proxy:loaded": 46,
      "web-proxy:status": 2,
      "web-proxy:refused": 3,
    });
  });

  it("refuses only for reasons the analyst can act on", () => {
    const reasons = set.inventory.filter((e) => e.outcome === "refused").flatMap((e) => e.reasons ?? []);
    for (const r of reasons) expect(r).toMatch(/is not available in|modifier is not supported/);
  });

  it("disables only rules that are actually in the bundle", () => {
    const disabled = readDisabledList(readFileSync(`${dir}/disabled.yml`, "utf8"));
    const ids = new Set(set.inventory.map((e) => e.id));
    for (const id of disabled.keys()) expect(ids.has(id)).toBe(true);
    expect(
      set.inventory
        .filter((e) => e.outcome === "disabled")
        .map((e) => e.id)
        .sort(),
    ).toEqual([...disabled.keys()].sort());
  });

  it("loads no experimental rule", () => {
    const experimental = set.inventory.filter((e) => e.outcome === "status");
    expect(experimental.every((e) => e.reasons?.[0] === "status is experimental")).toBe(true);
  });
});
