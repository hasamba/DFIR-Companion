import { describe, it, expect } from "vitest";
import { buildHostAliasIndex } from "../../src/analysis/hostAlias.js";
import { renderStructuredTags } from "../../src/analysis/synthEvidence.js";
import { collapseForPrompt } from "../../src/analysis/synthGroup.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

const ALIAS = buildHostAliasIndex([], { win11: "win11.windomain.local" });

function ev(id: string, asset: string, ts: string): ForensicEvent {
  return {
    id,
    timestamp: ts,
    description: "identical detection",
    severity: "Medium",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    asset,
    sources: ["Sysmon"],
  };
}

describe("renderStructuredTags", () => {
  it("emits the raw asset without an alias index", () => {
    expect(renderStructuredTags(ev("a", "WIN11", "2026-04-22T11:00:00Z"))).toContain("<host:WIN11>");
  });

  it("emits the canonical name with an alias index", () => {
    const tags = renderStructuredTags(ev("a", "WIN11", "2026-04-22T11:00:00Z"), ALIAS);
    expect(tags).toContain("<host:win11.windomain.local>");
    expect(tags).not.toContain("<host:WIN11>");
  });

  // NOT "<host:DC01>" as the task-6 brief's draft asserted. resolveHost falls back to
  // canonicalHostName(raw) when nothing links "dc01" to another canonical name, and that fallback
  // unconditionally lowercases (hostAlias.ts: "Lowercase, trim, drop a trailing FQDN dot"). This
  // is proven pre-existing, intentional behaviour, not a bug introduced here: hostAlias.test.ts
  // already asserts the identical contract — `resolveHost(index, "SRV-DC1")` returns `"srv-dc1"`,
  // titled "passes an unknown host through, canonicalized". "Untouched" therefore means "not
  // remapped to a DIFFERENT host identity", not "byte-for-byte identical casing". The assertion
  // below still fails if renderStructuredTags stopped calling resolveHost when given an index (the
  // tag would stay "<host:DC01>"), so it keeps its value as a regression check.
  it("resolves a host with no alias to its canonicalized (lowercased) form, not a different host", () => {
    const tags = renderStructuredTags(ev("a", "DC01", "2026-04-22T11:00:00Z"), ALIAS);
    expect(tags).toContain("<host:dc01>");
    expect(tags).not.toContain("<host:DC01>");
    expect(tags).not.toContain("win11");
  });
});

describe("collapseForPrompt group hosts", () => {
  const run = [
    ev("a", "WIN11", "2026-04-22T11:00:00Z"),
    ev("b", "WIN11.windomain.local", "2026-04-22T11:00:05Z"),
    ev("c", "WIN11", "2026-04-22T11:00:10Z"),
  ];

  it("reports two hosts without an alias index", () => {
    const collapsed = collapseForPrompt(run, { minRepeats: 2 });
    const group = [...collapsed.groupById.values()][0];
    expect(group.hosts).toHaveLength(2);
  });

  it("reports one host with an alias index", () => {
    const collapsed = collapseForPrompt(run, { minRepeats: 2, aliasIndex: ALIAS });
    const group = [...collapsed.groupById.values()][0];
    expect(group.hosts).toEqual(["win11.windomain.local"]);
  });
});
