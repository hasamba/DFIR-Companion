import { describe, it, expect } from "vitest";
import { findingCautionLine } from "../../src/reports/findingCaution.js";
import type { Finding } from "../../src/analysis/stateTypes.js";

function f(p: Partial<Finding>): Finding {
  return {
    id: "f1",
    severity: "High",
    title: "t",
    description: "",
    relatedIocs: [],
    sourceScreenshots: [],
    mitreTechniques: [],
    firstSeen: "",
    lastUpdated: "",
    status: "open",
    ...p,
  };
}

describe("findingCautionLine", () => {
  it("prints the renamed-shell caution for a decoy-only finding (#1502)", () => {
    expect(findingCautionLine(f({ decoyBinary: true }))).toMatch(
      /^> ⚠️ \*\*Renamed shell, not the named tool\*\*/,
    );
  });
  it("orders the badges: ungrounded wins, then decoy, then mismatch, then lateral, then corroboration", () => {
    expect(findingCautionLine(f({ ungrounded: true, decoyBinary: true }))).toMatch(/No cited evidence/);
    expect(findingCautionLine(f({ buildBaseline: true, decoyBinary: true }))).toMatch(/Build baseline/);
    expect(findingCautionLine(f({ decoyBinary: true, contentMismatch: true }))).toMatch(/Renamed shell/);
    expect(findingCautionLine(f({ contentMismatch: true, lateralUnconfirmed: true }))).toMatch(
      /Citation mismatch/,
    );
    expect(findingCautionLine(f({ lateralUnconfirmed: true }))).toMatch(/Unconfirmed lateral movement/);
    expect(
      findingCautionLine(
        f({
          corroboration: {
            distinctTools: 2,
            distinctHosts: 1,
            intelSources: 0,
            graphLinked: false,
            verdictFirst: true,
            huntArtifactOnly: false,
            kevLinked: false,
          },
        }),
      ),
    ).toMatch(/^- Corroboration: 2 tools/);
  });
  it("is empty for a plain finding", () => {
    expect(findingCautionLine(f({}))).toBe("");
  });
});
