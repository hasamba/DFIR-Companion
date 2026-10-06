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
  it("says the citation mismatch covers an IP or a program name (#1954)", () => {
    expect(findingCautionLine(f({ contentMismatch: true }))).toMatch(/an IP or a program name/);
  });
  it("is empty for a plain finding", () => {
    expect(findingCautionLine(f({}))).toBe("");
  });
});

describe("findingCautionLine — lab setup (#1946)", () => {
  const marked = (p: Partial<Finding> = {}): Finding => ({ ...f(p), labSetup: true }) as Finding;
  it("prints the lab-setup badge", () => {
    expect(findingCautionLine(marked())).toMatch(
      /^> ⚠️ \*\*Lab setup\*\* — every cited event is a file copied into the VM through a hypervisor drag-and-drop folder/,
    );
  });
  it("ranks below the build baseline and above corroboration", () => {
    expect(findingCautionLine(marked({ buildBaseline: true }))).toMatch(/Build baseline/);
    expect(findingCautionLine(marked({ ungrounded: true }))).toMatch(/No cited evidence/);
  });
});

describe("findingCautionLine — Defender-tamper timing (#1941)", () => {
  const marked = (t: string, p: Partial<Finding> = {}): Finding => ({ ...f(p), tamperTiming: t }) as Finding;
  it("prints the date-unknown badge", () => {
    expect(findingCautionLine(marked("date-unknown"))).toMatch(
      /^> ⚠️ \*\*Date unknown\*\* — the only evidence is PowerShell console history, which has no per-line time/,
    );
  });
  it("prints the before-the-incident badge", () => {
    expect(findingCautionLine(marked("before-incident"))).toMatch(
      /^> ⚠️ \*\*Before the incident\*\* — every cited event is dated well before the main activity burst/,
    );
  });
  it("ranks below the evidence gates and above corroboration", () => {
    expect(findingCautionLine(marked("date-unknown", { ungrounded: true }))).toMatch(/No cited evidence/);
    expect(findingCautionLine(marked("date-unknown", { lateralUnconfirmed: true }))).toMatch(
      /Unconfirmed lateral movement/,
    );
  });
});

// #1973: an analyst restore replaces the cap badge with who restored it, over which gate.
describe("findingCautionLine — severity restored by the analyst (#1973)", () => {
  const restored = (p: Partial<Finding> = {}, gates = ["tamper-timing"]): Finding =>
    ({
      ...f(p),
      tamperTiming: "date-unknown",
      severityCap: { from: "High", to: "Medium", gates },
      severityRestored: { by: "Alice", at: "2026-10-06T10:00:00.000Z" },
    }) as Finding;
  it("prints the restore badge instead of the cap badge", () => {
    const line = findingCautionLine(restored());
    expect(line).toMatch(/^> ℹ️ \*\*Severity restored by analyst\*\*/);
    expect(line).toMatch(/Alice/);
    expect(line).toMatch(/Defender-tamper timing/);
    expect(line).not.toMatch(/Date unknown/);
  });
  it("keeps the no-evidence badge first", () => {
    expect(findingCautionLine(restored({ ungrounded: true }))).toMatch(/No cited evidence/);
  });
  it("prints the cap badge when the finding is capped but not restored", () => {
    const capped = { ...restored(), severityRestored: undefined } as Finding;
    expect(findingCautionLine(capped)).toMatch(/Date unknown/);
  });
});
