// #1757 — technique deltas. A model "maps" a technique when its MITRE table OR one of its live
// findings carries it, so a technique both models tag on a finding is no disagreement. And the
// referee judging a real technique delta sees the findings that carry it — their text and the
// events they cite — plus a rule that "staged, not run" is not a reason to drop a technique.
import { describe, it, expect } from "vitest";
import {
  emptyState,
  type Finding,
  type ForensicEvent,
  type InvestigationState,
  type Technique,
} from "../../src/analysis/stateTypes.js";
import {
  buildSecondOpinionDeltas,
  buildReconcilePrompt,
  RECONCILE_TECHNIQUE_FINDINGS,
} from "../../src/analysis/secondOpinion.js";

function finding(over: Partial<Finding> & Pick<Finding, "id" | "title" | "severity">): Finding {
  return {
    confidence: 80,
    description: `${over.title} description`,
    relatedIocs: [],
    sourceScreenshots: [],
    mitreTechniques: [],
    firstSeen: "2026-06-01T00:00:00.000Z",
    lastUpdated: "2026-06-01T00:00:00.000Z",
    status: "open",
    ...over,
  };
}

function event(id: string, over: Partial<ForensicEvent> = {}): ForensicEvent {
  return {
    id,
    timestamp: "2026-06-01T10:00:00.000Z",
    description: `${id} happened`,
    severity: "Medium",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    ...over,
  };
}

const tech = (id: string, name = `${id} name`): Technique => ({ id, name, findingIds: [] });
const stateWith = (over: Partial<InvestigationState>): InvestigationState => ({
  ...emptyState("c1"),
  ...over,
});

const ids = (a: InvestigationState, b: InvestigationState, kind: string): string[] =>
  buildSecondOpinionDeltas(a, b)
    .filter((d) => d.kind === kind)
    .map((d) => d.title);

// The prompt text of one delta: its header line down to the next delta or the first blank line.
function blockOf(prompt: string, deltaId: string): string {
  const start = prompt.indexOf(`[${deltaId}]`);
  if (start < 0) return "";
  const rest = prompt.slice(start + 1);
  const ends = [rest.indexOf("\n["), rest.indexOf("\n\n")].filter((i) => i >= 0);
  return prompt.slice(start, ends.length ? start + 1 + Math.min(...ends) : undefined);
}

describe("technique deltas — a model maps what its live findings carry (#1757)", () => {
  it("raises no removal when model B's finding still carries the technique its table omits", () => {
    const a = stateWith({
      findings: [
        finding({ id: "f4", title: "Batch kit staged", severity: "High", mitreTechniques: ["T1490"] }),
      ],
      mitreTechniques: [tech("T1490")],
    });
    const b = stateWith({
      findings: [
        finding({ id: "f4", title: "Batch kit staged", severity: "High", mitreTechniques: ["T1490"] }),
      ],
      mitreTechniques: [],
    });
    expect(ids(a, b, "mitre_removed")).toEqual([]);
  });

  it("raises no addition when model A's finding already carries the technique its table omits", () => {
    const a = stateWith({
      findings: [finding({ id: "f1", title: "Beacon", severity: "High", mitreTechniques: ["T1071"] })],
    });
    const b = stateWith({
      findings: [finding({ id: "g1", title: "Beacon", severity: "High", mitreTechniques: ["T1071"] })],
      mitreTechniques: [tech("T1071")],
    });
    expect(ids(a, b, "mitre_added")).toEqual([]);
  });

  it("a dismissed finding does not count as mapping, in either direction", () => {
    const dismissedB = stateWith({
      findings: [
        finding({ id: "g4", title: "Old", severity: "Low", status: "dismissed", mitreTechniques: ["T1490"] }),
      ],
    });
    const a = stateWith({ mitreTechniques: [tech("T1490")] });
    expect(ids(a, dismissedB, "mitre_removed")).toEqual(["T1490"]);

    const dismissedA = stateWith({
      findings: [
        finding({ id: "f9", title: "Old", severity: "Low", status: "dismissed", mitreTechniques: ["T1105"] }),
      ],
    });
    const b = stateWith({ mitreTechniques: [tech("T1105")] });
    expect(ids(dismissedA, b, "mitre_added")).toEqual(["T1105"]);
  });

  it("a sub-technique on a finding does not count as mapping its parent", () => {
    const a = stateWith({ mitreTechniques: [tech("T1070")] });
    const b = stateWith({
      findings: [
        finding({ id: "g1", title: "Logs cleared", severity: "High", mitreTechniques: ["T1070.001"] }),
      ],
    });
    expect(ids(a, b, "mitre_removed")).toEqual(["T1070"]);
  });
});

describe("buildReconcilePrompt — technique deltas show the findings that carry them (#1757)", () => {
  // The issue's eval case: a staged batch kit tagged T1490 that model B drops. The execution-status
  // sentence sits past character 240, where the old 240-character excerpt stopped.
  const kitText =
    "PowerShell wrote a known affiliate batch kit to two folders. " +
    "The kit holds shadow.bat and shadowGuru.bat (VSS deletion), delbackup.bat and backup.bat " +
    "(backup removal), clearlog.bat (log clearing), def1.bat and disable.bat (Defender tampering), " +
    "LOGOFF.bat (log off all users) and svc.bat (service stop). " +
    "The scripts are staged, but there is no evidence that they ran.";
  const timeline = [
    event("e1", { severity: "High", description: "shadow.bat written to C:\\kit" }),
    event("e2", { severity: "Medium", description: "delbackup.bat written to C:\\kit" }),
    event("e9", { severity: "Low", description: "unrelated logon" }),
  ];
  const kit = finding({
    id: "f4",
    title: "Pre-ransomware batch kit staged",
    severity: "High",
    description: kitText,
    relatedEventIds: ["e1", "e2"],
    mitreTechniques: ["T1490", "T1489"],
  });
  const a = stateWith({
    forensicTimeline: timeline,
    findings: [kit],
    mitreTechniques: [tech("T1490", "Inhibit System Recovery"), tech("T1489", "Service Stop")],
  });
  const b = stateWith({ forensicTimeline: timeline, findings: [], mitreTechniques: [] });
  const prompt = buildReconcilePrompt(a, b, buildSecondOpinionDeltas(a, b));
  const t1490 = blockOf(prompt, "mitre_removed:t1490");

  it("shows the carrying finding's full text, past the old 240-character cut", () => {
    expect(kitText.indexOf("no evidence that they ran")).toBeGreaterThan(240);
    expect(t1490).toContain("[f4]");
    expect(t1490).toContain("Pre-ransomware batch kit staged");
    expect(t1490).toContain("no evidence that they ran");
  });

  it("shows the events the carrying finding cites, though none is tagged with the technique", () => {
    expect(t1490).toContain("[e1]");
    expect(t1490).toContain("[e2]");
    expect(t1490).not.toContain("[e9]");
    expect(t1490).not.toMatch(/ungrounded/i);
  });

  it("puts the staged-tooling rule in the USER prompt, so an ejected system prompt keeps it", () => {
    expect(prompt).toMatch(/staged/i);
    expect(prompt).toMatch(/not (?:a reason|enough) to remove/i);
    expect(prompt).toMatch(/wrong for the artefact/i);
    expect(prompt).toMatch(/general-purpose program/i);
  });

  it("leaves the rule out when no technique delta is in the run", () => {
    const x = stateWith({ findings: [finding({ id: "f1", title: "Alpha tool", severity: "High" })] });
    const y = stateWith({ findings: [] });
    const p = buildReconcilePrompt(x, y, buildSecondOpinionDeltas(x, y));
    expect(p).not.toMatch(/ATT&CK TECHNIQUE DELTAS/);
  });

  it("renders a finding's text once; a later technique delta refers back to it", () => {
    expect(prompt.split("no evidence that they ran").length - 1).toBe(1);
    expect(blockOf(prompt, "mitre_removed:t1489")).toMatch(/\[f4\].*shown above/);
  });

  it("keys that reference by model side, so B's f4 is never taken for A's f4", () => {
    const aSide = stateWith({
      forensicTimeline: timeline,
      findings: [
        finding({
          id: "f4",
          title: "A kit",
          severity: "High",
          description: "A-SIDE TEXT",
          mitreTechniques: ["T1490"],
        }),
      ],
      mitreTechniques: [tech("T1490")],
    });
    const bSide = stateWith({
      forensicTimeline: timeline,
      findings: [
        finding({
          id: "f4",
          title: "B beacon",
          severity: "High",
          description: "B-SIDE TEXT",
          mitreTechniques: ["T1071"],
        }),
      ],
      mitreTechniques: [tech("T1071")],
    });
    const p = buildReconcilePrompt(aSide, bSide, buildSecondOpinionDeltas(aSide, bSide));
    expect(blockOf(p, "mitre_removed:t1490")).toContain("A-SIDE TEXT");
    expect(blockOf(p, "mitre_added:t1071")).toContain("B-SIDE TEXT");
    expect(p).not.toMatch(/shown above/);
  });

  it("caps the carrying findings, highest severity first, and takes events only from those shown", () => {
    const sev = ["Low", "Critical", "Medium", "High"] as const;
    const tl = sev.map((_, i) => event(`c${i}`));
    const carriers = sev.map((s, i) =>
      finding({
        id: `f${i}`,
        title: `${s} carrier`,
        severity: s,
        relatedEventIds: [`c${i}`],
        mitreTechniques: ["T1490"],
      }),
    );
    const x = stateWith({ forensicTimeline: tl, findings: carriers, mitreTechniques: [tech("T1490")] });
    const y = stateWith({ forensicTimeline: tl });
    const block = blockOf(buildReconcilePrompt(x, y, buildSecondOpinionDeltas(x, y)), "mitre_removed:t1490");
    expect(RECONCILE_TECHNIQUE_FINDINGS).toBe(3);
    const shown = [...block.matchAll(/\[(f\d)\] "/g)].map((m) => m[1]);
    expect(shown).toEqual(["f1", "f3", "f2"]); // Critical, High, Medium
    expect(block).toMatch(/\+1 more/);
    expect(block).not.toContain("[c0]"); // the Low carrier is not shown, so neither is its event
    expect(block).toContain("[c1]");
  });

  it("does not show a dismissed finding as a carrier", () => {
    const x = stateWith({
      forensicTimeline: timeline,
      findings: [
        finding({
          id: "f7",
          title: "Dismissed kit",
          severity: "High",
          status: "dismissed",
          mitreTechniques: ["T1490"],
        }),
      ],
      mitreTechniques: [tech("T1490")],
    });
    const y = stateWith({ forensicTimeline: timeline });
    const block = blockOf(buildReconcilePrompt(x, y, buildSecondOpinionDeltas(x, y)), "mitre_removed:t1490");
    expect(block).not.toContain("[f7]");
  });

  it("still calls a technique ungrounded when no live finding and no event carries it", () => {
    const x = stateWith({ forensicTimeline: timeline, mitreTechniques: [tech("T1531")] });
    const y = stateWith({ forensicTimeline: timeline });
    const block = blockOf(buildReconcilePrompt(x, y, buildSecondOpinionDeltas(x, y)), "mitre_removed:t1531");
    expect(block).toMatch(/ungrounded/i);
  });
});
