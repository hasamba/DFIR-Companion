import { describe, it, expect } from "vitest";
import {
  applySimulationVerdict,
  findSimulationVerdict,
  isSimulationVerdictTitle,
  simulationSeverityLabel,
  summaryStatesSimulationVerdict,
  SIMULATED_LABEL,
} from "../../src/analysis/simulationVerdict.js";
import { buildHostAliasIndex } from "../../src/analysis/hostAlias.js";
import type { Finding, ForensicEvent, Severity } from "../../src/analysis/stateTypes.js";

const T = "2026-09-24T09:04:00.000Z";
const HOST = "desktop-sim01.example.com";

function finding(id: string, severity: Severity, title: string, over: Partial<Finding> = {}): Finding {
  return {
    id,
    severity,
    confidence: 90,
    title,
    description: `${title} — details`,
    relatedIocs: [],
    sourceScreenshots: [],
    mitreTechniques: [],
    relatedEventIds: [`e-${id}`],
    firstSeen: T,
    lastUpdated: T,
    status: "confirmed",
    ...over,
  };
}

function ev(id: string, asset: string | undefined): ForensicEvent {
  return {
    id,
    timestamp: T,
    description: `row ${id}`,
    severity: "High",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    ...(asset ? { asset } : {}),
  };
}

const VERDICT_TITLE =
  "Strong indicators this activity is a scripted attack-simulation / detection-engineering exercise rather than an uncontrolled intrusion";

// Shaped on INC-2026-005 (GoGoogle ransomware simulation): the attack chain at Critical, the IFEO
// backdoor, and the simulation finding the synthesis left at Info.
function labCase(verdictConfidence = 85): { findings: Finding[]; events: ForensicEvent[] } {
  const findings = [
    finding("f1", "Critical", "Mimikatz executed against LSASS", { mitreTechniques: ["T1003.001"] }),
    finding("f4", "Critical", "Accessibility-feature (Utilman) IFEO debugger backdoor installed", {
      mitreTechniques: ["T1546.008", "T1112"],
    }),
    finding("f6", "Medium", "Advanced IP Scanner executed", { mitreTechniques: ["T1046"] }),
    finding("f8", "Critical", "Windows event logs cleared", { mitreTechniques: ["T1070.001"] }),
    finding("f10", "High", "Windows Defender real-time protection disabled", {
      mitreTechniques: ["T1562.001"],
    }),
    finding("f13", "Info", "Quick Assist present", { status: "dismissed" }),
    finding("f14", "Info", VERDICT_TITLE, { confidence: verdictConfidence, status: "open" }),
    finding("f23", "Low", "Email artifact linked to wevtutil activity"),
  ];
  const events = findings.map((f) => ev(`e-${f.id}`, HOST));
  return { findings, events };
}

const byId = (list: Finding[]): Record<string, Finding> => Object.fromEntries(list.map((f) => [f.id, f]));

describe("simulation verdict detection (#1595)", () => {
  it("recognises an affirmative simulation conclusion", () => {
    expect(isSimulationVerdictTitle(VERDICT_TITLE)).toBe(true);
    expect(isSimulationVerdictTitle("Activity is consistent with an authorized purple-team exercise")).toBe(
      true,
    );
    expect(isSimulationVerdictTitle("Likely a planned red-team engagement")).toBe(true);
  });

  it("does not treat simulation tooling, hostile use or a negated verdict as a verdict", () => {
    expect(isSimulationVerdictTitle("Simulated ransomware execution")).toBe(false);
    expect(isSimulationVerdictTitle("Unauthorized red-team tooling used by attacker, likely staged")).toBe(
      false,
    );
    expect(isSimulationVerdictTitle("Simulation framework abused by attacker, likely for persistence")).toBe(
      false,
    );
    expect(isSimulationVerdictTitle("No indication this was an authorized exercise")).toBe(false);
    expect(isSimulationVerdictTitle("Penetration-test utility observed in real intrusion")).toBe(false);
    expect(isSimulationVerdictTitle("Mimikatz executed against LSASS")).toBe(false);
    // Review of #1595: a denial AFTER the noun, and tooling named without a conclusion.
    expect(isSimulationVerdictTitle("Red-team exercise was not authorized, likely hostile")).toBe(false);
    expect(isSimulationVerdictTitle("Authorized exercise was ruled out")).toBe(false);
    expect(isSimulationVerdictTitle("Indicators of penetration-test tooling")).toBe(false);
    expect(isSimulationVerdictTitle("Penetration-test tooling likely used by the attacker")).toBe(false);
  });

  it("needs confidence of at least 80 and an undismissed finding", () => {
    expect(findSimulationVerdict(labCase(79).findings)).toBeUndefined();
    expect(findSimulationVerdict(labCase(80).findings)?.id).toBe("f14");
    const dismissed = labCase().findings.map((f) =>
      f.id === "f14" ? { ...f, status: "dismissed" as const } : f,
    );
    expect(findSimulationVerdict(dismissed)).toBeUndefined();
  });
});

describe("applySimulationVerdict (#1595)", () => {
  it("leaves a case with no simulation indicators unchanged (regression)", () => {
    const { findings, events } = labCase();
    const real = findings.filter((f) => f.id !== "f14");
    const snapshot = structuredClone(real);
    const out = applySimulationVerdict(real, events);
    expect(out).toBe(real);
    expect(out).toEqual(snapshot);
    out.forEach((f, i) => expect(f).toBe(real[i]));
  });

  it("leaves the case unchanged below the confidence threshold", () => {
    const { findings, events } = labCase(79);
    expect(applySimulationVerdict(findings, events)).toBe(findings);
  });

  it("raises the verdict, caps the scenario findings and keeps the live exposure (INC-2026-005 shape)", () => {
    const { findings, events } = labCase();
    const out = byId(applySimulationVerdict(findings, events));

    // 1. The verdict ties the highest attack finding it explains.
    expect(out.f14.severity).toBe("Critical");
    expect(out.f14.simulation).toMatchObject({ role: "verdict", originalSeverity: "Info" });

    // 2. Scenario findings carry the tag, capped at Medium, the live-intrusion severity kept.
    expect(out.f1.severity).toBe("Medium");
    expect(out.f1.simulation).toMatchObject({
      role: "simulated",
      originalSeverity: "Critical",
      verdictId: "f14",
    });
    expect(out.f10.severity).toBe("Medium");
    expect(out.f10.simulation?.originalSeverity).toBe("High");
    expect(out.f6.severity).toBe("Medium");
    expect(out.f6.simulation?.role).toBe("simulated");

    // 3. The IFEO backdoor is a live exposure: it keeps Critical.
    expect(out.f4.severity).toBe("Critical");
    expect(out.f4.simulation?.role).toBe("live-exposure");

    // Dismissed and Low/Info findings are not touched.
    expect(out.f13.simulation).toBeUndefined();
    expect(out.f23.simulation).toBeUndefined();
    expect(out.f23.severity).toBe("Low");
  });

  it("never mutates its input", () => {
    const { findings, events } = labCase();
    const snapshot = structuredClone(findings);
    applySimulationVerdict(findings, events);
    expect(findings).toEqual(snapshot);
  });

  it("is idempotent", () => {
    const { findings, events } = labCase();
    const once = applySimulationVerdict(findings, events);
    expect(applySimulationVerdict(once, events)).toEqual(once);
  });

  it("lets a later severity rewrite win over the stored original", () => {
    const { findings, events } = labCase();
    const once = applySimulationVerdict(findings, events);
    // A later run re-rated f1 as High; the annotation from the run before still says Critical.
    const rewritten = once.map((f) => (f.id === "f1" ? { ...f, severity: "High" as const } : f));
    const out = byId(applySimulationVerdict(rewritten, events));
    expect(out.f1.simulation?.originalSeverity).toBe("High");
    expect(out.f1.severity).toBe("Medium");
  });

  it("restores every original severity when the verdict disappears", () => {
    const { findings, events } = labCase();
    const once = applySimulationVerdict(findings, events);
    const gone = once.map((f) => (f.id === "f14" ? { ...f, status: "dismissed" as const } : f));
    const out = byId(applySimulationVerdict(gone, events));
    expect(out.f1.severity).toBe("Critical");
    expect(out.f1.simulation).toBeUndefined();
    expect(out.f14.severity).toBe("Info");
  });

  it("treat-as-real: no caps, the verdict is only marked overridden", () => {
    const { findings, events } = labCase();
    const once = applySimulationVerdict(findings, events);
    const out = byId(applySimulationVerdict(once, events, { treatAsReal: true }));
    expect(out.f1.severity).toBe("Critical");
    expect(out.f1.simulation).toBeUndefined();
    expect(out.f4.simulation).toBeUndefined();
    expect(out.f14.severity).toBe("Info");
    expect(out.f14.simulation).toMatchObject({ role: "verdict", overridden: true });
  });

  it("judges the verdict on the model's own confidence when grading capped it", () => {
    const { findings, events } = labCase(65);
    expect(applySimulationVerdict(findings, events)).toBe(findings);
    const out = byId(applySimulationVerdict(findings, events, { modelConfidence: new Map([["f14", 85]]) }));
    expect(out.f14.severity).toBe("Critical");
    expect(out.f1.severity).toBe("Medium");
  });

  it("keeps an accepted verdict when the step is re-applied without the model's confidence", () => {
    const { findings, events } = labCase(65);
    const once = applySimulationVerdict(findings, events, { modelConfidence: new Map([["f14", 85]]) });
    const overridden = applySimulationVerdict(once, events, { treatAsReal: true });
    expect(byId(overridden).f1.severity).toBe("Critical");
    const restored = byId(applySimulationVerdict(overridden, events));
    expect(restored.f1.severity).toBe("Medium");
    expect(restored.f14.severity).toBe("Critical");
  });

  it("never accepts an ungrounded verdict", () => {
    const { findings, events } = labCase();
    const ungrounded = findings.map((f) => (f.id === "f14" ? { ...f, ungrounded: true } : f));
    expect(applySimulationVerdict(ungrounded, events)).toBe(ungrounded);
  });

  it("does not cap a real intrusion on another host", () => {
    const { findings, events } = labCase();
    const other = finding("f30", "Critical", "Ransomware encryption on file server", {
      mitreTechniques: ["T1486"],
    });
    const out = byId(
      applySimulationVerdict([...findings, other], [...events, ev("e-f30", "fs01.example.com")]),
    );
    expect(out.f30.severity).toBe("Critical");
    expect(out.f30.simulation).toBeUndefined();
    expect(out.f1.severity).toBe("Medium");
  });

  it("matches a short host name to its FQDN", () => {
    const { findings } = labCase();
    const events = findings.map((f) => ev(`e-${f.id}`, f.id === "f14" ? HOST : "DESKTOP-SIM01"));
    expect(byId(applySimulationVerdict(findings, events)).f1.severity).toBe("Medium");
  });

  it("uses the analyst's host merges when an alias index is given", () => {
    const { findings } = labCase();
    const events = findings.map((f) => ev(`e-${f.id}`, f.id === "f14" ? HOST : "ws-renamed.example.com"));
    expect(byId(applySimulationVerdict(findings, events)).f1.severity).toBe("Critical");
    const aliasIndex = buildHostAliasIndex([], { "ws-renamed.example.com": HOST });
    expect(byId(applySimulationVerdict(findings, events, { aliasIndex })).f1.severity).toBe("Medium");
  });

  it("a hostless verdict explains findings only on a single-host case", () => {
    const { findings } = labCase();
    const single = findings.map((f) => ev(`e-${f.id}`, f.id === "f14" ? undefined : HOST));
    expect(byId(applySimulationVerdict(findings, single)).f1.severity).toBe("Medium");
    const multi = [...single, ev("e-x", "fs01.example.com")];
    const out = byId(applySimulationVerdict(findings, multi));
    expect(out.f1.severity).toBe("Critical");
    expect(out.f14.severity).toBe("Info");
  });

  it("caps a scenario finding that names simulation tooling without concluding", () => {
    const { findings, events } = labCase();
    const sim = finding("f40", "High", "Simulated ransomware execution");
    const out = byId(applySimulationVerdict([...findings, sim], [...events, ev("e-f40", HOST)]));
    expect(out.f40.severity).toBe("Medium");
    expect(out.f40.simulation?.role).toBe("simulated");
  });

  it("matches a persistence sub-technique by its parent", () => {
    const { findings, events } = labCase();
    const task = finding("f50", "High", "Scheduled task created", { mitreTechniques: ["T1053.005"] });
    const lookalike = finding("f51", "High", "Unrelated technique", { mitreTechniques: ["T10530"] });
    const out = byId(
      applySimulationVerdict(
        [...findings, task, lookalike],
        [...events, ev("e-f50", HOST), ev("e-f51", HOST)],
      ),
    );
    expect(out.f50.simulation?.role).toBe("live-exposure");
    expect(out.f51.simulation?.role).toBe("simulated");
  });
});

describe("simulationSeverityLabel (#1595)", () => {
  it("names the capped and the live-intrusion severity side by side", () => {
    const { findings, events } = labCase();
    const out = byId(applySimulationVerdict(findings, events));
    expect(simulationSeverityLabel(out.f1)).toBe(`[${SIMULATED_LABEL}; live-intrusion severity: Critical]`);
    expect(simulationSeverityLabel(out.f6)).toBe(`[${SIMULATED_LABEL}]`);
    expect(simulationSeverityLabel(out.f4)).toMatch(/live exposure/);
    expect(simulationSeverityLabel(out.f14)).toBe("[simulation verdict; raised from Info]");
    expect(simulationSeverityLabel(out.f23)).toBe("");
  });

  it("says when the analyst overruled the verdict", () => {
    const { findings, events } = labCase();
    const out = byId(applySimulationVerdict(findings, events, { treatAsReal: true }));
    expect(simulationSeverityLabel(out.f14)).toBe("[treated as real intrusion (analyst)]");
  });
});

// #1948: the synthesis often states the verdict with less confidence. A verdict finding below 80 is
// accepted only when the summary ALSO states the verdict, in a sentence that passes a strict test
// (no contrast or hedge), and never below the floor of 25.
describe("simulation verdict from the summary (#1948)", () => {
  const WEAK_TITLE = "Activity strongly consistent with an authorized attack simulation";
  const AFFIRMATIVE =
    "Multiple host artifacts were collected. The activity is strongly consistent with an authorized attack simulation. Six findings were raised.";
  function weakCase(conf: number): { findings: Finding[]; events: ForensicEvent[] } {
    const { findings, events } = labCase();
    const withWeak = findings.map((f) =>
      f.id === "f14" ? { ...f, title: WEAK_TITLE, confidence: conf } : f,
    );
    return { findings: withWeak, events };
  }

  it("states the verdict in an affirmative sentence", () => {
    expect(summaryStatesSimulationVerdict(AFFIRMATIVE)).toBe(true);
    expect(summaryStatesSimulationVerdict("")).toBe(false);
    expect(summaryStatesSimulationVerdict(undefined)).toBe(false);
  });

  it("caps the other findings when a weak verdict finding and the summary agree", () => {
    const { findings, events } = weakCase(30);
    const out = byId(applySimulationVerdict(findings, events, { summary: AFFIRMATIVE }));
    expect(out.f1.severity).toBe("Medium");
    expect(out.f1.simulation?.basis).toBe("summary");
    expect(out.f14.simulation?.role).toBe("verdict");
    expect(out.f14.simulation?.basis).toBe("summary");
    expect(simulationSeverityLabel(out.f1)).toMatch(/verdict from summary/);
    expect(simulationSeverityLabel(out.f14)).toMatch(/verdict from summary/);
    expect(findSimulationVerdict(findings, undefined, AFFIRMATIVE)?.id).toBe("f14");
    expect(findSimulationVerdict(findings)).toBeUndefined();
  });

  it("is idempotent on the summary path, and an override keeps the basis", () => {
    const { findings, events } = weakCase(30);
    const once = applySimulationVerdict(findings, events, { summary: AFFIRMATIVE });
    expect(applySimulationVerdict(once, events, { summary: AFFIRMATIVE })).toEqual(once);
    const real = byId(applySimulationVerdict(once, events, { summary: AFFIRMATIVE, treatAsReal: true }));
    expect(real.f1.severity).toBe("Critical");
    expect(real.f14.simulation?.overridden).toBe(true);
    expect(real.f14.simulation?.basis).toBe("summary");
  });

  it("leaves the case unchanged when the summary does not state the verdict", () => {
    const { findings, events } = weakCase(30);
    const summary = "Credential theft and log clearing were observed on one workstation.";
    expect(applySimulationVerdict(findings, events, { summary })).toBe(findings);
    expect(applySimulationVerdict(findings, events)).toBe(findings);
  });

  it("leaves the case unchanged below the floor of 25", () => {
    const { findings, events } = weakCase(20);
    expect(applySimulationVerdict(findings, events, { summary: AFFIRMATIVE })).toBe(findings);
  });

  it.each([
    "It is likely a real intrusion rather than a simulation.",
    "Although triage first suggested an authorized red-team exercise, the evidence rules this out.",
    "The tooling resembles a red-team framework, but the activity is consistent with a financially motivated actor.",
    "Whether this is an authorized simulation remains unconfirmed.",
    "The owner should confirm whether this was a planned penetration test; until then treat it as hostile.",
  ])("does not cap a real intrusion whose summary says: %s", (summary) => {
    expect(summaryStatesSimulationVerdict(summary)).toBe(false);
    const { findings, events } = weakCase(30);
    expect(applySimulationVerdict(findings, events, { summary })).toBe(findings);
  });

  it("rejects a summary that states the verdict and contests it in another sentence", () => {
    const summary = `${AFFIRMATIVE} However, the owner has not confirmed a planned exercise.`;
    expect(summaryStatesSimulationVerdict(summary)).toBe(false);
  });

  // #1979: a soft follow-up line about the exercise must not veto a stated verdict.
  const A = "The activity is strongly consistent with an authorized attack simulation.";
  it.each([
    "The investigation is consistent with a scripted simulation. Once the exercise wraps, the team may rerun detection rules to confirm coverage.",
    `${A} After the exercise, the SOC could tune the Sigma rules.`,
    `${A} Until the exercise ends, keep the lab hosts isolated.`,
    `${A} If the exercise repeats, collect memory as well.`,
    `${A} Pending the exercise debrief, retain the collected artifacts.`,
  ])("keeps the verdict beside a soft follow-up line (#1979): %s", (summary) => {
    expect(summaryStatesSimulationVerdict(summary)).toBe(true);
    const { findings, events } = weakCase(30);
    const out = byId(applySimulationVerdict(findings, events, { summary }));
    expect(out.f1.severity).toBe("Medium");
    expect(out.f1.simulation?.basis).toBe("summary");
  });

  it.each([
    `${A} However, the owner has not confirmed a planned exercise.`,
    `${A} Whether this is an authorized simulation remains unconfirmed.`,
    `${A} It could also be a real attacker posing as a red-team exercise.`,
    `${A} This may be a red-team exercise.`,
    `${A} The exercise may not have been authorized.`,
    `${A} Contact the owner to confirm the exercise.`,
    `${A} If the exercise is confirmed, close the case.`,
    `${A} Until the owner signs off, the exercise stays unverified.`,
    `${A} Pending owner confirmation of the exercise, keep the findings open.`,
    `${A} The exercise might have been used as cover by an attacker.`,
    `${A} The penetration test may be authorized.`,
    "The activity may be consistent with an authorized simulation.",
  ])("still refuses a summary that contests or hedges the verdict (#1979): %s", (summary) => {
    expect(summaryStatesSimulationVerdict(summary)).toBe(false);
    const { findings, events } = weakCase(30);
    expect(applySimulationVerdict(findings, events, { summary })).toBe(findings);
  });

  it("keeps the 80+ path free of the summary basis", () => {
    const { findings, events } = labCase(85);
    const out = byId(applySimulationVerdict(findings, events, { summary: AFFIRMATIVE }));
    expect(out.f1.severity).toBe("Medium");
    expect(out.f1.simulation?.basis).toBeUndefined();
  });
});
