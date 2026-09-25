// #1595 review: deciding a second-opinion delta re-applies the simulation verdict with the analyst's
// override read fresh, inside the per-case state lock, so a "treat as real intrusion" saved meanwhile
// is never overwritten by a stale capped state.
import { describe, it, expect } from "vitest";
import { applySecondOpinion, type SecondOpinionContext } from "../../src/analysis/ai/secondOpinionRun.js";
import { applySimulationVerdict } from "../../src/analysis/simulationVerdict.js";
import { StateLock } from "../../src/analysis/stateLock.js";
import {
  emptyState,
  type Finding,
  type InvestigationState,
  type Severity,
} from "../../src/analysis/stateTypes.js";
import type { SecondOpinion } from "../../src/analysis/secondOpinion.js";

const T = "2026-09-24T09:04:00.000Z";

const finding = (id: string, severity: Severity, title: string, confidence = 90): Finding => ({
  id,
  severity,
  confidence,
  title,
  description: "d",
  relatedIocs: [],
  sourceScreenshots: [],
  mitreTechniques: [],
  relatedEventIds: [`e-${id}`],
  firstSeen: T,
  lastUpdated: T,
  status: "open",
});

function simulatedState(): InvestigationState {
  const s = emptyState("c1");
  s.forensicTimeline = ["e-f1", "e-f14"].map((id) => ({
    id,
    timestamp: T,
    description: "row",
    severity: "High" as const,
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    asset: "ws-01.example.com",
  }));
  s.findings = applySimulationVerdict(
    [
      finding("f1", "Critical", "Mimikatz executed against LSASS"),
      finding("f14", "Info", "Activity is likely an authorized attack-simulation exercise", 85),
    ],
    s.forensicTimeline,
  );
  return s;
}

const RECORD = {
  generatedAt: T,
  modelA: "a",
  modelB: "b",
  referee: "",
  summary: "",
  agreementCount: 0,
  deltas: [
    {
      id: "mitre_added:t1486",
      kind: "mitre_added",
      title: "T1486",
      techniqueName: "Data Encrypted for Impact",
      rationale: "",
      recommendation: "review",
      status: "pending",
    },
  ],
} as unknown as SecondOpinion;

function harness(treatAsReal: boolean) {
  let current = simulatedState();
  const saves: InvestigationState[] = [];
  let record = RECORD;
  const stateLock = new StateLock();
  const ctx = {
    opts: {
      stateLock,
      stateStore: {
        load: async () => current,
        save: async (s: InvestigationState) => {
          current = s;
          saves.push(s);
        },
      },
      secondOpinionStore: {
        load: async () => record,
        save: async (_: string, r: SecondOpinion) => {
          record = r;
        },
      },
      synthMetaStore: { treatAsReal: async () => treatAsReal },
      onState: () => {},
    },
  } as unknown as SecondOpinionContext;
  return { ctx, saves, stateLock, current: () => current };
}

describe("second-opinion decisions and the simulation verdict (#1595)", () => {
  it("honours an override the analyst saved before the decision", async () => {
    const h = harness(true);
    await applySecondOpinion(h.ctx, "c1", "mitre_added:t1486", true);
    const f1 = h.current().findings.find((f) => f.id === "f1");
    expect(f1?.severity).toBe("Critical");
    expect(f1?.simulation).toBeUndefined();
  });

  it("keeps the caps when there is no override", async () => {
    const h = harness(false);
    await applySecondOpinion(h.ctx, "c1", "mitre_added:t1486", true);
    expect(h.current().findings.find((f) => f.id === "f1")?.severity).toBe("Medium");
  });

  it("writes inside the state lock", async () => {
    const h = harness(false);
    let release!: () => void;
    const held = h.stateLock.runExclusive("c1", () => new Promise<void>((r) => (release = r)));
    const pending = applySecondOpinion(h.ctx, "c1", "mitre_added:t1486", true);
    await new Promise((r) => setTimeout(r, 20));
    expect(h.saves).toHaveLength(0);
    release();
    await held;
    await pending;
    expect(h.saves).toHaveLength(1);
  });
});
