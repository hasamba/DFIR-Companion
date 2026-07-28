import { describe, it, expect } from "vitest";
import {
  observedTechniqueSequence,
  observedSequences,
  matchPlaybook,
  rankPlaybooks,
  buildPlaybookMatchResult,
  BASE_MATCH_WEIGHT,
  DEFAULT_MIN_SCORE,
  PLAYBOOK_MATCH_CAVEAT,
  type ObservedSequence,
  type Playbook,
  type KnownPlaybooksDataset,
} from "../../src/analysis/playbookMatch.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

const ev = (
  id: string,
  timestamp: string,
  techniques: string[],
  asset?: string,
): ForensicEvent => ({
  id,
  timestamp,
  description: id,
  severity: "High",
  mitreTechniques: techniques,
  relatedFindingIds: [],
  sourceScreenshots: [],
  ...(asset ? { asset } : {}),
});

// A bare case-scope sequence from technique ids, for the tests that only care about order.
const seq = (...techniques: string[]): ObservedSequence => ({
  scope: "case",
  techniques: techniques.map((technique, i) => ({ technique, eventId: `e${i}` })),
});

const conti: Playbook = {
  name: "Conti",
  description: "",
  steps: [
    { technique: "T1566.001", name: "Spearphish" },
    { technique: "T1059.001", name: "PowerShell" },
    { technique: "T1003.001", name: "LSASS dump" },
    { technique: "T1021.002", name: "Lateral SMB" },
    { technique: "T1486", name: "Encryption" },
  ],
};

const dataset = (playbooks: Playbook[]): KnownPlaybooksDataset => ({
  source: "test",
  generated: "2026-07-24",
  playbooks,
});

// Matching is only meaningful if the chronology is right, so these guard the ordering itself.
describe("observedTechniqueSequence", () => {
  it("orders techniques chronologically by event timestamp", () => {
    const s = observedTechniqueSequence([
      ev("e2", "2026-01-02T00:00:00Z", ["T1003.001"]),
      ev("e1", "2026-01-01T00:00:00Z", ["T1566.001", "T1059.001"]),
    ]);
    expect(s.map((t) => t.technique)).toEqual(["T1566.001", "T1059.001", "T1003.001"]);
  });

  it("carries the source event id so a matched step can jump to its evidence", () => {
    const s = observedTechniqueSequence([ev("evt-42", "2026-01-01T00:00:00Z", ["T1486"])]);
    expect(s).toEqual([{ technique: "T1486", eventId: "evt-42" }]);
  });

  it("orders by real instant, not string order, across mixed UTC offsets", () => {
    // 10:00+02:00 is 08:00Z — genuinely BEFORE 09:00Z, though it sorts after as a string.
    const s = observedTechniqueSequence([
      ev("lsass", "2026-01-01T09:00:00Z", ["T1003.001"]),
      ev("phish", "2026-01-01T10:00:00+02:00", ["T1566.001"]),
    ]);
    expect(s.map((t) => t.technique)).toEqual(["T1566.001", "T1003.001"]);
    // …and the chain therefore reads as in-order rather than out-of-order.
    const m = matchPlaybook(conti, { scope: "case", techniques: s });
    expect(m.steps.map((x) => x.status)).toEqual([
      "matched",
      "missing",
      "matched",
      "missing",
      "missing",
    ]);
  });

  it("sorts an unparseable timestamp to the END, never to the front of the chain", () => {
    // A blank-timestamped encryption event at the head would make T1486 look like step one and
    // knock the real Impact step out-of-order in every playbook.
    const s = observedTechniqueSequence([
      ev("known", "2026-01-01T01:00:00Z", ["T1566.001"]),
      ev("undated", "", ["T1486"]),
    ]);
    expect(s.map((t) => t.technique)).toEqual(["T1566.001", "T1486"]);
  });

  it("drops non-technique ids and collapses adjacent duplicates", () => {
    const s = observedTechniqueSequence([
      ev("e1", "2026-01-01T00:00:00Z", ["nonsense", "T1059.001"]),
      ev("e2", "2026-01-01T00:00:01Z", ["T1059.001", "T1486"]),
    ]);
    expect(s.map((t) => t.technique)).toEqual(["T1059.001", "T1486"]);
  });

  it("returns an empty sequence when no events carry techniques", () => {
    expect(observedTechniqueSequence([ev("e1", "2026-01-01T00:00:00Z", [])])).toEqual([]);
  });
});

describe("observedSequences", () => {
  it("adds a per-host scope alongside the case scope on a multi-host timeline", () => {
    const scopes = observedSequences([
      ev("e1", "2026-01-01T00:00:00Z", ["T1566.001"], "WKSTN01"),
      ev("e2", "2026-01-01T00:01:00Z", ["T1003.001"], "WKSTN01"),
      ev("e3", "2026-01-01T00:02:00Z", ["T1486"], "DC01"),
    ]);
    expect(scopes.map((s) => `${s.scope}:${s.host ?? "-"}`)).toEqual([
      "case:-",
      "host:DC01",
      "host:WKSTN01",
    ]);
    expect(scopes[0].techniques).toHaveLength(3);
  });

  it("skips host scopes on a single-host case (they would duplicate the case scope)", () => {
    const scopes = observedSequences([
      ev("e1", "2026-01-01T00:00:00Z", ["T1566.001"], "WKSTN01"),
      ev("e2", "2026-01-01T00:01:00Z", ["T1486"], "WKSTN01"),
    ]);
    expect(scopes).toHaveLength(1);
    expect(scopes[0].scope).toBe("case");
  });

  it("gives events with no recorded asset no host scope of their own", () => {
    // That bucket can hold several machines — treating it as one host would invent a chain.
    const scopes = observedSequences([
      ev("e1", "2026-01-01T00:00:00Z", ["T1566.001"]),
      ev("e2", "2026-01-01T00:01:00Z", ["T1486"], "DC01"),
    ]);
    expect(scopes.map((s) => s.scope)).toEqual(["case", "host"]);
    expect(scopes[1].host).toBe("DC01");
  });
});

describe("matchPlaybook", () => {
  it("scores a full in-order chain at 100 and marks all steps matched/exact", () => {
    const m = matchPlaybook(
      conti,
      seq("T1566.001", "T1059.001", "T1003.001", "T1021.002", "T1486"),
    );
    expect(m.score).toBe(100);
    expect(m.matchedCount).toBe(5);
    expect(m.exactCount).toBe(5);
    expect(m.missingCount).toBe(0);
    expect(m.outOfOrderCount).toBe(0);
    expect(m.steps.every((s) => s.status === "matched" && s.matchKind === "exact")).toBe(true);
  });

  it("reports the event id behind each matched step", () => {
    const events = [
      ev("phish", "2026-01-01T00:00:00Z", ["T1566.001"]),
      ev("ps", "2026-01-01T00:01:00Z", ["T1059.001"]),
    ];
    const m = matchPlaybook(conti, { scope: "case", techniques: observedTechniqueSequence(events) });
    expect(m.steps[0].matchedEventId).toBe("phish");
    expect(m.steps[1].matchedEventId).toBe("ps");
    expect(m.steps[2].matchedEventId).toBeUndefined(); // missing steps have no evidence to point at
  });

  it("allows unrelated techniques between playbook steps (subsequence match)", () => {
    const m = matchPlaybook(
      conti,
      seq("T1566.001", "T1190", "T1059.001", "T1105", "T1003.001", "T1078", "T1021.002", "T1486"),
    );
    expect(m.matchedCount).toBe(5);
    expect(m.missingCount).toBe(0);
    expect(m.score).toBe(100);
  });

  it("marks unseen steps missing and computes a partial score", () => {
    const m = matchPlaybook(conti, seq("T1566.001", "T1059.001"));
    expect(m.matchedCount).toBe(2);
    expect(m.missingCount).toBe(3);
    expect(m.score).toBe(40);
    expect(m.steps.map((s) => s.status)).toEqual([
      "matched",
      "matched",
      "missing",
      "missing",
      "missing",
    ]);
  });

  it("separates out-of-order steps from missing ones in the counts", () => {
    const m = matchPlaybook(conti, seq("T1003.001", "T1566.001", "T1059.001"));
    const lsass = m.steps.find((s) => s.step.technique === "T1003.001");
    expect(lsass?.status).toBe("out-of-order");
    expect(m.matchedCount).toBe(2);
    expect(m.outOfOrderCount).toBe(1);
    expect(m.missingCount).toBe(2); // only the two never seen at all
    // the three counts partition the playbook exactly, so a UI tally always adds up
    expect(m.matchedCount + m.outOfOrderCount + m.missingCount).toBe(conti.steps.length);
  });

  it("awards partial credit for a base-technique match and ranks it below an exact one", () => {
    // Playbook wants T1059.001 (PowerShell); case observed T1059.003 (cmd) — same base.
    const m = matchPlaybook(
      conti,
      seq("T1566.001", "T1059.003", "T1003.001", "T1021.002", "T1486"),
    );
    expect(m.matchedCount).toBe(5);
    expect(m.exactCount).toBe(4);
    const ps = m.steps.find((s) => s.step.technique === "T1059.001");
    expect(ps?.status).toBe("matched");
    expect(ps?.matchKind).toBe("base");
    expect(m.score).toBe(Math.round(((4 + BASE_MATCH_WEIGHT) / 5) * 100));
  });
});

describe("rankPlaybooks", () => {
  const lockbit: Playbook = {
    name: "LockBit",
    description: "",
    steps: [
      { technique: "T1190", name: "Exploit App" },
      { technique: "T1105", name: "Tool Transfer" },
      { technique: "T1071.001", name: "C2" },
      { technique: "T1486", name: "Encryption" },
    ],
  };

  it("ranks by score and drops playbooks that barely overlap", () => {
    // Conti's chain is observed end to end; LockBit shares only its final encryption step, which
    // is an overlap rather than a sequence — even with the score floor off it must not surface.
    const observed = seq("T1566.001", "T1059.001", "T1003.001", "T1021.002", "T1486");
    const ranked = rankPlaybooks([conti, lockbit], [observed], { topN: 3, minScore: 0 });
    expect(ranked.map((m) => m.name)).toEqual(["Conti"]);
    expect(ranked[0].score).toBe(100);
  });

  it("caps results at topN", () => {
    const many = Array.from({ length: 5 }, (_, i) => ({
      name: `P${i}`,
      description: "",
      steps: [
        { technique: "T1078", name: "Valid Accounts" },
        { technique: "T1486", name: "Encryption" },
      ],
    }));
    expect(rankPlaybooks(many, [seq("T1078", "T1486")], { topN: 2 })).toHaveLength(2);
  });

  it("returns nothing for an empty observed sequence", () => {
    expect(rankPlaybooks([conti, lockbit], [seq()])).toEqual([]);
  });

  it("drops a single-technique overlap — one shared step is not a sequence", () => {
    // T1486 alone hits every ransomware playbook's last step; reporting it as a ~20% match reads
    // as weak attribution rather than the non-signal it is.
    expect(rankPlaybooks([conti, lockbit], [seq("T1486")])).toEqual([]);
  });

  it("applies the score floor, and honours an explicit override", () => {
    const observed = [seq("T1566.001", "T1059.001")]; // 2 of Conti's 5 steps ⇒ 40
    expect(rankPlaybooks([conti], observed, { minScore: 60 })).toEqual([]);
    expect(rankPlaybooks([conti], observed, { minScore: DEFAULT_MIN_SCORE })).toHaveLength(1);
  });

  it("keeps a playbook's best-scoring scope and says which one it was", () => {
    // The full Conti chain plays out on WKSTN01; DC01 only ever shows encryption. Interleaved at
    // case scope the chain still holds, but the per-host slice is what makes it unambiguous.
    const scopes = observedSequences([
      ev("a", "2026-01-01T00:00:00Z", ["T1566.001"], "WKSTN01"),
      ev("b", "2026-01-01T00:01:00Z", ["T1059.001"], "WKSTN01"),
      ev("c", "2026-01-01T00:02:00Z", ["T1003.001"], "WKSTN01"),
      ev("d", "2026-01-01T00:03:00Z", ["T1021.002"], "WKSTN01"),
      ev("e", "2026-01-01T00:04:00Z", ["T1486"], "WKSTN01"),
      ev("f", "2026-01-01T00:05:00Z", ["T1486"], "DC01"),
    ]);
    const ranked = rankPlaybooks([conti], scopes);
    expect(ranked[0].score).toBe(100);
    expect(["case", "host"]).toContain(ranked[0].scope);
  });

  it("finds a chain on one host that the interleaved case timeline breaks", () => {
    // WKSTN01 runs the whole Conti chain, but tags PowerShell coarsely as T1059.003. A LATE,
    // unrelated T1059.001 on DC01 is an exact hit for that step, so at case scope the walk prefers
    // it and drags the cursor past everything after it — steps 3-5 fall out-of-order. The per-host
    // slice has no such decoy and keeps the real chain.
    const scopes = observedSequences([
      ev("a", "2026-01-01T00:00:00Z", ["T1566.001"], "WKSTN01"),
      ev("b", "2026-01-01T00:01:00Z", ["T1059.003"], "WKSTN01"),
      ev("c", "2026-01-01T00:02:00Z", ["T1003.001"], "WKSTN01"),
      ev("d", "2026-01-01T00:03:00Z", ["T1021.002"], "WKSTN01"),
      ev("e", "2026-01-01T00:04:00Z", ["T1486"], "WKSTN01"),
      ev("decoy", "2026-01-01T00:05:00Z", ["T1059.001"], "DC01"),
    ]);
    const caseOnly = matchPlaybook(conti, scopes[0]);
    expect(caseOnly.matchedCount).toBe(2);
    expect(caseOnly.outOfOrderCount).toBe(3);

    const best = rankPlaybooks([conti], scopes)[0];
    expect(best.scope).toBe("host");
    expect(best.host).toBe("WKSTN01");
    expect(best.matchedCount).toBe(5);
    expect(best.score).toBe(Math.round(((4 + BASE_MATCH_WEIGHT) / 5) * 100));
  });

  it("ranks an exact-heavy playbook above a base-heavy one at equal matched counts", () => {
    const exactPlaybook: Playbook = {
      name: "Exact",
      description: "",
      steps: [
        { technique: "T1059.001", name: "PowerShell" },
        { technique: "T1486", name: "Encryption" },
      ],
    };
    const basePlaybook: Playbook = {
      name: "Base",
      description: "",
      steps: [
        { technique: "T1059.003", name: "Cmd" },
        { technique: "T1486", name: "Encryption" },
      ],
    };
    const ranked = rankPlaybooks([basePlaybook, exactPlaybook], [seq("T1059.001", "T1486")]);
    expect(ranked[0].name).toBe("Exact");
    expect(ranked[0].exactCount).toBe(2);
    expect(ranked[1].exactCount).toBe(1);
  });
});

describe("buildPlaybookMatchResult", () => {
  it("derives the observed sequence from forensic events and returns matches + provenance", () => {
    const events = [
      ev("e1", "2026-01-01T00:00:00Z", ["T1566.001"]),
      ev("e2", "2026-01-01T00:01:00Z", ["T1059.001"]),
      ev("e3", "2026-01-01T00:02:00Z", ["T1003.001"]),
      ev("e4", "2026-01-01T00:03:00Z", ["T1021.002"]),
      ev("e5", "2026-01-01T00:04:00Z", ["T1486"]),
    ];
    const result = buildPlaybookMatchResult(events, dataset([conti]), { topN: 3 });
    expect(result.observed).toEqual([
      "T1566.001",
      "T1059.001",
      "T1003.001",
      "T1021.002",
      "T1486",
    ]);
    expect(result.matches).toHaveLength(1);
    expect(result.matches[0].name).toBe("Conti");
    expect(result.matches[0].score).toBe(100);
    expect(result.source).toBe("test");
    expect(result.generated).toBe("2026-07-24");
  });

  it("always carries the non-attribution caveat and the floor it applied", () => {
    const result = buildPlaybookMatchResult([], dataset([conti]));
    expect(result.caveat).toBe(PLAYBOOK_MATCH_CAVEAT);
    expect(result.caveat).toMatch(/not attribution/i);
    expect(result.minScore).toBe(DEFAULT_MIN_SCORE);
    expect(result.matches).toEqual([]);
  });

  it("respects topN", () => {
    const events = [
      ev("e1", "2026-01-01T00:00:00Z", ["T1078"]),
      ev("e2", "2026-01-01T00:01:00Z", ["T1486"]),
    ];
    const playbooks = Array.from({ length: 5 }, (_, i) => ({
      name: `P${i}`,
      description: "",
      steps: [
        { technique: "T1078", name: "Valid Accounts" },
        { technique: "T1486", name: "Encryption" },
      ],
    }));
    const result = buildPlaybookMatchResult(events, dataset(playbooks), { topN: 2 });
    expect(result.matches).toHaveLength(2);
  });
});
