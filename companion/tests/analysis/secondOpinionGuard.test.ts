import { describe, it, expect } from "vitest";
import {
  emptyState,
  type Finding,
  type ForensicEvent,
  type InvestigationQuestion,
  type InvestigationState,
} from "../../src/analysis/stateTypes.js";
import {
  buildReconcilePrompt,
  buildSecondOpinionDeltas,
  followRefereeStatus,
  mergeReconcileVerdicts,
  setAllPendingStatus,
  setDeltaStatus,
  type SecondOpinion,
} from "../../src/analysis/secondOpinion.js";
import {
  flagRefereeDismissals,
  guardCaseOf,
  openItemsOf,
  quotesEvidence,
  refereeContextBlock,
  refereeHints,
} from "../../src/analysis/secondOpinionGuard.js";
import { carryAcceptedDecisions } from "../../src/analysis/secondOpinionTargets.js";
import { secondOpinionSchema } from "../../src/analysis/secondOpinionStore.js";

// #1596 — INC-2026-005 in miniature. The referee dismissed the ransomware script block and the
// ransom-note contact address as "already covered", while q_impact said no encryption was seen and
// t6 still asked what the address was.

const CONTACT = "gogoogle-restore@example.com";

function finding(over: Partial<Finding> & Pick<Finding, "id" | "title">): Finding {
  return {
    severity: "High",
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

function event(id: string, description: string, over: Partial<ForensicEvent> = {}): ForensicEvent {
  return {
    id,
    timestamp: "2026-06-01T10:00:00.000Z",
    description,
    severity: "High",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    ...over,
  };
}

function question(
  over: Partial<InvestigationQuestion> & Pick<InvestigationQuestion, "id">,
): InvestigationQuestion {
  return { question: "", status: "answered", answer: "", pointer: "", ...over };
}

const EVENTS: ForensicEvent[] = [
  event(
    "e-sb",
    `PowerShell script block (EID 4104) bild_emulator.ps1: foreach ($f in $files) { Protect-File $f -Aes; Rename-Item $f "$f.google" }; Set-Content FileRecovery.txt "Contact ${CONTACT} to restore"`,
  ),
  event(
    "e-enc",
    "PowerShell script block (EID 4104): -EncodedCommand JABjAHIAZQBkACAAPQA= credential dump launcher",
    {
      mitreTechniques: ["T1003"],
    },
  ),
  event("e-brute", "PowerShell script block (EID 4104): brute-force launcher against 10 accounts", {
    mitreTechniques: ["T1110"],
  }),
  event("e-mk1", "YARA hit Mimikatz on C:\\Users\\Public\\mk.exe", { mitreTechniques: ["T1003.001"] }),
  event("e-mk2", "YARA hit Mimikatz on C:\\Users\\Public\\mk64.exe", { mitreTechniques: ["T1003.001"] }),
];

const A_FINDINGS: Finding[] = [
  finding({
    id: "f1",
    title: "Encoded credential-theft PowerShell",
    mitreTechniques: ["T1003"],
    relatedEventIds: ["e-enc"],
  }),
  finding({
    id: "f5",
    title: "Brute-force launcher script",
    mitreTechniques: ["T1110"],
    relatedEventIds: ["e-brute"],
  }),
  finding({ id: "f-auto-2e22", title: "Script Block Auditing (EID 4104)", relatedEventIds: ["e-sb"] }),
  finding({ id: "f23", title: `Ransom-note contact address ${CONTACT}`, relatedEventIds: ["e-sb"] }),
  finding({
    id: "f30",
    title: "Mimikatz YARA detection",
    mitreTechniques: ["T1003.001"],
    relatedEventIds: ["e-mk1"],
  }),
  finding({
    id: "f31",
    title: "Mimikatz YARA detection on mk64",
    mitreTechniques: ["T1003.001"],
    relatedEventIds: ["e-mk2"],
  }),
];

function caseA(over: Partial<InvestigationState> = {}): InvestigationState {
  return {
    ...emptyState("c1"),
    findings: A_FINDINGS,
    forensicTimeline: EVENTS,
    keyQuestions: [
      question({
        id: "q_impact",
        question: "What was the impact?",
        answer: "No file-encryption, ransom-note, or other destructive-impact event was observed.",
      }),
      question({
        id: "q_credential_access",
        question: "Which credentials were accessed?",
        answer: "Mimikatz dumped LSASS on the host",
      }),
      question({
        id: "q_initial",
        question: "What was the initial access vector?",
        answer: "Phishing email to user",
      }),
    ],
    openThreads: [
      {
        id: "t6",
        description: `What is the contact address ${CONTACT}?`,
        status: "open",
        openedAt: "",
        closedAt: null,
      },
      {
        id: "t7",
        description: "Which other host has tools staged in C:\\Users\\Public?",
        status: "open",
        openedAt: "",
        closedAt: null,
      },
      { id: "t9", description: "closed thread", status: "closed", openedAt: "", closedAt: "" },
    ],
    ...over,
  };
}

// Model B kept the credential findings and one Mimikatz hit, and dropped the rest.
const bOf = (keep: readonly Finding[]): InvestigationState => ({
  ...emptyState("c1"),
  findings: keep.map((f) => ({ ...f, id: `b-${f.id}` })),
});
const B = bOf([A_FINDINGS[0], A_FINDINGS[1], A_FINDINGS[4]]);
// Model B dropped BOTH Mimikatz hits.
const B_NO_MK = bOf([A_FINDINGS[0], A_FINDINGS[1]]);

function record(a: InvestigationState, b: InvestigationState = B): SecondOpinion {
  return {
    generatedAt: "2026-06-02T00:00:00.000Z",
    modelA: "A",
    modelB: "B",
    referee: "A",
    summary: "",
    agreementCount: 3,
    deltas: buildSecondOpinionDeltas(a, b),
  };
}

const aOnly = (so: SecondOpinion, findingId: string) =>
  so.deltas.find((d) => d.kind === "a_only" && d.finding?.id === findingId)!;

// The referee's INC-2026-005 verdicts: every drop accepted, reasons that quote nothing.
function refereeDismissesAll(
  so: SecondOpinion,
  rationale = "PowerShell content already covered under f1/f5",
): SecondOpinion {
  return mergeReconcileVerdicts(so, {
    summary: "",
    verdicts: so.deltas
      .filter((d) => d.kind === "a_only")
      .map((d) => ({ id: d.id, rationale, recommendation: "accept_b" as const })),
  });
}

describe("open items the referee is shown (#1596)", () => {
  it("lists open threads, unresolved questions and negative answers — not settled positive answers", () => {
    const ids = openItemsOf(caseA()).map((i) => i.id);
    expect(ids).toEqual(["t6", "t7", "q_impact"]);
  });

  it("puts the items and the rules into the referee's user prompt, with a hint under each last-support finding", () => {
    const a = caseA();
    const so = record(a);
    const gc = guardCaseOf(a, EVENTS);
    const prompt = buildReconcilePrompt(a, B, so.deltas, EVENTS, {
      block: refereeContextBlock(gc, so.deltas),
      hints: refereeHints(gc, so),
    });
    expect(prompt).toContain("OPEN QUESTIONS AND NEGATIVE ANSWERS (3)");
    expect(prompt).toContain("[q_impact] (negative answer) What was the impact?");
    expect(prompt).toContain("[t6] (open thread)");
    expect(prompt).toContain('"keep — answers <item id>"');
    const sbLine = prompt.split("\n").findIndex((l) => l.includes(aOnly(so, "f-auto-2e22").id));
    expect(prompt.split("\n")[sbLine + 1]).toMatch(/^ {2}! may be the only evidence for .*q_impact/);
    expect(prompt.split("\n")[sbLine + 1]).toContain("t6");
  });

  it("gives a plain duplicate no hint — its twin still bears on the same question", () => {
    const a = caseA();
    const hints = refereeHints(guardCaseOf(a, EVENTS), record(a));
    expect(hints.has(aOnly(record(a), "f31").id)).toBe(false);
  });

  it("adds nothing to the prompt when no A-only finding is in dispute", () => {
    expect(refereeContextBlock(guardCaseOf(caseA(), EVENTS), [])).toBe("");
  });
});

describe("flagRefereeDismissals (#1596)", () => {
  it("flags both INC-2026-005 dismissals, linked to q_impact and t6", () => {
    const a = caseA();
    const flagged = flagRefereeDismissals(refereeDismissesAll(record(a)), guardCaseOf(a, EVENTS));
    const sb = aOnly(flagged, "f-auto-2e22").refereeFlags ?? [];
    const contact = aOnly(flagged, "f23").refereeFlags ?? [];
    expect(sb.map((f) => (f.kind === "answers_open_item" ? f.itemId : f.kind))).toEqual(
      expect.arrayContaining(["q_impact", "t6", "unquoted_reason"]),
    );
    expect(contact.map((f) => (f.kind === "answers_open_item" ? f.itemId : f.kind))).toEqual(
      expect.arrayContaining(["t6", "unquoted_reason"]),
    );
    expect(sb.find((f) => f.kind === "answers_open_item" && f.itemId === "q_impact")).toMatchObject({
      itemKind: "negative",
    });
  });

  it("still lets a plain duplicate go: a second Mimikatz YARA hit with a quoted reason is not flagged", () => {
    const a = caseA();
    const so = mergeReconcileVerdicts(record(a), {
      summary: "",
      verdicts: [
        {
          id: aOnly(record(a), "f31").id,
          rationale: 'Duplicate of f30: both are "YARA hit Mimikatz on C:\\Users\\Public\\mk" detections.',
          recommendation: "accept_b",
        },
      ],
    });
    const flagged = flagRefereeDismissals(so, guardCaseOf(a, EVENTS));
    expect(aOnly(flagged, "f31").refereeFlags).toBeUndefined();
    expect(followRefereeStatus(flagged).deltas.find((d) => d.id === aOnly(so, "f31").id)?.status).toBe(
      "accepted",
    );
  });

  it("protects BOTH twins when the referee dismisses both in the same pass", () => {
    const a = caseA();
    const flagged = flagRefereeDismissals(
      refereeDismissesAll(record(a, B_NO_MK), 'dup "YARA hit Mimikatz"'),
      guardCaseOf(a, EVENTS),
    );
    expect(aOnly(flagged, "f30").refereeFlags?.some((f) => f.kind === "answers_open_item")).toBe(true);
    expect(aOnly(flagged, "f31").refereeFlags?.some((f) => f.kind === "answers_open_item")).toBe(true);
  });

  it("does not count an already-dismissed finding as surviving support", () => {
    const a = caseA({
      findings: A_FINDINGS.map((f) => (f.id === "f30" ? { ...f, status: "dismissed" as const } : f)),
    });
    const so = mergeReconcileVerdicts(record(caseA()), {
      summary: "",
      verdicts: [
        {
          id: aOnly(record(caseA()), "f31").id,
          rationale: '"YARA hit Mimikatz"',
          recommendation: "accept_b",
        },
      ],
    });
    const flagged = flagRefereeDismissals(so, guardCaseOf(a, EVENTS));
    expect(aOnly(flagged, "f31").refereeFlags?.[0]).toMatchObject({ itemId: "t7", itemKind: "thread" });
  });

  it("does not count a twin already accepted for dismissal as surviving support", () => {
    const a = caseA();
    const base = record(a, B_NO_MK);
    const decided = setDeltaStatus(base, aOnly(base, "f30").id, "accepted");
    const so = mergeReconcileVerdicts(decided, {
      summary: "",
      verdicts: [{ id: aOnly(base, "f31").id, rationale: '"YARA hit Mimikatz"', recommendation: "accept_b" }],
    });
    const flagged = flagRefereeDismissals(so, guardCaseOf(a, EVENTS));
    expect(aOnly(flagged, "f31").refereeFlags?.some((f) => f.kind === "answers_open_item")).toBe(true);
  });

  it("flags only fresh pending accept_b dismissals, and clears stale flags", () => {
    const a = caseA();
    const once = flagRefereeDismissals(refereeDismissesAll(record(a)), guardCaseOf(a, EVENTS));
    const id = aOnly(once, "f23").id;
    const decided = setDeltaStatus(once, id, "rejected");
    expect(aOnly(decided, "f23").refereeFlags).toBeUndefined();
    const again = flagRefereeDismissals(decided, guardCaseOf(a, EVENTS));
    expect(aOnly(again, "f23").refereeFlags).toBeUndefined();
    const keep = mergeReconcileVerdicts(once, {
      summary: "",
      verdicts: [{ id, rationale: "keep", recommendation: "keep_a" }],
    });
    expect(aOnly(flagRefereeDismissals(keep, guardCaseOf(a, EVENTS)), "f23").refereeFlags).toBeUndefined();
  });
});

describe("quotesEvidence (#1596)", () => {
  const text = EVENTS[0].description;
  it("accepts a verbatim quoted span of the cited events", () => {
    expect(quotesEvidence('covered: "Rename-Item $f \\"$f.google\\"" no', text)).toBe(false); // mangled quote
    expect(quotesEvidence('same script: "Set-Content FileRecovery.txt"', text)).toBe(true);
    expect(quotesEvidence("same script: “bild_emulator.ps1: foreach”", text)).toBe(true);
  });
  it("rejects a reason that quotes nothing, or quotes a claim that is not in the events", () => {
    expect(quotesEvidence("PowerShell content already covered under f1/f5", text)).toBe(false);
    expect(quotesEvidence('"encoded credential-theft launcher"', text)).toBe(false);
    expect(quotesEvidence('"Aes"', text)).toBe(false); // too short to be a quote
    // An unquoted exact copy is not a quote.
    expect(quotesEvidence("Set-Content FileRecovery.txt Contact", text)).toBe(false);
  });
  it("accepts an elided quote when every kept piece is verbatim", () => {
    expect(quotesEvidence('"PowerShell script block … Set-Content FileRecovery.txt"', text)).toBe(true);
  });
});

describe("bulk actions hold flagged dismissals for the analyst (#1596)", () => {
  const a = caseA();
  const flagged = flagRefereeDismissals(refereeDismissesAll(record(a)), guardCaseOf(a, EVENTS));
  const sbId = aOnly(flagged, "f-auto-2e22").id;

  it("follow referee leaves a flagged dismissal pending", () => {
    expect(followRefereeStatus(flagged).deltas.find((d) => d.id === sbId)?.status).toBe("pending");
  });
  it("accept all leaves it pending too; reject all still rejects it", () => {
    expect(setAllPendingStatus(flagged, "accepted").deltas.find((d) => d.id === sbId)?.status).toBe(
      "pending",
    );
    const rejected = setAllPendingStatus(flagged, "rejected").deltas.find((d) => d.id === sbId);
    expect(rejected?.status).toBe("rejected");
    expect(rejected?.refereeFlags).toBeUndefined();
  });
  it("an individual accept still works and settles the flags", () => {
    const d = setDeltaStatus(flagged, sbId, "accepted").deltas.find((x) => x.id === sbId);
    expect(d?.status).toBe("accepted");
    expect(d?.refereeFlags).toBeUndefined();
  });
  it("carried accepted decisions keep no flags", () => {
    const accepted = {
      ...flagged,
      deltas: flagged.deltas.map((d) => (d.id === sbId ? { ...d, status: "accepted" as const } : d)),
    };
    const next = carryAcceptedDecisions(accepted, { ...record(a), generatedAt: "2026-06-03T00:00:00.000Z" });
    expect(next.deltas.find((d) => d.id === sbId)?.refereeFlags).toBeUndefined();
  });
});

describe("stored flags fail safe (#1596)", () => {
  const base = {
    generatedAt: "t",
    deltas: [
      {
        id: "a_only:x",
        kind: "a_only",
        title: "x",
        status: "pending",
        recommendation: "accept_b",
        rationale: "",
      },
    ],
  };
  it("round-trips a valid flag", () => {
    const parsed = secondOpinionSchema.parse({
      ...base,
      deltas: [
        {
          ...base.deltas[0],
          refereeFlags: [{ kind: "answers_open_item", itemId: "t6", itemKind: "thread", text: "x" }],
        },
      ],
    });
    expect(parsed.deltas[0]?.refereeFlags).toEqual([
      { kind: "answers_open_item", itemId: "t6", itemKind: "thread", text: "x" },
    ]);
  });
  it("loads a malformed flag as a blocking 'unreadable' flag, never as none", () => {
    const parsed = secondOpinionSchema.parse({
      ...base,
      deltas: [{ ...base.deltas[0], refereeFlags: [{ kind: "bogus" }] }],
    });
    expect(parsed.deltas[0]?.refereeFlags).toEqual([{ kind: "unreadable" }]);
  });
  it("loads a record with no flags as having none", () => {
    expect(secondOpinionSchema.parse(base).deltas[0]?.refereeFlags).toBeUndefined();
  });
});
