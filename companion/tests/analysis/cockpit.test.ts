import { describe, expect, it } from "vitest";
import { deriveCockpit, type CockpitDecisionState } from "../../src/analysis/cockpit.js";
import type { ImportMeta } from "../../src/analysis/importMeta.js";
import { emptyState, type InvestigationState } from "../../src/analysis/stateTypes.js";
import type { Hypothesis } from "../../src/analysis/hypothesis.js";

const NOW = "2026-07-30T12:00:00.000Z";
const RECENT_IMPORT = {
  lastImportedAt: "2026-07-30T11:45:00.000Z",
  lastImportKind: "velociraptor",
  lastImportFile: "Windows.Forensics.CertUtil.json",
  addedCount: 0,
  removedCount: 0,
  lastDiff: { added: [], removed: [] },
  iocsAddedCount: 0,
  iocsRemovedCount: 0,
  iocsDiff: { added: [], removed: [] },
  linesIn: 17,
  path: "deterministic",
  fpPropagation: [],
  truncation: null,
} satisfies ImportMeta;

function state(overrides: Partial<InvestigationState> = {}): InvestigationState {
  return {
    ...emptyState("case-375"),
    updatedAt: "2026-07-30T11:00:00.000Z",
    ...overrides,
  };
}

function finding(
  id: string,
  severity: "Critical" | "High" | "Medium" | "Low" = "High",
  overrides: Partial<InvestigationState["findings"][number]> = {},
): InvestigationState["findings"][number] {
  return {
    id,
    severity,
    confidence: 80,
    title: `Finding ${id}`,
    description: `Description ${id}`,
    relatedIocs: [],
    sourceScreenshots: [],
    mitreTechniques: [],
    relatedEventIds: [`e-${id}`],
    firstSeen: "2026-07-30T09:00:00.000Z",
    lastUpdated: "2026-07-30T11:30:00.000Z",
    status: "open",
    ...overrides,
  };
}

function hypothesis(overrides: Partial<Hypothesis> = {}): Hypothesis {
  return {
    id: "h1",
    title: "Credential theft enabled lateral movement",
    description: "Test the credential-access explanation.",
    expectedOutcome: "Credential access artifacts on WS-01.",
    status: "open",
    relatedTechniques: ["T1003"],
    relatedEventIds: ["e-f1"],
    relatedIocIds: [],
    contradictingEventIds: ["e-contradiction"],
    discriminator: "Collect LSASS access telemetry from WS-01.",
    exhausted: false,
    exhaustedReason: "",
    assignee: "",
    notes: "",
    source: "synthesis",
    analystTouched: false,
    needsReview: false,
    sourceKey: "synth:h1",
    createdAt: "2026-07-30T10:00:00.000Z",
    updatedAt: "2026-07-30T11:00:00.000Z",
    statusHistory: [{ status: "open", changedAt: "2026-07-30T10:00:00.000Z" }],
    ...overrides,
  };
}

describe("deriveCockpit — investigator usability scenarios", () => {
  it("gives triage an actionable empty state instead of an empty dashboard", () => {
    const result = deriveCockpit({ state: state(), investigator: "Alice", now: NOW });

    expect(result.phase).toBe("triage");
    expect(result.sections.leads).toEqual([]);
    expect(result.sections.gaps[0]).toMatchObject({
      id: "gap:import-evidence",
      title: "Import the first evidence",
      target: { panel: "import" },
    });
    expect(result.readiness.ready).toBe(false);
    expect(result.readiness.blockers.map((card) => card.id)).toContain("blocker:no-evidence");
  });

  it("surfaces ranked leads, contradictions, collection actions, failures, and exact evidence in an active investigation", () => {
    const investigation = state({
      findings: [
        finding("f1", "Critical", { confidence: 94, title: "Domain admin credential theft" }),
        finding("f2", "High", { confidence: 72 }),
        finding("f3", "Medium", { confidence: 88 }),
        finding("f4", "Low", { confidence: 99 }),
      ],
      forensicTimeline: [
        {
          id: "e-f1",
          timestamp: "2026-07-30T09:15:00.000Z",
          description: "LSASS access on WS-01",
          severity: "Critical",
          mitreTechniques: ["T1003"],
          relatedFindingIds: ["f1"],
          sourceScreenshots: [],
        },
        {
          id: "e-contradiction",
          timestamp: "2026-07-30T09:20:00.000Z",
          description: "Outbound transfer observed",
          severity: "High",
          mitreTechniques: ["T1041"],
          relatedFindingIds: [],
          sourceScreenshots: [],
        },
      ],
      keyQuestions: [
        {
          id: "q1",
          question: "Was data exfiltrated?",
          status: "partial",
          answer: "No exfiltration was confirmed.",
          pointer: "Proxy logs are incomplete.",
          contradicted: { techniques: ["T1041"], eventIds: ["e-contradiction"] },
          collect: {
            host: "proxy-01",
            logSource: "proxy access logs",
            expectedOutcome: "Confirm or refute outbound transfer.",
          },
        },
      ],
      uncertainties: [
        {
          topic: "Initial access",
          status: "speculated",
          basis: "No primary source yet.",
          gap: "Collect mailbox audit and message trace for the affected user.",
        },
      ],
    });

    const result = deriveCockpit({
      state: investigation,
      hypotheses: [hypothesis()],
      jobs: [
        {
          id: "job_1",
          caseId: investigation.caseId,
          kind: "import",
          status: "failed",
          priority: "normal",
          queuedAt: "2026-07-30T11:45:00.000Z",
          startedAt: "2026-07-30T11:45:00.000Z",
          endedAt: "2026-07-30T11:46:00.000Z",
          updatedAt: "2026-07-30T11:46:00.000Z",
          error: "Parser rejected the archive",
          warnings: [],
          attempt: 1,
          maxRetries: 0,
          resumable: false,
          cancellable: false,
        },
      ],
      investigator: "Alice",
      now: NOW,
    });

    expect(result.phase).toBe("active-investigation");
    expect(result.sections.leads).toHaveLength(3);
    expect(result.sections.leads[0]).toMatchObject({
      id: "lead:finding:f1",
      severity: "Critical",
      evidenceIds: ["e-f1"],
      target: { panel: "findings", findingId: "f1", eventId: "e-f1" },
    });
    expect(result.sections.contradictions.map((card) => card.id)).toEqual(
      expect.arrayContaining(["contradiction:question:q1", "contradiction:hypothesis:h1"]),
    );
    expect(result.sections.gaps.find((card) => card.id === "gap:question:q1")?.action).toContain(
      "proxy access logs",
    );
    expect(result.sections.activity[0]).toMatchObject({
      id: "activity:job:job_1",
      severity: "High",
      target: { panel: "jobs", jobId: "job_1" },
    });
    expect(result.readiness.ready).toBe(false);
  });

  it("moves a fully triaged case into report preparation with no blockers", () => {
    const result = deriveCockpit({
      state: state({
        findings: [finding("f1", "High", { status: "confirmed" })],
        forensicTimeline: [
          {
            id: "e-f1",
            timestamp: "2026-07-30T09:15:00.000Z",
            description: "Confirmed malicious execution",
            severity: "High",
            mitreTechniques: [],
            relatedFindingIds: ["f1"],
            sourceScreenshots: [],
          },
        ],
        keyQuestions: [
          {
            id: "q1",
            question: "What happened?",
            status: "answered",
            answer: "Malicious execution was confirmed.",
            pointer: "f1",
          },
        ],
        lastSummary: "Confirmed malicious execution on WS-01.",
        attackerPath: "Initial execution led to credential access.",
      }),
      investigator: "Alice",
      now: NOW,
    });

    expect(result.phase).toBe("report-preparation");
    expect(result.readiness).toMatchObject({ ready: true, blockers: [] });
  });
});

describe("deriveCockpit — review and card decisions", () => {
  it("keeps a running job card stable while its detailed progress changes", () => {
    const investigation = state();
    const job = {
      id: "job_live",
      caseId: investigation.caseId,
      kind: "import" as const,
      label: "security.evtx",
      status: "running" as const,
      priority: "normal" as const,
      queuedAt: "2026-07-30T11:45:00.000Z",
      startedAt: "2026-07-30T11:45:00.000Z",
      updatedAt: "2026-07-30T11:46:00.000Z",
      warnings: [],
      attempt: 1,
      maxRetries: 0,
      resumable: true,
      cancellable: true,
    };
    const first = deriveCockpit({
      state: investigation,
      jobs: [{ ...job, detail: "reading Windows events 100/1000" }],
      investigator: "Alice",
      now: NOW,
    });
    const second = deriveCockpit({
      state: investigation,
      jobs: [{ ...job, detail: "reading Windows events 900/1000" }],
      investigator: "Alice",
      now: NOW,
    });

    expect(first.sections.activity[0].summary).toBe("security.evtx");
    expect(second.sections.activity[0].summary).toBe(first.sections.activity[0].summary);
  });

  it("shows only changes after this investigator's last review", () => {
    const result = deriveCockpit({
      state: state({
        findings: [
          finding("old", "High", { lastUpdated: "2026-07-29T08:00:00.000Z" }),
          finding("new", "Critical", { lastUpdated: "2026-07-30T11:30:00.000Z" }),
        ],
      }),
      synthMeta: {
        lastSynthesizedAt: "2026-07-30T11:40:00.000Z",
        lastDiff: { added: ["new"], removed: [], severityChanged: [] },
      },
      decisions: {
        cards: [],
        reviews: [
          { investigatorKey: "alice", investigator: "Alice", reviewedAt: "2026-07-30T10:00:00.000Z" },
        ],
        history: [],
      },
      investigator: "Alice",
      now: NOW,
    });

    expect(result.lastReviewedAt).toBe("2026-07-30T10:00:00.000Z");
    expect(result.sections.changes.map((card) => card.id)).toContain("change:finding:new");
    expect(result.sections.changes.map((card) => card.id)).not.toContain("change:finding:old");
    expect(result.newSinceReview).toBeGreaterThan(0);
  });

  it("reports forensic and super-timeline additions from the latest import", () => {
    const result = deriveCockpit({
      state: state(),
      importMeta: {
        ...RECENT_IMPORT,
        superTimelineAddedCount: 17,
      },
      investigator: "Alice",
      now: NOW,
    });

    expect(result.sections.changes[0]).toMatchObject({
      title: "Import added 0 forensic events · 17 super-timeline events",
      severity: "Medium",
      target: { panel: "super-timeline" },
    });

    const legacy = deriveCockpit({
      state: state(),
      importMeta: RECENT_IMPORT,
      investigator: "Alice",
      now: NOW,
    });
    expect(legacy.sections.changes[0].title).toBe(
      "Import added 0 forensic events · super-timeline count unavailable",
    );
  });

  it("normalizes an unknown synthesis severity instead of destabilizing card ranking", () => {
    const result = deriveCockpit({
      state: state(),
      synthMeta: {
        lastSynthesizedAt: "2026-07-30T11:40:00.000Z",
        lastDiff: {
          added: [],
          removed: [],
          severityChanged: [{ title: "Legacy finding", from: "High", to: "Urgent" }],
        },
      },
      investigator: "Alice",
      now: NOW,
    });

    expect(result.sections.changes[0]).toMatchObject({
      id: "change:severity:Legacy finding",
      severity: "Info",
    });
  });

  it("sorts pins first and parks dismissed or not-yet-due deferred cards without deleting them", () => {
    const decisions: CockpitDecisionState = {
      cards: [
        { cardId: "lead:finding:f2", pinned: true, assignee: "Bob", updatedAt: NOW, updatedBy: "Alice" },
        {
          cardId: "lead:finding:f1",
          dismissedAt: "2026-07-30T11:00:00.000Z",
          updatedAt: NOW,
          updatedBy: "Alice",
        },
        {
          cardId: "lead:finding:f3",
          deferredUntil: "2026-07-31T12:00:00.000Z",
          updatedAt: NOW,
          updatedBy: "Alice",
        },
      ],
      reviews: [],
      history: [],
    };
    const result = deriveCockpit({
      state: state({ findings: [finding("f1", "Critical"), finding("f2", "High"), finding("f3", "Medium")] }),
      decisions,
      investigator: "Alice",
      now: NOW,
    });

    expect(result.sections.leads[0]).toMatchObject({ id: "lead:finding:f2", pinned: true, assignee: "Bob" });
    expect(result.sections.leads.map((card) => card.id)).not.toContain("lead:finding:f1");
    expect(result.sections.leads.map((card) => card.id)).not.toContain("lead:finding:f3");
    expect(result.parked.map((card) => card.id)).toEqual(
      expect.arrayContaining(["lead:finding:f1", "lead:finding:f3"]),
    );
  });

  it("lets authoritative finding pin and owner stores override stale cockpit decisions", () => {
    const result = deriveCockpit({
      state: state({ findings: [finding("f1", "High")] }),
      pinnedFindingIds: ["f1"],
      workflows: [
        {
          findingId: "f1",
          assignee: "Carol",
          status: "in_progress",
          updatedAt: NOW,
          updatedBy: "Carol",
        },
      ],
      decisions: {
        cards: [
          {
            cardId: "lead:finding:f1",
            pinned: false,
            assignee: "Bob",
            updatedAt: "2026-07-29T10:00:00.000Z",
            updatedBy: "Bob",
          },
        ],
        reviews: [],
        history: [],
      },
      investigator: "Alice",
      now: NOW,
    });

    expect(result.sections.leads[0]).toMatchObject({ pinned: true, assignee: "Carol" });
  });
});

// The near-duplicate host gate (#572) blocks synthesis before a prompt is built. Until this suite,
// the only cockpit trace of that hold was the FAILED synthesis job it left behind — an activity card
// pointing at Background Jobs, which cannot merge anything. The blocker below is the cockpit's own
// account of the hold, and it targets the panel that carries the two decision buttons.
describe("deriveCockpit host-duplicate blocker", () => {
  const pair = { canonical: "win11.windomain.local", other: "win11", reason: "shortname-fqdn" as const };

  it("raises a blocker naming both spellings and targeting the merge panel", () => {
    const result = deriveCockpit({
      state: state({ findings: [finding("f1")] }),
      hostDuplicates: [pair],
      investigator: "Alice",
      now: NOW,
    });

    const card = result.readiness.blockers.find((item) => item.id === "blocker:host-duplicates");
    expect(card).toMatchObject({
      kind: "blocker",
      severity: "Critical",
      target: { panel: "host-duplicates" },
    });
    expect(card?.title).toContain("1 host");
    expect(card?.summary).toContain("win11.windomain.local");
    expect(card?.summary).toContain("win11");
  });

  it("counts the pairs and names only the first two in the summary", () => {
    const result = deriveCockpit({
      state: state(),
      hostDuplicates: [
        pair,
        { canonical: "dc01.windomain.local", other: "dc01", reason: "shortname-fqdn" as const },
        { canonical: "srv02.windomain.local", other: "srv02", reason: "shortname-fqdn" as const },
      ],
      now: NOW,
    });

    const card = result.readiness.blockers.find((item) => item.id === "blocker:host-duplicates");
    expect(card?.title).toContain("3 hosts");
    expect(card?.summary).toContain("dc01");
    expect(card?.summary).not.toContain("srv02");
  });

  // The field is optional so every existing caller keeps compiling; an absent list must read as
  // "nothing pending", never as "unknown, so warn".
  it("raises nothing when no pair is pending, and nothing when the field is absent", () => {
    const withEmpty = deriveCockpit({ state: state(), hostDuplicates: [], now: NOW });
    const withoutField = deriveCockpit({ state: state(), now: NOW });
    for (const result of [withEmpty, withoutField]) {
      expect(result.readiness.blockers.map((card) => card.id)).not.toContain("blocker:host-duplicates");
    }
  });

  // A case whose ONLY outstanding item is the merge decision must not read as report-ready.
  it("keeps the case out of report-ready while a pair is pending", () => {
    const ready = {
      state: state({
        findings: [finding("f1", "High", { status: "confirmed" })],
        forensicTimeline: [
          {
            id: "e-f1",
            timestamp: "2026-07-30T09:15:00.000Z",
            description: "LSASS access on WS-01",
            severity: "Critical" as const,
            mitreTechniques: ["T1003"],
            relatedFindingIds: ["f1"],
            sourceScreenshots: [],
          },
        ],
        lastSummary: "Summary",
        attackerPath: "Path",
      }),
      now: NOW,
    };
    expect(deriveCockpit(ready).readiness.ready).toBe(true);
    expect(deriveCockpit({ ...ready, hostDuplicates: [pair] }).readiness.ready).toBe(false);
  });
});
