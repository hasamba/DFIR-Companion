import { describe, expect, it } from "vitest";
import {
  deriveCockpitStory,
  STORY_STAGE_EVENT_LIMIT,
  STORY_STAGE_ORDER,
} from "../../src/analysis/cockpitStory.js";
import {
  emptyState,
  type Finding,
  type ForensicEvent,
  type InvestigationState,
} from "../../src/analysis/stateTypes.js";
import type { SynthMeta } from "../../src/analysis/synthMeta.js";

const SYNTH_AT = "2026-07-30T11:00:00.000Z";

function state(overrides: Partial<InvestigationState> = {}): InvestigationState {
  return {
    ...emptyState("case-1487"),
    updatedAt: "2026-07-30T11:00:00.000Z",
    ...overrides,
  };
}

function event(id: string, overrides: Partial<ForensicEvent> = {}): ForensicEvent {
  return {
    id,
    timestamp: "2026-07-30T09:00:00.000Z",
    description: `Event ${id}`,
    severity: "High",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    ...overrides,
  };
}

function finding(id: string, overrides: Partial<Finding> = {}): Finding {
  return {
    id,
    severity: "High",
    title: `Finding ${id}`,
    description: `Description ${id}`,
    relatedIocs: [],
    sourceScreenshots: [],
    mitreTechniques: [],
    relatedEventIds: [],
    firstSeen: "2026-07-30T09:00:00.000Z",
    lastUpdated: "2026-07-30T11:30:00.000Z",
    status: "open",
    ...overrides,
  };
}

function synthMeta(overrides: Partial<SynthMeta> = {}): SynthMeta {
  return { lastSynthesizedAt: SYNTH_AT, lastDiff: null, ...overrides };
}

describe("deriveCockpitStory — stage chain", () => {
  it("orders stages by STORY_STAGE_ORDER whatever order the events arrive in", () => {
    const story = deriveCockpitStory(
      state({
        forensicTimeline: [
          event("exfil", { mitreTechniques: ["T1041"], timestamp: "2026-07-30T12:00:00.000Z" }),
          event("cred", { mitreTechniques: ["T1003"], timestamp: "2026-07-30T10:00:00.000Z" }),
          event("phish", { mitreTechniques: ["T1566"], timestamp: "2026-07-30T08:00:00.000Z" }),
        ],
      }),
    );

    expect(story.stages.map((stage) => stage.tactic)).toEqual([
      "Initial Access",
      "Credential Access",
      "Exfiltration",
    ]);
    expect(STORY_STAGE_ORDER[0]).toBe("Initial Access");
    expect(STORY_STAGE_ORDER[STORY_STAGE_ORDER.length - 1]).toBe("Impact");
  });

  it("skips stages with no events and leaves nothing behind for an empty timeline", () => {
    const story = deriveCockpitStory(
      state({ forensicTimeline: [event("exec", { mitreTechniques: ["T1059"] })] }),
    );

    expect(story.stages).toHaveLength(1);
    expect(story.stages[0].tactic).toBe("Execution");
    expect(deriveCockpitStory(state()).stages).toEqual([]);
  });

  it("excludes Info events and events with no tactic", () => {
    const story = deriveCockpitStory(
      state({
        forensicTimeline: [
          event("info", { severity: "Info", mitreTechniques: ["T1566"] }),
          event("untagged", { description: "plain row", mitreTechniques: [] }),
          event("exec", { mitreTechniques: ["T1059"] }),
        ],
      }),
    );

    expect(story.stages.map((stage) => stage.tactic)).toEqual(["Execution"]);
    expect(story.stages[0].eventIds).toEqual(["exec"]);
  });

  it("takes firstSeenAt and host from the earliest timestamped event and counts every event", () => {
    const story = deriveCockpitStory(
      state({
        forensicTimeline: [
          event("late", {
            mitreTechniques: ["T1059"],
            timestamp: "2026-07-30T10:00:00.000Z",
            asset: "WS-02",
          }),
          event("no-time", { mitreTechniques: ["T1059"], timestamp: "", asset: "WS-09" }),
          event("bad-time", { mitreTechniques: ["T1059"], timestamp: "not a date", asset: "WS-08" }),
          event("early", {
            mitreTechniques: ["T1059"],
            timestamp: "2026-07-30T08:00:00.000Z",
            asset: "WS-01",
          }),
        ],
      }),
    );

    expect(story.stages).toHaveLength(1);
    expect(story.stages[0]).toMatchObject({
      tactic: "Execution",
      firstSeenAt: "2026-07-30T08:00:00.000Z",
      host: "WS-01",
      eventCount: 4,
    });
    expect(story.stages[0].eventIds.slice(0, 2)).toEqual(["early", "late"]);
  });

  it("reports a null host when the earliest event names no asset", () => {
    const story = deriveCockpitStory(
      state({ forensicTimeline: [event("exec", { mitreTechniques: ["T1059"] })] }),
    );

    expect(story.stages[0].host).toBeNull();
  });

  it("lists eventIds chronologically and caps them at STORY_STAGE_EVENT_LIMIT", () => {
    const events = Array.from({ length: STORY_STAGE_EVENT_LIMIT + 50 }, (_, index) =>
      event(`e-${index}`, {
        mitreTechniques: ["T1059"],
        timestamp: new Date(Date.UTC(2026, 6, 30, 0, 0, STORY_STAGE_EVENT_LIMIT + 50 - index)).toISOString(),
      }),
    );
    const story = deriveCockpitStory(state({ forensicTimeline: events }));

    expect(STORY_STAGE_EVENT_LIMIT).toBe(200);
    expect(story.stages[0].eventCount).toBe(STORY_STAGE_EVENT_LIMIT + 50);
    expect(story.stages[0].eventIds).toHaveLength(STORY_STAGE_EVENT_LIMIT);
    expect(story.stages[0].eventIds[0]).toBe(`e-${STORY_STAGE_EVENT_LIMIT + 49}`);
    expect(story.stages[0].eventIds[1]).toBe(`e-${STORY_STAGE_EVENT_LIMIT + 48}`);
  });
});

describe("deriveCockpitStory — stage cards: worst severity and headline", () => {
  it("reports the highest severity among the stage's events", () => {
    const story = deriveCockpitStory(
      state({
        forensicTimeline: [
          event("low", { severity: "Low", mitreTechniques: ["T1059"] }),
          event("crit", { severity: "Critical", mitreTechniques: ["T1059"] }),
          event("med", { severity: "Medium", mitreTechniques: ["T1059"] }),
          event("phish", { severity: "Medium", mitreTechniques: ["T1566"] }),
        ],
      }),
    );

    expect(story.stages.map((stage) => [stage.tactic, stage.worstSeverity])).toEqual([
      ["Initial Access", "Medium"],
      ["Execution", "Critical"],
    ]);
  });

  it("headlines the most severe event, earliest first on a tie, then timeline order", () => {
    const story = deriveCockpitStory(
      state({
        forensicTimeline: [
          event("high-late", {
            severity: "High",
            mitreTechniques: ["T1059"],
            timestamp: "2026-07-30T10:00:00.000Z",
            description: "Late high",
          }),
          event("crit-b", {
            severity: "Critical",
            mitreTechniques: ["T1059"],
            timestamp: "2026-07-30T09:00:00.000Z",
            description: "Critical B, same second",
          }),
          event("crit-a", {
            severity: "Critical",
            mitreTechniques: ["T1059"],
            timestamp: "2026-07-30T09:00:00.000Z",
            description: "Critical A, same second",
          }),
          event("crit-early", {
            severity: "Critical",
            mitreTechniques: ["T1059"],
            timestamp: "2026-07-30T08:00:00.000Z",
            description: "Critical, earliest",
          }),
        ],
      }),
    );

    expect(story.stages[0].headline).toEqual({ eventId: "crit-early", description: "Critical, earliest" });
  });

  it("breaks a severity-and-time tie by timeline order, and dated events beat undated ones", () => {
    const tied = deriveCockpitStory(
      state({
        forensicTimeline: [
          event("first", { mitreTechniques: ["T1059"], description: "First in the timeline" }),
          event("second", { mitreTechniques: ["T1059"], description: "Second in the timeline" }),
        ],
      }),
    );
    const undated = deriveCockpitStory(
      state({
        forensicTimeline: [
          event("no-time", { mitreTechniques: ["T1059"], timestamp: "", description: "Undated" }),
          event("dated", { mitreTechniques: ["T1059"], description: "Dated" }),
        ],
      }),
    );

    expect(tied.stages[0].headline?.eventId).toBe("first");
    expect(undated.stages[0].headline?.eventId).toBe("dated");
  });

  it("caps the headline description at 400 characters with an ellipsis", () => {
    const story = deriveCockpitStory(
      state({
        forensicTimeline: [event("long", { mitreTechniques: ["T1059"], description: "y".repeat(900) })],
      }),
    );

    expect(story.stages[0].headline?.description).toHaveLength(400);
    expect(story.stages[0].headline?.description.endsWith("…")).toBe(true);
  });

  it("drops the importer's artifact and tool labels from the headline — the card has no room for provenance", () => {
    const cases: Array<[string, string]> = [
      [
        "[Windows.EventLogs.Chainsaw] Chainsaw/Sigma: Windows Defender Disabled - EID 5001",
        "Windows Defender Disabled - EID 5001",
      ],
      [
        "Velociraptor [Windows.Sigma.Base] Sigma: User Added To Local Admin Grp - EID 4732",
        "User Added To Local Admin Grp - EID 4732",
      ],
      [
        "DetectRaptor Evtx detection: T1059.001-Mimikatz Execution via PowerShell",
        "T1059.001-Mimikatz Execution via PowerShell",
      ],
      [
        "[Windows.EventLogs.Chainsaw] Chainsaw/Log Tampering: Security Audit Log Cleared",
        "Security Audit Log Cleared",
      ],
      [
        "Velociraptor detection: HackTool:Mimikatz in C:\\Temp\\m.exe",
        "HackTool:Mimikatz in C:\\Temp\\m.exe",
      ],
      ["THOR Alert [Filescan]: Mimikatz dropped — C:\\Temp\\m.exe", "Mimikatz dropped — C:\\Temp\\m.exe"],
      ["Hayabusa/Sigma: Suspicious Service Installed", "Suspicious Service Installed"],
      [
        "Scheduled task: backup.exe registered by vagrant",
        "Scheduled task: backup.exe registered by vagrant",
      ],
      ["[Custom.Artifact] only a bracket", "only a bracket"],
      ["[Windows.EventLogs.Chainsaw] Chainsaw/Sigma:", "[Windows.EventLogs.Chainsaw] Chainsaw/Sigma:"],
    ];
    for (const [raw, shown] of cases) {
      const story = deriveCockpitStory(
        state({ forensicTimeline: [event("e", { mitreTechniques: ["T1059"], description: raw })] }),
      );
      expect(story.stages[0].headline?.description, raw).toBe(shown);
    }
  });

  it("has no headline when the only candidate has a blank description", () => {
    const story = deriveCockpitStory(
      state({ forensicTimeline: [event("blank", { mitreTechniques: ["T1059"], description: "   " })] }),
    );

    expect(story.stages[0].headline).toBeNull();
  });
});

describe("deriveCockpitStory — stage cards: linked finding", () => {
  const timeline = [
    event("exec-1", { mitreTechniques: ["T1059"], relatedFindingIds: ["from-event"] }),
    event("exec-2", { mitreTechniques: ["T1059"] }),
    event("phish", { mitreTechniques: ["T1566"] }),
  ];

  it("links a finding through either direction and is null for a stage with none", () => {
    const story = deriveCockpitStory(
      state({
        forensicTimeline: timeline,
        findings: [
          finding("from-event", { severity: "Medium" }),
          finding("from-finding", { severity: "Low", relatedEventIds: ["exec-2"] }),
          finding("elsewhere", { severity: "Critical", relatedEventIds: ["nope"] }),
        ],
      }),
    );

    expect(story.stages.map((stage) => stage.tactic)).toEqual(["Initial Access", "Execution"]);
    expect(story.stages[0].finding).toBeNull();
    expect(story.stages[1].finding).toEqual({
      id: "from-event",
      title: "Finding from-event",
      severity: "Medium",
    });
  });

  it("never surfaces a dismissed finding, whatever its severity", () => {
    const story = deriveCockpitStory(
      state({
        forensicTimeline: timeline,
        findings: [
          finding("dismissed", { severity: "Critical", status: "dismissed", relatedEventIds: ["exec-1"] }),
          finding("open", { severity: "Low", relatedEventIds: ["exec-1"] }),
        ],
      }),
    );

    expect(story.stages[1].finding?.id).toBe("open");
  });

  it("picks the highest severity, then confirmed over open, then the earliest firstSeen, then the id", () => {
    const linked = (id: string, overrides: Partial<Finding>) =>
      finding(id, { relatedEventIds: ["exec-2"], ...overrides });
    const pick = (findings: Finding[]) =>
      deriveCockpitStory(state({ forensicTimeline: timeline, findings })).stages[1].finding?.id;

    expect(pick([linked("high", { severity: "High" }), linked("crit", { severity: "Critical" })])).toBe(
      "crit",
    );
    expect(pick([linked("open", { status: "open" }), linked("confirmed", { status: "confirmed" })])).toBe(
      "confirmed",
    );
    expect(
      pick([
        linked("later", { firstSeen: "2026-07-30T10:00:00.000Z" }),
        linked("earlier", { firstSeen: "2026-07-30T08:00:00.000Z" }),
      ]),
    ).toBe("earlier");
    expect(pick([linked("b", {}), linked("a", {})])).toBe("a");
  });

  it("links through events beyond the eventIds cap", () => {
    const events = Array.from({ length: STORY_STAGE_EVENT_LIMIT + 1 }, (_, index) =>
      event(`e-${index}`, {
        mitreTechniques: ["T1059"],
        timestamp: new Date(Date.UTC(2026, 6, 30, 0, 0, index)).toISOString(),
      }),
    );
    const story = deriveCockpitStory(
      state({
        forensicTimeline: events,
        findings: [finding("tail", { relatedEventIds: [`e-${STORY_STAGE_EVENT_LIMIT}`] })],
      }),
    );

    expect(story.stages[0].eventIds).not.toContain(`e-${STORY_STAGE_EVENT_LIMIT}`);
    expect(story.stages[0].finding?.id).toBe("tail");
  });
});

describe("deriveCockpitStory — conclusion and attacker path", () => {
  it('paints a Markdown attacker path as plain text — list numbers and emphasis gone, no sentence made of a bare "1."', () => {
    const story = deriveCockpitStory(
      state({
        attackerPath:
          "1. **Initial Access (T1566.001)** — May 15: phishing to `jsmith`.\n2. **Execution** — macro spawned PowerShell.\n3. **Persistence** — run key.",
      }),
      synthMeta(),
    );
    expect(story.attackerPath).toBe(
      "Initial Access (T1566.001) — May 15: phishing to jsmith. Execution — macro spawned PowerShell.",
    );
  });
  it("keeps only the first two sentences of the summary and the attacker path", () => {
    const story = deriveCockpitStory(
      state({
        lastSummary: "The attacker phished an admin.  Then they dumped LSASS. Finally they left.",
        attackerPath: "Entry via email? Yes! Exfiltration followed over HTTPS.",
      }),
    );

    expect(story.conclusion).toBe("The attacker phished an admin. Then they dumped LSASS.");
    expect(story.attackerPath).toBe("Entry via email? Yes!");
  });

  it("returns an empty string for a blank summary and a whitespace-only path", () => {
    const story = deriveCockpitStory(state({ lastSummary: "", attackerPath: "   \n " }));

    expect(story.conclusion).toBe("");
    expect(story.attackerPath).toBe("");
  });

  it("hard-caps a huge sentence at 320 characters with an ellipsis", () => {
    const story = deriveCockpitStory(state({ lastSummary: "x".repeat(1000) }));

    expect(story.conclusion).toHaveLength(320);
    expect(story.conclusion.endsWith("…")).toBe(true);
  });
});

describe("deriveCockpitStory — synthesis freshness", () => {
  it("has no synthesizedAt and zero stale events when synthMeta is absent or blank", () => {
    const investigation = state({
      forensicTimeline: [
        event("exec", { mitreTechniques: ["T1059"], importedAt: "2026-07-30T11:30:00.000Z" }),
      ],
    });

    const absent = deriveCockpitStory(investigation);
    const blank = deriveCockpitStory(investigation, synthMeta({ lastSynthesizedAt: "" }));

    expect(absent.synthesizedAt).toBeNull();
    expect(absent.staleEventCount).toBe(0);
    expect(blank.synthesizedAt).toBeNull();
    expect(blank.staleEventCount).toBe(0);
  });

  it("counts forensic events imported after the last synthesis as stale", () => {
    const story = deriveCockpitStory(
      state({
        forensicTimeline: [
          event("before", { importedAt: "2026-07-30T10:59:00.000Z" }),
          event("same", { importedAt: SYNTH_AT }),
          event("after-1", { importedAt: "2026-07-30T11:01:00.000Z" }),
          event("after-2", { severity: "Info", importedAt: "2026-07-30T11:02:00.000Z" }),
          event("untracked"),
        ],
      }),
      synthMeta(),
    );

    expect(story.synthesizedAt).toBe(SYNTH_AT);
    expect(story.staleEventCount).toBe(2);
  });
});

describe("deriveCockpitStory — shape (#1493)", () => {
  it("spans the staged events only — an Info or untagged event outside the window never widens it", () => {
    const story = deriveCockpitStory(
      state({
        forensicTimeline: [
          event("info-early", {
            severity: "Info",
            mitreTechniques: ["T1566"],
            timestamp: "2026-07-29T00:00:00.000Z",
            asset: "IGNORED-A",
            description: "Noise for CORP\\ignored",
          }),
          event("untagged-late", {
            description: "plain row on CORP\\alsoignored",
            mitreTechniques: [],
            timestamp: "2026-08-02T00:00:00.000Z",
            asset: "IGNORED-B",
          }),
          event("exec", {
            mitreTechniques: ["T1059"],
            timestamp: "2026-07-30T10:00:00.000Z",
            asset: "WKSTN-JSMITH",
            description: "PowerShell run by CORP\\jsmith",
          }),
          event("phish", {
            mitreTechniques: ["T1566"],
            timestamp: "2026-07-30T08:00:00.000Z",
            asset: "WEB01",
            description: "Phish opened by CORP\\jsmith",
          }),
        ],
      }),
    );

    expect(story.shape).toEqual({
      firstAt: "2026-07-30T08:00:00.000Z",
      lastAt: "2026-07-30T10:00:00.000Z",
      dwellMs: 2 * 60 * 60 * 1000,
      hosts: ["WEB01", "WKSTN-JSMITH"],
      hostsTotal: 2,
      accounts: ["CORP\\jsmith"],
      accountsTotal: 1,
    });
  });

  it("uses a later endTimestamp for lastAt", () => {
    const story = deriveCockpitStory(
      state({
        forensicTimeline: [
          event("agg", {
            mitreTechniques: ["T1059"],
            timestamp: "2026-07-30T08:00:00.000Z",
            endTimestamp: "2026-07-30T12:00:00.000Z",
          }),
        ],
      }),
    );

    expect(story.shape.lastAt).toBe("2026-07-30T12:00:00.000Z");
    expect(story.shape.dwellMs).toBe(4 * 60 * 60 * 1000);
  });

  it("is all nulls and empties for an empty timeline", () => {
    expect(deriveCockpitStory(state()).shape).toEqual({
      firstAt: null,
      lastAt: null,
      dwellMs: null,
      hosts: [],
      hostsTotal: 0,
      accounts: [],
      accountsTotal: 0,
    });
  });
});

describe("deriveCockpitStory — missing stages (#1493)", () => {
  it("lists the stages with no card, in STORY_STAGE_ORDER, as the complement of the stages", () => {
    const story = deriveCockpitStory(
      state({
        forensicTimeline: [
          event("exfil", { mitreTechniques: ["T1041"] }),
          event("phish", { mitreTechniques: ["T1566"] }),
        ],
      }),
    );

    expect(story.stages.map((stage) => stage.tactic)).toEqual(["Initial Access", "Exfiltration"]);
    expect(story.missingStages).toEqual([
      "Execution",
      "Persistence",
      "Privilege Escalation",
      "Defense Evasion",
      "Credential Access",
      "Discovery",
      "Lateral Movement",
      "Collection",
      "Command and Control",
      "Impact",
    ]);
    expect([...story.stages.map((stage) => stage.tactic), ...story.missingStages]).toHaveLength(
      STORY_STAGE_ORDER.length,
    );
  });

  it("names all twelve stages when nothing is staged, and none when every stage has a card", () => {
    const techniques: Record<string, string> = {
      "Initial Access": "T1566",
      Execution: "T1059",
      Persistence: "T1547",
      "Privilege Escalation": "T1068",
      "Defense Evasion": "T1070",
      "Credential Access": "T1003",
      Discovery: "T1087",
      "Lateral Movement": "T1021",
      Collection: "T1560",
      "Command and Control": "T1071",
      Exfiltration: "T1041",
      Impact: "T1486",
    };
    const full = deriveCockpitStory(
      state({
        forensicTimeline: STORY_STAGE_ORDER.map((tactic) =>
          event(tactic, { mitreTechniques: [techniques[tactic]] }),
        ),
      }),
    );

    expect(deriveCockpitStory(state()).missingStages).toEqual([...STORY_STAGE_ORDER]);
    expect(deriveCockpitStory(state()).missingStages).toHaveLength(12);
    expect(full.stages.map((stage) => stage.tactic)).toEqual([...STORY_STAGE_ORDER]);
    expect(full.missingStages).toEqual([]);
  });
});

describe("deriveCockpitStory — immutability", () => {
  it("never mutates the input state", () => {
    const investigation = state({
      lastSummary: "One. Two. Three.",
      forensicTimeline: [
        event("b", { mitreTechniques: ["T1059"], timestamp: "2026-07-30T10:00:00.000Z" }),
        event("a", { mitreTechniques: ["T1566"], timestamp: "2026-07-30T08:00:00.000Z" }),
      ],
    });
    const before = JSON.stringify(investigation);

    deriveCockpitStory(investigation, synthMeta());

    expect(JSON.stringify(investigation)).toBe(before);
  });
});
