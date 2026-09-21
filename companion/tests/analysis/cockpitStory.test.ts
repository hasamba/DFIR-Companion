import { describe, expect, it } from "vitest";
import {
  deriveCockpitStory,
  STORY_STAGE_EVENT_LIMIT,
  STORY_STAGE_ORDER,
} from "../../src/analysis/cockpitStory.js";
import { emptyState, type InvestigationState, type ForensicEvent } from "../../src/analysis/stateTypes.js";
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
