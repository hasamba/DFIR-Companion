import { describe, it, expect } from "vitest";
import {
  groupDetections,
  collapseForPrompt,
  renderGroupSuffix,
  groupEnvOptions,
  groupingEnabled,
  DEFAULT_GROUP_GAP_SECONDS,
  DEFAULT_GROUP_MIN_REPEATS,
} from "../../src/analysis/synthGroup.js";
import type { ForensicEvent, Severity } from "../../src/analysis/stateTypes.js";

function ev(id: string, t: string, sev: Severity, desc: string, asset?: string): ForensicEvent {
  return {
    id,
    timestamp: t,
    description: desc,
    severity: sev,
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    ...(asset ? { asset } : {}),
  };
}

// n hits of the same Sigma rule, five minutes apart, alternating across two hosts.
function burst(prefix: string, startHour: number, n: number, sev: Severity = "High"): ForensicEvent[] {
  return Array.from({ length: n }, (_, i) =>
    ev(
      `${prefix}${i}`,
      `2026-05-20T${String(startHour).padStart(2, "0")}:${String(i * 5).padStart(2, "0")}:00Z`,
      sev,
      "Suspicious encoded PowerShell command",
      i % 2 === 0 ? "ws-01" : "ws-02",
    ),
  );
}

describe("groupDetections", () => {
  it("collapses repeated identical detections into one group with count, hosts and span", () => {
    const groups = groupDetections(burst("a", 9, 6));
    expect(groups).toHaveLength(1);
    expect(groups[0].count).toBe(6);
    expect(groups[0].memberIds).toHaveLength(6);
    expect(groups[0].hosts.sort()).toEqual(["ws-01", "ws-02"]);
    expect(groups[0].first).toBe("2026-05-20T09:00:00Z");
    expect(groups[0].last).toBe("2026-05-20T09:25:00Z");
    expect(groups[0].representative.id).toBe("a0");
    expect(groups[0].severity).toBe("High");
  });

  it("splits the same detection into separate groups across a long time gap", () => {
    const events = [...burst("a", 9, 5), ...burst("b", 20, 5)];
    const groups = groupDetections(events);
    expect(groups).toHaveLength(2);
    expect(groups[0].first).toBe("2026-05-20T09:00:00Z");
    expect(groups[1].first).toBe("2026-05-20T20:00:00Z");
  });

  it("never groups across severities", () => {
    const events = [...burst("a", 9, 5, "High"), ...burst("b", 9, 5, "Medium")];
    const groups = groupDetections(events);
    expect(groups).toHaveLength(2);
    expect(groups.map((g) => g.severity).sort()).toEqual(["High", "Medium"]);
  });

  it("leaves bursts below the repeat threshold ungrouped", () => {
    expect(groupDetections(burst("a", 9, 3))).toHaveLength(0);
    expect(groupDetections(burst("a", 9, 4))).toHaveLength(1);
  });

  it("ignores undated events (they have no position on the time axis)", () => {
    const events = Array.from({ length: 6 }, (_, i) => ev(`u${i}`, "", "High", "same detection"));
    expect(groupDetections(events)).toHaveLength(0);
  });

  it("is deterministic and does not mutate its input", () => {
    const events = burst("a", 9, 6);
    const before = JSON.stringify(events);
    const first = groupDetections(events);
    const second = groupDetections(events);
    expect(JSON.stringify(events)).toBe(before);
    expect(JSON.stringify(first)).toBe(JSON.stringify(second));
  });
});

describe("collapseForPrompt", () => {
  it("replaces a burst with one representative and drops the other members", () => {
    const events = [...burst("a", 9, 6), ev("solo", "2026-05-20T15:00:00Z", "Medium", "one-off thing")];
    const { events: collapsed, groupById, memberIdsByRepresentative } = collapseForPrompt(events);
    expect(collapsed.map((e) => e.id)).toEqual(["a0", "solo"]);
    expect(collapsed[0].count).toBe(6);
    expect(collapsed[0].endTimestamp).toBe("2026-05-20T09:25:00Z");
    expect(groupById.get("a0")?.count).toBe(6);
    expect(memberIdsByRepresentative.get("a0")).toHaveLength(6);
  });

  it("returns the original events untouched when nothing repeats enough", () => {
    const events = burst("a", 9, 3);
    const { events: collapsed, groupById } = collapseForPrompt(events);
    expect(collapsed.map((e) => e.id)).toEqual(["a0", "a1", "a2"]);
    expect(collapsed[0].count).toBeUndefined();
    expect(groupById.size).toBe(0);
  });

  it("does not mutate the source events when building a representative", () => {
    const events = burst("a", 9, 6);
    collapseForPrompt(events);
    expect(events[0].count).toBeUndefined();
    expect(events[0].endTimestamp).toBeUndefined();
  });
});

describe("renderGroupSuffix", () => {
  it("names the hosts and the span", () => {
    const g = groupDetections(burst("a", 9, 6))[0];
    const s = renderGroupSuffix(g);
    expect(s).toContain("6× identical detection");
    expect(s).toContain("on 2 hosts (ws-01, ws-02)");
    expect(s).toContain("between 2026-05-20T09:00:00Z and 2026-05-20T09:25:00Z");
  });

  it("caps how many hosts it names", () => {
    const events = Array.from({ length: 10 }, (_, i) =>
      ev(`h${i}`, `2026-05-20T09:${String(i).padStart(2, "0")}:00Z`, "High", "same detection", `ws-${i}`),
    );
    const g = groupDetections(events)[0];
    expect(renderGroupSuffix(g, 3)).toContain("+7 more");
  });
});

describe("env options", () => {
  it("falls back to the defaults when unset or invalid", () => {
    expect(groupEnvOptions({})).toEqual({
      gapSeconds: DEFAULT_GROUP_GAP_SECONDS,
      minRepeats: DEFAULT_GROUP_MIN_REPEATS,
    });
    expect(groupEnvOptions({ DFIR_SYNTH_GROUP_GAP_SECONDS: "nope" }).gapSeconds).toBe(DEFAULT_GROUP_GAP_SECONDS);
    expect(groupEnvOptions({ DFIR_SYNTH_GROUP_MIN_REPEATS: "1" }).minRepeats).toBe(DEFAULT_GROUP_MIN_REPEATS);
  });

  it("reads overrides", () => {
    expect(groupEnvOptions({ DFIR_SYNTH_GROUP_GAP_SECONDS: "600" }).gapSeconds).toBe(600);
    expect(groupEnvOptions({ DFIR_SYNTH_GROUP_MIN_REPEATS: "10" }).minRepeats).toBe(10);
  });

  it("is on unless explicitly disabled", () => {
    expect(groupingEnabled({})).toBe(true);
    expect(groupingEnabled({ DFIR_SYNTH_GROUP: "1" })).toBe(true);
    expect(groupingEnabled({ DFIR_SYNTH_GROUP: "0" })).toBe(false);
    expect(groupingEnabled({ DFIR_SYNTH_GROUP: "off" })).toBe(false);
  });
});
