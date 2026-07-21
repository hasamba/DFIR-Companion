import { describe, it, expect } from "vitest";
import {
  groupDetections,
  collapseForPrompt,
  renderGroupSuffix,
  groupEnvOptions,
  groupingEnabled,
  detectionRuleHead,
  promptIncludesInfo,
  promptCandidates,
  maxPromptEvents,
  DEFAULT_GROUP_GAP_SECONDS,
  DEFAULT_GROUP_MIN_REPEATS,
  DEFAULT_MAX_PROMPT_EVENTS,
} from "../../src/analysis/synthGroup.js";
import { selectSynthesisEventsAnnotated } from "../../src/analysis/synthSelect.js";
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

  it("excludes Info events from the prompt unless explicitly re-enabled", () => {
    expect(promptIncludesInfo({})).toBe(false);
    expect(promptIncludesInfo({ DFIR_SYNTH_INCLUDE_INFO: "0" })).toBe(false);
    expect(promptIncludesInfo({ DFIR_SYNTH_INCLUDE_INFO: "1" })).toBe(true);
    expect(promptIncludesInfo({ DFIR_SYNTH_INCLUDE_INFO: "true" })).toBe(true);
    expect(promptIncludesInfo({ DFIR_SYNTH_INCLUDE_INFO: "on" })).toBe(true);
  });

  it("reads the event cap, defaulting to 600", () => {
    expect(maxPromptEvents({})).toBe(DEFAULT_MAX_PROMPT_EVENTS);
    expect(maxPromptEvents({ DFIR_AI_SYNTH_MAX_EVENTS: "900" })).toBe(900);
    expect(maxPromptEvents({ DFIR_AI_SYNTH_MAX_EVENTS: "nope" })).toBe(DEFAULT_MAX_PROMPT_EVENTS);
  });
});

describe("promptCandidates", () => {
  const mixed: ForensicEvent[] = [
    ev("i1", "2026-05-20T09:00:00Z", "Info", "routine file touched"),
    ev("h1", "2026-05-20T09:01:00Z", "High", "Velociraptor [A.B] Sigma: Bad Thing - detail"),
    ev("i2", "2026-05-20T09:02:00Z", "Info", "another routine thing"),
    ev("m1", "2026-05-20T09:03:00Z", "Medium", "something mildly odd"),
  ];

  it("drops Info events by default so the budget goes to graded detections", () => {
    expect(promptCandidates(mixed, {}).map((e) => e.id)).toEqual(["h1", "m1"]);
  });

  it("keeps everything when Info is explicitly re-enabled", () => {
    expect(promptCandidates(mixed, { DFIR_SYNTH_INCLUDE_INFO: "1" })).toHaveLength(4);
  });

  it("does not mutate or reorder the surviving events", () => {
    const out = promptCandidates(mixed, {});
    expect(out[0]).toBe(mixed[1]);
    expect(mixed).toHaveLength(4);
  });
});

describe("detectionRuleHead", () => {
  it("extracts the rule identity and drops the per-event detail", () => {
    expect(detectionRuleHead("Velociraptor [Windows.Detection.Sigma] Sigma: Encoded PowerShell - Computer: ws-01"))
      .toBe("Velociraptor [Windows.Detection.Sigma] Sigma: Encoded PowerShell");
  });

  it("keeps the whole header when there is no per-event detail", () => {
    expect(detectionRuleHead("Velociraptor [Windows.Detection.Yara] Yara: Mimikatz_Generic"))
      .toBe("Velociraptor [Windows.Detection.Yara] Yara: Mimikatz_Generic");
  });

  it("returns null for descriptions that are not in the detection format", () => {
    expect(detectionRuleHead("robocopy C:\\data \\\\srv\\bak /mir")).toBeNull();      // no bracket, no colon
    expect(detectionRuleHead("A file was written [somewhere]")).toBeNull();            // bracket but no ": "
    expect(detectionRuleHead("")).toBeNull();
  });
});

describe("rule-identity grouping", () => {
  // One Sigma rule firing on many hosts, each hit carrying different per-event detail. Keying on the
  // whole description fragmented these into one group per host; keying on the rule identity is one group.
  function sigmaHits(rule: string, n: number, sev: Severity = "High"): ForensicEvent[] {
    return Array.from({ length: n }, (_, i) =>
      ev(
        `${rule}-${i}`,
        `2026-05-20T09:${String(i).padStart(2, "0")}:00Z`,
        sev,
        `Velociraptor [Windows.Detection.Sigma] Sigma: ${rule} - Computer: ws-${i} User: alice${i}`,
        `ws-${i}`,
      ),
    );
  }

  it("groups the same rule across hosts despite differing per-event detail", () => {
    const groups = groupDetections(sigmaHits("Encoded PowerShell", 8));
    expect(groups).toHaveLength(1);
    expect(groups[0].count).toBe(8);
    expect(groups[0].hosts).toHaveLength(8);
  });

  it("never merges two different rules", () => {
    const groups = groupDetections([...sigmaHits("Encoded PowerShell", 6), ...sigmaHits("Mimikatz Access", 6)]);
    expect(groups).toHaveLength(2);
  });

  it("leaves non-detection descriptions on the existing fingerprint", () => {
    // Same shape under commandShape (paths normalized), so these still group exactly as before.
    const events = Array.from({ length: 5 }, (_, i) =>
      ev(`r${i}`, `2026-05-20T09:0${i}:00Z`, "Medium", `robocopy C:\\data\\${i} \\\\srv\\bak /mir`),
    );
    expect(groupDetections(events)).toHaveLength(1);
  });

  it("still keys on the file hash when one is present, so distinct samples stay distinct", () => {
    const withHash = (id: string, t: string, sha: string): ForensicEvent => ({
      ...ev(id, t, "High", "Velociraptor [Windows.Detection.Yara] Yara: Generic_Loader - hit"),
      sha256: sha,
    });
    const events = [
      ...Array.from({ length: 4 }, (_, i) => withHash(`a${i}`, `2026-05-20T09:0${i}:00Z`, "a".repeat(64))),
      ...Array.from({ length: 4 }, (_, i) => withHash(`b${i}`, `2026-05-20T09:1${i}:00Z`, "b".repeat(64))),
    ];
    expect(groupDetections(events)).toHaveLength(2);
  });
});

describe("grouping + selection end to end", () => {
  // Distinct rule TITLES, not numbered ones: patternKey normalizes bare numbers to <n> (so that
  // "robocopy C:\\data\\1" and "…\\2" fingerprint alike), which means descriptions differing ONLY by a
  // number are one pattern by design. Real Sigma/YARA rule titles are words, so this mirrors reality.
  function ruleTitle(i: number): string {
    const a = "abcdefghijklmnopqrstuvwxyz";
    return `${a[Math.floor(i / 26) % 26]}${a[i % 26]}`;
  }

  // The shape of a real Hayabusa import: a handful of distinct Sigma rules, each firing many times.
  function hayabusaLikeCase(rules: number, hitsPerRule: number): ForensicEvent[] {
    const events: ForensicEvent[] = [];
    for (let rule = 0; rule < rules; rule++) {
      for (let hit = 0; hit < hitsPerRule; hit++) {
        events.push(
          ev(
            `r${rule}h${hit}`,
            `2026-05-20T09:${String(hit).padStart(2, "0")}:00Z`,
            "High",
            `Sigma rule ${ruleTitle(rule)} matched`,
            `ws-${hit % 5}`,
          ),
        );
      }
    }
    return events;
  }

  it("treats detections that differ only by a number as ONE pattern (documented limitation)", () => {
    // patternKey strips bare numbers, so these two titles share a fingerprint and merge. Acceptable:
    // it is the same normalization the prevalence/rarity baseline already relies on, and real detection
    // titles carry words. Asserted so the behaviour is a recorded decision, not an accident.
    const events = [
      ...Array.from({ length: 4 }, (_, i) => ev(`x${i}`, `2026-05-20T09:0${i}:00Z`, "High", "Sigma rule 1 matched")),
      ...Array.from({ length: 4 }, (_, i) => ev(`y${i}`, `2026-05-20T09:1${i}:00Z`, "High", "Sigma rule 2 matched")),
    ];
    expect(groupDetections(events)).toHaveLength(1);
  });

  it("fits 2000 repeated detections across 50 distinct rules inside a 300-event cap", () => {
    const events = hayabusaLikeCase(50, 40);
    expect(events).toHaveLength(2000);

    const { events: collapsed, memberIdsByRepresentative } = collapseForPrompt(events);
    expect(collapsed).toHaveLength(50);

    const selection = selectSynthesisEventsAnnotated(collapsed, 300);
    expect(selection.events).toHaveLength(50);
    expect(selection.omitted).toBe(0);

    // Every one of the 2000 original events is represented by a row the model actually reads.
    const represented = new Set<string>();
    for (const e of selection.events) {
      represented.add(e.id);
      for (const id of memberIdsByRepresentative.get(e.id) ?? []) represented.add(id);
    }
    expect(represented.size).toBe(2000);
  });

  it("without grouping the same case loses most of its detections to the cap", () => {
    const selection = selectSynthesisEventsAnnotated(hayabusaLikeCase(50, 40), 300);
    expect(selection.events.length).toBeLessThanOrEqual(300);
    expect(selection.omitted).toBeGreaterThan(1600);
  });
});
