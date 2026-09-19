import { describe, it, expect } from "vitest";
import type { Finding, ForensicEvent } from "../../src/analysis/stateTypes.js";
import {
  fallbackFindingTask,
  findingSourceHash,
  renderFindingTaskDescription,
  sanitizeFindingTasks,
  findingEvidenceHosts,
} from "../../src/analysis/findingTasks.js";

const NOW = "2026-06-10T00:00:00.000Z";

function finding(over: Partial<Finding> = {}): Finding {
  return {
    id: "f1",
    severity: "Critical",
    title: "Impacket secretsdump.exe used for SAM/LSA/NTDS credential extraction",
    description:
      "secretsdump.exe was staged in the attacker share, spawned from powershell.exe, and flagged as malware by THOR. This is the Impacket tool for credential extraction.",
    relatedIocs: [],
    sourceScreenshots: [],
    mitreTechniques: ["T1003.002"],
    firstSeen: NOW,
    lastUpdated: NOW,
    status: "open",
    ...over,
  };
}

function event(over: Partial<ForensicEvent> = {}): ForensicEvent {
  return {
    id: "e1",
    timestamp: "2026-06-09T14:02:00.000Z",
    description: "secretsdump.exe spawned by powershell.exe",
    severity: "Critical",
    mitreTechniques: [],
    relatedFindingIds: ["f1"],
    sourceScreenshots: [],
    asset: "WS-042",
    ...over,
  };
}

describe("sanitizeFindingTasks", () => {
  const offered = new Set(["f1", "f2"]);

  it("keeps a well-formed task and trims its text", () => {
    const out = sanitizeFindingTasks(
      [
        {
          findingId: "f1",
          title: "  Confirm secretsdump ran on WS-042 ",
          steps: [" Pull prefetch "],
          doneWhen: " Execution confirmed ",
        },
      ],
      offered,
    );
    expect(out).toEqual({
      f1: {
        title: "Confirm secretsdump ran on WS-042",
        steps: ["Pull prefetch"],
        doneWhen: "Execution confirmed",
      },
    });
  });

  it("drops a task for a finding that was not offered, and one with no usable steps", () => {
    const out = sanitizeFindingTasks(
      [
        { findingId: "f9", title: "Invented", steps: ["x"], doneWhen: "y" },
        { findingId: "f2", title: "No steps", steps: ["   "], doneWhen: "y" },
      ],
      offered,
    );
    expect(out).toEqual({});
  });

  it("caps steps at four, strips control characters and collapses newlines inside a step", () => {
    const out = sanitizeFindingTasks(
      [
        {
          findingId: "f1",
          title: "T\u0000itle",
          steps: ["one\nline", "two", "three", "four", "five"],
          doneWhen: "done",
        },
      ],
      offered,
    );
    expect(out.f1.title).toBe("Title");
    expect(out.f1.steps).toEqual(["one line", "two", "three", "four"]);
  });

  it("truncates an over-long title and step instead of dropping the task", () => {
    const out = sanitizeFindingTasks(
      [{ findingId: "f1", title: "a".repeat(300), steps: ["b".repeat(900)], doneWhen: "c".repeat(900) }],
      offered,
    );
    expect(out.f1.title.length).toBeLessThanOrEqual(160);
    expect(out.f1.steps[0].length).toBeLessThanOrEqual(400);
    expect(out.f1.doneWhen.length).toBeLessThanOrEqual(400);
  });

  it("keeps the first task when the model repeats a finding id", () => {
    const out = sanitizeFindingTasks(
      [
        { findingId: "f1", title: "first", steps: ["a"], doneWhen: "d" },
        { findingId: "f1", title: "second", steps: ["b"], doneWhen: "d" },
      ],
      offered,
    );
    expect(out.f1.title).toBe("first");
  });
});

describe("findingSourceHash", () => {
  it("changes when the finding's severity, title or description changes, and not otherwise", () => {
    const base = findingSourceHash(finding());
    expect(findingSourceHash(finding({ confidence: 12, lastUpdated: "2027-01-01T00:00:00Z" }))).toBe(base);
    expect(findingSourceHash(finding({ severity: "High" }))).not.toBe(base);
    expect(findingSourceHash(finding({ title: "other" }))).not.toBe(base);
    expect(findingSourceHash(finding({ description: "other" }))).not.toBe(base);
  });
});

describe("findingEvidenceHosts", () => {
  it("returns the distinct hosts of the finding's cited events, first-cited first", () => {
    const f = finding({ relatedEventIds: ["e2", "e1", "e3"] });
    const events = [
      event({ id: "e1", asset: "WS-042" }),
      event({ id: "e2", asset: "DC01" }),
      event({ id: "e3", asset: "ws-042" }),
    ];
    expect(findingEvidenceHosts(f, events)).toEqual(["DC01", "WS-042"]);
  });

  it("is empty when the finding cites nothing or the events carry no asset", () => {
    expect(findingEvidenceHosts(finding(), [event()])).toEqual([]);
    expect(findingEvidenceHosts(finding({ relatedEventIds: ["e1"] }), [event({ asset: undefined })])).toEqual(
      [],
    );
  });
});

describe("fallbackFindingTask", () => {
  it("writes an imperative tactic-specific title that keeps the finding's own title", () => {
    const t = fallbackFindingTask(finding(), { hosts: ["WS-042"], collectLines: [] });
    expect(t.title).toMatch(/^Confirm the credential theft and rotate what was exposed: /);
    expect(t.title).toContain("secretsdump.exe");
  });

  it("falls back to a generic imperative when the finding has no known tactic", () => {
    const t = fallbackFindingTask(
      finding({ mitreTechniques: [], title: "Odd thing", description: "Something unusual." }),
      {
        hosts: [],
        collectLines: [],
      },
    );
    expect(t.title).toBe("Confirm and scope: Odd thing");
  });

  it("names the evidence hosts and time in the first step, then the tactic focus, then containment for Critical", () => {
    const t = fallbackFindingTask(finding(), {
      hosts: ["WS-042", "DC01"],
      collectLines: ["collect Security.evtx 4624/4672 (Windows.EventLogs.Evtx) from WS-042"],
    });
    expect(t.steps[0]).toContain("WS-042");
    expect(t.steps[0]).toContain("DC01");
    expect(t.steps[0]).toContain("2026-06-10");
    expect(t.steps[1]).toContain("Security.evtx 4624/4672");
    expect(t.steps[1]).toContain("from WS-042");
    expect(t.steps.some((s) => /credentials/i.test(s))).toBe(true);
    expect(t.steps[t.steps.length - 1]).toMatch(/^Contain: /);
    expect(t.doneWhen).toContain("containment");
  });

  it("omits the containment step and clause for a High finding", () => {
    const t = fallbackFindingTask(finding({ severity: "High" }), { hosts: ["WS-042"], collectLines: [] });
    expect(t.steps.some((s) => s.startsWith("Contain: "))).toBe(false);
    expect(t.doneWhen).not.toContain("containment");
  });

  it("never uses the finding description as a step", () => {
    const f = finding();
    const t = fallbackFindingTask(f, { hosts: [], collectLines: [] });
    expect(t.steps).not.toContain(f.description);
    expect(t.steps.length).toBeGreaterThanOrEqual(1);
    expect(t.steps.length).toBeLessThanOrEqual(4);
  });
});

describe("renderFindingTaskDescription", () => {
  const task = {
    title: "Confirm secretsdump ran",
    steps: ["Pull the prefetch", "Search Temp for NTDS.dit"],
    doneWhen: "Execution confirmed or refuted",
  };

  it("numbers the steps, then Done when, then a one-sentence Why", () => {
    const body = renderFindingTaskDescription(task, { why: finding().description });
    expect(body.split("\n")).toEqual([
      "1. Pull the prefetch",
      "2. Search Temp for NTDS.dit",
      "Done when: Execution confirmed or refuted",
      "Why: secretsdump.exe was staged in the attacker share, spawned from powershell.exe, and flagged as malware by THOR.",
    ]);
  });

  it("appends folded next steps as numbered 'Also:' steps and a rabbit-hole note before Done when", () => {
    const body = renderFindingTaskDescription(task, {
      extraSteps: ["Analyze the PUA binary — confirm malicious"],
      rabbitNote: "Possible rabbit hole — verify before chasing.",
    });
    expect(body.split("\n")).toEqual([
      "1. Pull the prefetch",
      "2. Search Temp for NTDS.dit",
      "3. Also: Analyze the PUA binary — confirm malicious",
      "Possible rabbit hole — verify before chasing.",
      "Done when: Execution confirmed or refuted",
    ]);
  });

  it("caps the Why line at 200 characters", () => {
    const body = renderFindingTaskDescription(task, { why: "x".repeat(500) });
    const why = body.split("\n").find((l) => l.startsWith("Why: "))!;
    expect(why.length).toBeLessThanOrEqual("Why: ".length + 200);
  });
});
