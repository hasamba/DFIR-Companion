import { describe, it, expect, afterEach, vi } from "vitest";
import {
  PS_SESSION_PER_SESSION_MAX,
  psSessionSeatCap,
  psSessionSeats,
} from "../../src/analysis/ai/synthPsSessionSeats.js";
import { createTimelineSelection } from "../../src/analysis/ai/synthesisPromptEvents.js";
import { createCanonicalEvent } from "../../src/analysis/canonicalEvent.js";
import { emptyState, type ForensicEvent, type Severity } from "../../src/analysis/stateTypes.js";

// #2078 (design B1): once any row of a PowerShell session is graded High, the session's other
// Low/Medium rows get reserved seats in the synthesis prompt, inside DFIR_AI_SYNTH_MAX_EVENTS.

const BASE = Date.parse("2026-05-20T03:00:00Z");
const at = (minutes: number): string => new Date(BASE + minutes * 60_000).toISOString();
const lower = (raw: string): string => raw.trim().toLowerCase();
const HOST = "WS-01.example.com";

function psCanonical(id: string, ts: string, pid: number) {
  return createCanonicalEvent({
    event: { category: "other", type: "event" },
    powershell: { sessionId: `pid:${pid}`, processId: pid },
    time: { observed: ts, normalized: ts },
    evidence: { rawRecords: [{ source: "windows-event", locator: `row:${id}` }] },
    producer: { importer: "windows-event", parserVersion: "1", mappingVersion: "windows-event-v1" },
    rawFieldMap: { "powershell.processId": ["ExecutionProcessID"] },
  });
}

function ev(
  id: string,
  minutes: number,
  severity: Severity,
  extra: Partial<ForensicEvent> & { pid?: number } = {},
): ForensicEvent {
  const { pid, ...rest } = extra;
  const timestamp = at(minutes);
  return {
    id,
    timestamp,
    severity,
    description: id,
    asset: HOST,
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    ...(pid !== undefined ? { canonical: psCanonical(id, timestamp, pid) } : {}),
    ...rest,
  };
}

// Letters, not digits: burst grouping folds numbers, so "rule 1" and "rule 2" would be one burst.
const word = (i: number): string =>
  String.fromCharCode(97 + (i % 26)) +
  String.fromCharCode(97 + (Math.floor(i / 26) % 26)) +
  String.fromCharCode(97 + Math.floor(i / 676));

/** The triage's APT29-shaped scenario: one implant session on WS-01 among 200 noise rows. */
function scenario(): ForensicEvent[] {
  const events: ForensicEvent[] = [
    ev("hi", 0, "High", {
      pid: 4242,
      description: "PowerShell Script block logged (EID 4104) - ScriptBlockText=IEX (implant stager)",
    }),
    ev("runkey", 10, "Medium", {
      pid: 4242,
      description:
        "PowerShell Script block logged (EID 4104) - ScriptBlockText=New-ItemProperty -Path HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    }),
    ev("netuse", 40, "Low", {
      pid: 4242,
      description:
        "PowerShell Module/pipeline execution (EID 4103) - Payload=net use y: https://d.example.net/x",
    }),
    ev("other-session", 20, "Low", {
      pid: 9999,
      description: "PowerShell Module/pipeline execution (EID 4103) - Payload=Get-Date",
    }),
  ];
  for (let i = 0; i < 200; i++)
    events.push(
      ev(`noise${i}`, -600 + i * 7, "Medium", {
        asset: `SRV-${word(i)}.example.com`,
        description: `Sigma rule ${word(i)} on telemetry`,
      }),
    );
  return events;
}

describe("psSessionSeats (#2078)", () => {
  it("seats the other rows of a session that has a High row, and not another session's", () => {
    const seats = psSessionSeats({ events: scenario(), hostOf: lower });
    const ids = seats.map((s) => s.event.id);
    expect(ids).toEqual(["runkey", "netuse"]);
    for (const s of seats) expect(s.shadowedBy).toEqual([]);
  });

  it("seats nothing when no row of the session is High", () => {
    const events = scenario().map((e) => (e.id === "hi" ? { ...e, severity: "Medium" as const } : e));
    expect(psSessionSeats({ events, hostOf: lower })).toEqual([]);
  });

  it("does not join the same pid on a different host", () => {
    const events = [
      ev("hi", 0, "High", { pid: 4242 }),
      ev("elsewhere", 5, "Medium", { pid: 4242, asset: "WS-02.example.com" }),
    ];
    expect(psSessionSeats({ events, hostOf: lower })).toEqual([]);
  });

  it("splits a recycled pid: a row more than 12 h after the session is not seated", () => {
    const events = [ev("hi", 0, "High", { pid: 4242 }), ev("days-later", 60 * 30, "Medium", { pid: 4242 })];
    expect(psSessionSeats({ events, hostOf: lower })).toEqual([]);
  });

  it("never seats Info rows (§7) and never builds on the collector's own rows", () => {
    const events = [
      ev("hi", 0, "High", { pid: 4242 }),
      ev("info", 2, "Info", { pid: 4242 }),
      ev("collector", 3, "Low", { pid: 4242, origin: "collector" }),
      ev("col-hi", 0, "High", { pid: 5555, origin: "collector" }),
      ev("col-child", 1, "Medium", { pid: 5555 }),
    ];
    expect(psSessionSeats({ events, hostOf: lower })).toEqual([]);
  });

  it("caps each session at PS_SESSION_PER_SESSION_MAX rows and seats identical text once", () => {
    const events = [ev("hi", 0, "High", { pid: 4242 })];
    for (let i = 0; i < PS_SESSION_PER_SESSION_MAX + 10; i++)
      events.push(ev(`m${i}`, 1 + i, "Medium", { pid: 4242, description: `Get-Item ${word(i)}` }));
    events.push(ev("dup", 1, "Low", { pid: 4242, description: "Get-Item aaa" }));
    const seats = psSessionSeats({ events, hostOf: lower });
    expect(seats).toHaveLength(PS_SESSION_PER_SESSION_MAX);
    expect(seats.map((s) => s.event.id)).not.toContain("dup");
    // Nearest to the High row first.
    expect(seats[0].event.id).toBe("m0");
  });

  it("ignores rows that carry no session (existing cases behave as before)", () => {
    const events = [ev("hi", 0, "High"), ev("quiet", 5, "Medium")];
    expect(psSessionSeats({ events, hostOf: lower })).toEqual([]);
  });

  it("sizes its cap from the prompt: 10%, at least 1, at most 50", () => {
    expect(psSessionSeatCap(0)).toBe(0);
    expect(psSessionSeatCap(5)).toBe(1);
    expect(psSessionSeatCap(30)).toBe(3);
    expect(psSessionSeatCap(600)).toBe(50);
  });
});

describe("createTimelineSelection — PowerShell session seats end to end (#2078)", () => {
  afterEach(() => vi.unstubAllEnvs());

  it("sends both session rows at a 30-row cap and not the other session's row", () => {
    vi.stubEnv("DFIR_AI_SYNTH_MAX_EVENTS", "30");
    const events = scenario();
    const t = createTimelineSelection({ ...emptyState("c2078"), forensicTimeline: events }, events);
    const shown = new Set(t.promptEvents.map((e) => e.id));
    expect(t.promptEvents.length).toBeLessThanOrEqual(30);
    expect(shown.has("hi")).toBe(true);
    expect(shown.has("runkey")).toBe(true);
    expect(shown.has("netuse")).toBe(true);
    expect(t.selection.classOf.get("netuse")).toBe("command");
    expect(t.selection.classOf.get("other-session")).not.toBe("command");
  });

  it("without the session key the 40-minute-later row is not sent (the gap #2078 fixes)", () => {
    vi.stubEnv("DFIR_AI_SYNTH_MAX_EVENTS", "30");
    const events = scenario().map(({ canonical: _c, ...e }) => e as ForensicEvent);
    const t = createTimelineSelection({ ...emptyState("c2078"), forensicTimeline: events }, events);
    expect(t.promptEvents.some((e) => e.id === "netuse")).toBe(false);
  });
});
