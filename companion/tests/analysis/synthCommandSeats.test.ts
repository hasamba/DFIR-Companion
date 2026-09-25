import { describe, it, expect } from "vitest";
import {
  COMMAND_SEAT_MAX,
  commandLineOf,
  commandSeatCap,
  findingSessionRowIds,
  sessionCommandSeats,
  type CommandSeat,
} from "../../src/analysis/ai/synthCommandSeats.js";
import { CANONICAL_EVENT_SCHEMA_VERSION } from "../../src/analysis/canonicalEvent.js";
import { emptyState, type ForensicEvent, type Severity } from "../../src/analysis/stateTypes.js";

// #1622: which Low/Medium session commands get a reserved synthesis-prompt seat.

const BASE = Date.parse("2026-05-20T10:00:00Z");
const at = (minutes: number): string => new Date(BASE + minutes * 60_000).toISOString();
const lower = (raw: string): string => raw.trim().toLowerCase();

function ev(
  id: string,
  minutes: number,
  severity: Severity,
  extra: Partial<ForensicEvent> = {},
): ForensicEvent {
  return {
    id,
    timestamp: at(minutes),
    severity,
    description: id,
    asset: "WS-01.example.com",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    ...extra,
  };
}

const anchor = (id: string, minutes: number, extra: Partial<ForensicEvent> = {}): ForensicEvent =>
  ev(id, minutes, "High", extra);
const cmd = (id: string, minutes: number, commandLine: string, extra: Partial<ForensicEvent> = {}) =>
  ev(id, minutes, "Low", { commandLine, processName: "cmd.exe", ...extra });
const ids = (seats: readonly CommandSeat[]): string[] => seats.map((s) => s.event.id);

describe("commandSeatCap", () => {
  it("reserves a tenth of the cap, at least one seat, at most 40", () => {
    expect(commandSeatCap(600)).toBe(COMMAND_SEAT_MAX);
    expect(commandSeatCap(100)).toBe(10);
    expect(commandSeatCap(20)).toBe(2);
    expect(commandSeatCap(3)).toBe(1);
    expect(commandSeatCap(0)).toBe(0);
  });
});

describe("sessionCommandSeats — the session", () => {
  it("keeps a command within 15 minutes of a lone anchor and drops one 16 minutes away", () => {
    const seats = sessionCommandSeats({
      events: [anchor("a", 60), cmd("in", 75, "net view /all"), cmd("out", 44, "tasklist /v")],
      hostOf: lower,
    });
    expect(ids(seats)).toEqual(["in"]);
  });

  it("bridges anchors exactly 2 hours apart and splits anchors more than 2 hours apart", () => {
    const bridged = sessionCommandSeats({
      events: [anchor("a1", 0), anchor("a2", 120), cmd("mid", 60, "net view /all")],
      hostOf: lower,
    });
    expect(ids(bridged)).toEqual(["mid"]);
    const split = sessionCommandSeats({
      events: [anchor("a1", 0), anchor("a2", 121), cmd("mid", 60, "net view /all")],
      hostOf: lower,
    });
    expect(split).toEqual([]);
  });

  it("needs an anchor on the same host", () => {
    const seats = sessionCommandSeats({
      events: [anchor("a", 0), cmd("other", 5, "net view /all", { asset: "WS-02.example.com" })],
      hostOf: lower,
    });
    expect(seats).toEqual([]);
  });

  it("resolves host spellings through the caller's host resolver", () => {
    const hostOf = (raw: string): string => lower(raw).split(".")[0];
    const seats = sessionCommandSeats({
      events: [anchor("a", 0, { asset: "WS-01" }), cmd("fqdn", 5, "net view /all")],
      hostOf,
    });
    expect(ids(seats)).toEqual(["fqdn"]);
  });

  it("opens a session around rows a live Medium+ finding cites, not around dismissed ones", () => {
    const state = emptyState("c1");
    const events = [ev("cited", 0, "Low"), cmd("near", 5, "subst E: C:\\e")];
    const live = {
      ...state,
      forensicTimeline: events,
      findings: [{ id: "f1", severity: "Medium", status: "open", relatedEventIds: ["cited"] }],
    } as unknown as typeof state;
    const dismissed = {
      ...live,
      findings: [{ id: "f1", severity: "Medium", status: "dismissed", relatedEventIds: ["cited"] }],
    } as unknown as typeof state;
    expect(
      ids(sessionCommandSeats({ events, hostOf: lower, findingRowIds: findingSessionRowIds(live) })),
    ).toEqual(["near"]);
    expect(
      sessionCommandSeats({ events, hostOf: lower, findingRowIds: findingSessionRowIds(dismissed) }),
    ).toEqual([]);
  });
});

describe("sessionCommandSeats — candidates", () => {
  it("takes Low and Medium command lines only — not Info, not rows without one", () => {
    const seats = sessionCommandSeats({
      events: [
        anchor("a", 0),
        cmd("low", 1, "net view /all"),
        ev("med", 2, "Medium", { commandLine: "tasklist /v" }),
        ev("info", 3, "Info", { commandLine: "whoami /all" }),
        ev("bare", 4, "Low", { processName: "net.exe" }),
      ],
      hostOf: lower,
    });
    expect(ids(seats).sort()).toEqual(["low", "med"]);
  });

  it("reads the canonical command line, and the legacy one when the canonical one is blank", () => {
    const envelope = (commandLine: string) =>
      ({
        canonical: { schemaVersion: CANONICAL_EVENT_SCHEMA_VERSION, process: { commandLine } },
      }) as Partial<ForensicEvent>;
    expect(commandLineOf(ev("c", 0, "Low", envelope(" tasklist /v ")))).toBe("tasklist /v");
    expect(commandLineOf(ev("l", 0, "Low", { commandLine: "net view /all", ...envelope("  ") }))).toBe(
      "net view /all",
    );
  });

  it("keeps one seat per host and command line — the instance nearest an anchor", () => {
    const seats = sessionCommandSeats({
      events: [
        anchor("a", 10),
        cmd("far", 0, "net view /all"),
        cmd("near", 11, "NET  view /all"),
        anchor("b", 10, { asset: "WS-02.example.com" }),
        cmd("other-host", 11, "net view /all", { asset: "WS-02.example.com" }),
      ],
      hostOf: lower,
    });
    expect(ids(seats).sort()).toEqual(["near", "other-host"]);
  });

  it("marks a command an anchor on the same host also carries as shadowed by that anchor", () => {
    const seats = sessionCommandSeats({
      events: [
        anchor("a", 0, { commandLine: "net view /all" }),
        cmd("dup", 5, "net view /all"),
        cmd("other", 6, "tasklist /v"),
      ],
      hostOf: lower,
    });
    expect(seats.map((s) => [s.event.id, s.shadowedBy])).toEqual([
      ["dup", ["a"]],
      ["other", []],
    ]);
  });

  it("orders nearest first, then Medium before Low, and deals seats round-robin across hosts", () => {
    const b = { asset: "WS-02.example.com" };
    const seats = sessionCommandSeats({
      events: [
        anchor("a", 0),
        cmd("a-far", 10, "tasklist /v"),
        cmd("a-near-low", 2, "net view /all"),
        ev("a-near-med", 2, "Medium", { commandLine: "whoami /all" }),
        anchor("b", 0, b),
        cmd("b-1", 3, "subst E: C:\\e", b),
      ],
      hostOf: lower,
    });
    expect(ids(seats)).toEqual(["a-near-med", "b-1", "a-near-low", "a-far"]);
  });
});
