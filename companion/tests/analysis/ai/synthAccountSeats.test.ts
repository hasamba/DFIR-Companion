import { describe, it, expect } from "vitest";
import {
  ACCOUNT_SEAT_MAX,
  accountLogonSeats,
  accountSeatCap,
} from "../../../src/analysis/ai/synthAccountSeats.js";
import { commandSeatCap } from "../../../src/analysis/ai/synthCommandSeats.js";
import { createTimelineSelection } from "../../../src/analysis/ai/synthesisPromptEvents.js";
import { emptyState, type ForensicEvent, type Severity } from "../../../src/analysis/stateTypes.js";

// #2014: a Medium explicit-credential logon naming a second account gets a bounded reserved seat.

const BASE = Date.parse("2026-05-20T10:00:00Z");
const at = (s: number): string => new Date(BASE + s * 1000).toISOString();
const lower = (raw: string): string => raw.trim().toLowerCase();

function ev(
  id: string,
  seconds: number,
  severity: Severity,
  description: string,
  asset = "HOST-A.example.com",
) {
  return {
    id,
    timestamp: at(seconds),
    severity,
    description,
    asset,
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
  } as ForensicEvent;
}

const explicit = (id: string, s: number, account: string, asset?: string, sev: Severity = "Medium") =>
  ev(
    id,
    s,
    sev,
    `Windows Security Logon with explicit credentials (EID 4648) - EXAMPLE\\${account}, EXAMPLE\\HOST-A$`,
    asset,
  );
const logon3 = (id: string, s: number, account: string, asset?: string) =>
  ev(
    id,
    s,
    "Low",
    `Windows Security Successful logon (EID 4624) - EXAMPLE\\${account} - LogonType=3 - IpAddress=10.0.0.9`,
    asset,
  );

// Distinct words: burst grouping folds digits, so numbered rows would collapse into one.
const word = (i: number): string =>
  String.fromCharCode(97 + (i % 26)) +
  String.fromCharCode(97 + (Math.floor(i / 26) % 26)) +
  String.fromCharCode(97 + Math.floor(i / 676));

/** A case far over the cap: High anchors plus distinct Medium noise rows. */
function bigCase(extra: ForensicEvent[], noise = 900): ForensicEvent[] {
  const rows: ForensicEvent[] = [];
  for (let i = 0; i < 40; i++) rows.push(ev(`a${i}`, i * 60, "High", `detection ${word(i)} fired`));
  for (let i = 0; i < noise; i++) rows.push(ev(`n${i}`, i * 5, "Medium", `process ${word(i)} started`));
  return [...rows, ...extra];
}

function select(events: ForensicEvent[]) {
  const state = { ...emptyState("c"), forensicTimeline: events };
  return createTimelineSelection(state, events);
}

describe("accountLogonSeats", () => {
  it("nominates a 4648 row for a user account", () => {
    const seats = accountLogonSeats({ events: [explicit("x1", 10, "second")], hostOf: lower });
    expect(seats.map((s) => s.event.id)).toEqual(["x1"]);
  });

  it("gives one seat per distinct account, not one per row", () => {
    const rows = Array.from({ length: 50 }, (_, i) => explicit(`r${i}`, i, "second"));
    rows.push(explicit("o1", 99, "third"));
    const seats = accountLogonSeats({ events: rows, hostOf: lower });
    expect(seats.map((s) => s.event.id).sort()).toEqual(["o1", "r0"]);
  });

  it("skips machine and built-in service accounts", () => {
    const rows = [
      explicit("m1", 1, "HOST-A$"),
      explicit("s1", 2, "SYSTEM"),
      explicit("s2", 3, "DWM-2"),
      explicit("s3", 4, "UMFD-0"),
      ev(
        "s4",
        5,
        "Medium",
        "Windows Security Logon with explicit credentials (EID 4648) - NT AUTHORITY\\LOCAL SERVICE, EXAMPLE\\HOST-A$",
      ),
    ];
    expect(accountLogonSeats({ events: rows, hostOf: lower })).toEqual([]);
  });

  it("ignores Critical/High and Info rows and non-network 4624 types", () => {
    const rows = [
      explicit("h1", 1, "alpha", undefined, "High"),
      explicit("i1", 2, "beta", undefined, "Info"),
      ev("t2", 3, "Low", "Windows Security Successful logon (EID 4624) - EXAMPLE\\gamma - LogonType=2"),
    ];
    expect(accountLogonSeats({ events: rows, hostOf: lower })).toEqual([]);
  });

  it("seats a 4624 type 3 account only when no anchor already names it", () => {
    const rows = [
      logon3("l1", 1, "delta"),
      logon3("l2", 2, "epsilon"),
      ev("an", 3, "High", "Suspicious activity by EXAMPLE\\epsilon on host"),
    ];
    const ids = accountLogonSeats({ events: rows, hostOf: lower }).map((s) => s.event.id);
    expect(ids).toEqual(["l1"]);
  });

  it("puts 4648 before 4624 and round-robins across hosts", () => {
    const rows = [
      logon3("l1", 1, "one", "HOST-A.example.com"),
      explicit("e1", 50, "two", "HOST-A.example.com"),
      explicit("e2", 60, "three", "HOST-B.example.com"),
      explicit("e3", 70, "four", "HOST-A.example.com"),
    ];
    const ids = accountLogonSeats({ events: rows, hostOf: lower }).map((s) => s.event.id);
    expect(ids).toEqual(["e1", "e2", "e3", "l1"]);
  });

  it("is deterministic and does not mutate its input", () => {
    const rows = [explicit("e1", 1, "two"), explicit("e2", 2, "three", "HOST-B.example.com")];
    const snapshot = JSON.stringify(rows);
    const a = accountLogonSeats({ events: rows, hostOf: lower }).map((s) => s.event.id);
    const b = accountLogonSeats({ events: [...rows].reverse(), hostOf: lower }).map((s) => s.event.id);
    expect(a).toEqual(b);
    expect(JSON.stringify(rows)).toBe(snapshot);
  });

  it("caps the reserve between 1 and the ceiling", () => {
    expect(accountSeatCap(0)).toBe(0);
    expect(accountSeatCap(10)).toBe(1);
    expect(accountSeatCap(600)).toBeLessThanOrEqual(ACCOUNT_SEAT_MAX);
    expect(accountSeatCap(1_000_000)).toBe(ACCOUNT_SEAT_MAX);
  });
});

const domainRow = (id: string, s: number, who: string, sev: Severity = "Medium") =>
  ev(id, s, sev, `Windows Security Logon with explicit credentials (EID 4648) - ${who}, X\\HOST-A$`);
const seatIds = (rows: ForensicEvent[]): string[] =>
  accountLogonSeats({ events: rows, hostOf: lower })
    .map((x) => x.event.id)
    .sort();

describe("account identity", () => {
  it("keeps the same name in two different domains as two accounts", () => {
    expect(seatIds([domainRow("a", 1, "ALPHA\\admin"), domainRow("b", 2, "BETA\\admin")])).toEqual([
      "a",
      "b",
    ]);
  });

  it("merges the FQDN and NetBIOS forms of one domain", () => {
    expect(seatIds([domainRow("a", 1, "CORP.EXAMPLE\\jdoe"), domainRow("b", 2, "CORP\\jdoe")])).toEqual([
      "a",
    ]);
  });

  it("merges a host-local (no domain) row with a domain-qualified one of the same name", () => {
    expect(seatIds([domainRow("a", 1, "jdoe"), domainRow("b", 2, "ALPHA\\jdoe")])).toEqual(["a"]);
  });

  it("merges casing variants", () => {
    expect(seatIds([domainRow("a", 1, "Alpha\\JDoe"), domainRow("b", 2, "ALPHA\\jdoe")])).toEqual(["a"]);
  });

  it("seats a UPN-only row from the description", () => {
    expect(seatIds([domainRow("a", 1, "alice@example.test")])).toEqual(["a"]);
  });

  it("treats a UPN domain like a backslash domain", () => {
    expect(
      seatIds([domainRow("a", 1, "alice@alpha.example.test"), domainRow("b", 2, "BETA\\alice")]),
    ).toEqual(["a", "b"]);
    expect(
      seatIds([domainRow("a", 1, "alice@alpha.example.test"), domainRow("b", 2, "ALPHA\\alice")]),
    ).toEqual(["a"]);
  });
});

describe("account seats keep their own budget", () => {
  const accountRows = (n: number): ForensicEvent[] =>
    Array.from({ length: n }, (_, i) => explicit(`acc${i}`, 9000 + i, `user${word(i)}`));
  const commandRows = (n: number): ForensicEvent[] =>
    Array.from({ length: n }, (_, i) => {
      const commandLine = `net group recon${word(i)} /domain`;
      return {
        ...ev(`cmd${i}`, i * 7 + 3, "Low", commandLine),
        commandLine,
        processName: "cmd.exe",
      };
    });

  it("seats at most the account cap and still seats the commands", () => {
    const anchors = Array.from({ length: 700 }, (_, i) =>
      ev(`h${i}`, i * 7, "High", `detection ${word(i)} fired`),
    );
    const events = [...anchors, ...accountRows(60), ...commandRows(40)];
    const sel = select(events);
    expect(sel.maxEvents).toBe(600);
    expect(sel.selection.counts.account).toBeLessThanOrEqual(accountSeatCap(600));
    expect(sel.selection.counts.account).toBeGreaterThan(0);
    const commandIds = sel.promptEvents.filter((e) => e.id.startsWith("cmd")).length;
    expect(commandIds).toBeGreaterThan(0);
    expect(sel.selection.counts.command).toBeLessThanOrEqual(commandSeatCap(600));
    expect(sel.promptEvents.length).toBeLessThanOrEqual(600);
  });

  it("recomputes the account cap in fitTo", () => {
    const events = [...bigCase(accountRows(60))];
    const sel = select(events);
    expect(sel.selection.counts.account).toBe(accountSeatCap(600));
    sel.fitTo(200);
    expect(sel.promptEvents.length).toBeLessThanOrEqual(200);
    expect(sel.selection.counts.account).toBeLessThanOrEqual(accountSeatCap(200));
  });

  it("labels account rows 'account' and keeps the selector's own result untouched", () => {
    const sel = select(bigCase([explicit("target", 7777, "second")]));
    expect(sel.selection.classOf.get("target")).toBe("account");
    expect(sel.selection.counts.account).toBe(1);
  });
});

describe("prompt selection with account seats", () => {
  it("seats a second account's 4648 row on a timeline larger than the cap", () => {
    const target = explicit("target", 7777, "second");
    const events = bigCase([target]);
    const sel = select(events);
    expect(events.length).toBeGreaterThan(sel.maxEvents);
    expect(sel.promptEvents.map((e) => e.id)).toContain("target");
    expect(sel.selection.classOf.get("target")).toBe("account");
  });

  it("never exceeds the cap and keeps every anchor", () => {
    const extras = Array.from({ length: 30 }, (_, i) => explicit(`x${i}`, 8000 + i, `acct${word(i)}`));
    const events = bigCase(extras);
    const sel = select(events);
    expect(sel.promptEvents.length).toBeLessThanOrEqual(sel.maxEvents);
    const shown = new Set(sel.promptEvents.map((e) => e.id));
    expect(Array.from({ length: 40 }, (_, i) => `a${i}`).every((id) => shown.has(id))).toBe(true);
    // The reserved class holds at most the stated reserve (rare rows can win seats through other fills).
    expect(sel.selection.counts.account).toBeLessThanOrEqual(accountSeatCap(sel.maxEvents));
    expect(sel.selection.counts.command).toBeLessThanOrEqual(commandSeatCap(sel.maxEvents));
  });

  it("is identical for identical input", () => {
    const events = bigCase([explicit("target", 7777, "second")]);
    const ids = (): string[] => select(events).promptEvents.map((e) => e.id);
    expect(ids()).toEqual(ids());
  });

  it("does not shrink the command-seat reserve", () => {
    expect(commandSeatCap(600)).toBe(40);
  });
});
