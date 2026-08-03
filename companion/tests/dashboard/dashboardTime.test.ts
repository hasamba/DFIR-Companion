import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { TimeApi } from "./dashboardApi.js";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

// public/js/dashboard-time.js — every relative-time and duration formatter the dashboard had (#415).
//
// None of this code had ever been reachable from a test. Writing these is what turned "six similar
// functions" into the table below: they disagree on every edge, and three of the disagreements are
// only visible when you call them side by side with the same argument.

const {
  lgAgo,
  veloClientsAge,
  veloMonAge,
  relTime,
  activityTimeAgo,
  cockpitAge,
  isoToUtcInput,
  utcInputToIso,
  fmtTime,
  mcpJobDuration,
  skewOffsetLabel,
} = loadDashboardModule<TimeApi>("dashboard-time.js");

const NOW = Date.parse("2026-03-01T12:00:00.000Z");
const ago = (ms: number) => new Date(NOW - ms).toISOString();

beforeEach(() => {
  vi.useFakeTimers();
  vi.setSystemTime(NOW);
});
afterEach(() => vi.useRealTimers());

// THE POINT OF PUTTING THESE IN ONE FILE. Six functions, one job, six answers. Nothing is asserted
// here about which is right — they are moved verbatim, because changing what six panels render is
// a product decision and not a refactor's. This table is what makes the decision possible later,
// and what stops any of them changing by accident in the meantime.
describe("the six relative-time formatters disagree, on purpose recorded", () => {
  const FNS = { lgAgo, veloClientsAge, veloMonAge, relTime, activityTimeAgo, cockpitAge };

  it.each([
    ["lgAgo", "just now", "just now", "a few seconds ago", "2 min ago", "3 h ago"],
    ["veloClientsAge", "never refreshed", "just now", "just now", "1m ago", "3h ago"],
    ["veloMonAge", "never", "just now", "30s ago", "1m ago", "3h ago"],
    ["relTime", "never", "unknown", "30s ago", "2m ago", "3h ago"],
    ["activityTimeAgo", "—", "—", "just now", "1m ago", "3h ago"],
    ["cockpitAge", "", "", "just now", "1m ago", "3h ago"],
  ])("%s: null=%j unparseable=%j 30s=%j 90s=%j 3h=%j", (name, onNull, onJunk, s30, s90, h3) => {
    const fn = FNS[name as keyof typeof FNS];
    expect(fn(null)).toBe(onNull);
    expect(fn("nonsense")).toBe(onJunk);
    expect(fn(ago(30_000))).toBe(s30);
    expect(fn(ago(90_000))).toBe(s90);
    expect(fn(ago(3 * 3_600_000))).toBe(h3);
  });

  // THE BUG #415 PINNED HERE, FIXED BY #458 — this test and the table row above are the two places
  // that pinned it. `new Date(null)` is the epoch, not Invalid Date, so activityTimeAgo was the one
  // of the six that reported a missing timestamp as 57 years ago — a literal "20513d ago" in the
  // activity feed — while its five siblings all guarded with `!iso` or Number.isFinite first. Only
  // null ever hit it: `new Date(undefined)` IS Invalid Date, so undefined already returned "—".
  //
  // IT RETURNS "—", NOT A SIBLING'S PLACEHOLDER. Both call sites render this into a muted, nowrap
  // table column with the row's raw timestamp already in a `title` tooltip: the Activity Log (#238)
  // and the Chain of Custody event table (#231). "never"/"never refreshed" would claim the logged
  // activity did not happen when it is only its timestamp that is missing, "just now" would invent
  // one, and "" would leave a blank cell that reads as a broken render rather than as absent data.
  // "—" is what this function already returned for an unparseable string, and what the custody
  // table beside it already renders for an unknown verification state.
  //
  // The sibling sweep is kept and now covers all six: it is what catches a seventh formatter added
  // without a guard, which is how this one got here.
  it("renders a placeholder for a missing timestamp, like its five siblings", () => {
    for (const missing of [null, undefined, ""]) {
      expect(activityTimeAgo(missing)).toBe("—");
    }
    for (const fn of [lgAgo, veloClientsAge, veloMonAge, relTime, activityTimeAgo, cockpitAge]) {
      expect(fn(null)).not.toMatch(/d ago$/);
    }
  });

  // Two round and four floor, which is why 90 seconds is "1m ago" in four panels and "2m ago" in
  // the other two.
  it("splits 4-2 between flooring and rounding at 90 seconds", () => {
    expect([lgAgo(ago(90_000)), relTime(ago(90_000))]).toEqual(["2 min ago", "2m ago"]);
    for (const fn of [veloClientsAge, veloMonAge, activityTimeAgo, cockpitAge]) {
      expect(fn(ago(90_000))).toBe("1m ago");
    }
  });

  it("cockpitAge alone falls back to an absolute timestamp past 48h", () => {
    expect(cockpitAge(ago(49 * 3_600_000))).toBe(new Date(NOW - 49 * 3_600_000).toLocaleString());
    expect(relTime(ago(49 * 3_600_000))).toBe("2d ago");
  });

  it("clamps a future timestamp rather than counting down", () => {
    const future = new Date(NOW + 60_000).toISOString();
    expect(relTime(future)).toBe("0s ago");
    expect(lgAgo(future)).toBe("a few seconds ago");
    expect(veloMonAge(future)).toBe("just now");
  });
});

// The datetime-local round trip. The picked wall-clock IS UTC — that is the whole contract, and it
// is the sort of thing that reads as a bug to anyone who assumes local time.
describe("isoToUtcInput / utcInputToIso", () => {
  it("renders an ISO instant as the UTC wall clock a datetime-local input wants", () => {
    expect(isoToUtcInput("2026-03-01T12:34:56.000Z")).toBe("2026-03-01T12:34");
    expect(isoToUtcInput("2026-01-02T03:04:05Z")).toBe("2026-01-02T03:04");
  });

  it("reads the picked wall clock back as UTC, not local", () => {
    expect(utcInputToIso("2026-03-01T12:34")).toBe("2026-03-01T12:34:00.000Z");
    expect(utcInputToIso("2026-03-01T12:34:56")).toBe("2026-03-01T12:34:56.000Z");
  });

  it("round-trips to the minute", () => {
    expect(utcInputToIso(isoToUtcInput("2026-03-01T12:34:56.789Z"))).toBe("2026-03-01T12:34:00.000Z");
  });

  it("returns the empty string / null rather than throwing on junk", () => {
    expect(isoToUtcInput("")).toBe("");
    expect(isoToUtcInput("nope")).toBe("");
    expect(utcInputToIso("")).toBeNull();
    expect(utcInputToIso("nope")).toBeNull();
  });
});

describe("mcpJobDuration", () => {
  it.each([
    [0, "0s"],
    [999, "0s"],
    [59_000, "59s"],
    [60_000, "1m 0s"],
    [3_599_000, "59m 59s"],
    [3_600_000, "1h 0m"],
    [3_725_000, "1h 2m"],
  ])("%ims -> %s", (ms, expected) => expect(mcpJobDuration(ms)).toBe(expected));

  it("floors a negative duration to zero instead of rendering a minus sign", () => {
    expect(mcpJobDuration(-5_000)).toBe("0s");
  });
});

// Clock skew is signed on purpose: which direction the endpoint's clock is wrong matters as much
// as by how much, so unlike the durations above this one keeps the sign.
describe("skewOffsetLabel", () => {
  it.each([
    [0, "0s"],
    [250, "250ms"],
    [-250, "-250ms"],
    [1_000, "1s"],
    [1_500, "1.5s"],
    [-89_000, "-89s"],
    [90_000, "1.5m"],
    [-125_000, "-2.1m"],
    [5_400_000, "1.50h"],
  ])("%ims -> %s", (ms, expected) => expect(skewOffsetLabel(ms)).toBe(expected));
});

describe("fmtTime", () => {
  it("renders the locale time for a valid instant", () => {
    expect(fmtTime("2026-03-01T12:00:00Z")).toBe(new Date("2026-03-01T12:00:00Z").toLocaleTimeString());
  });

  // `new Date("nope").toLocaleTimeString()` returns "Invalid Date" rather than throwing, so the
  // catch never fires and the input is not echoed back. Recorded because the code reads as though
  // it would be.
  it("returns Invalid Date, not the input, for junk", () => {
    expect(fmtTime("nope")).toBe("Invalid Date");
  });
});
