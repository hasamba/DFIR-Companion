// #2306 — the MFA-fatigue correlator: N denied / timed-out prompts for one user in one tenant inside
// the window, then a success. Pure units: window edges, tenant isolation, the success reset, the
// first-crossing emission gate (idempotence across imports) and the rendered row.
import { describe, it, expect } from "vitest";
import {
  MFA_FATIGUE_THRESHOLD,
  MFA_FATIGUE_WINDOW_MINUTES,
  isFatiguePrompt,
  mfaFatigueEpisodes,
  episodesInSpan,
  fatigueEventId,
  fatigueRows,
} from "../../src/analysis/mfaFatigue.js";
import type { StoredAuthObservation } from "../../src/analysis/authObservationStore.js";

const BASE = Date.parse("2026-06-01T10:00:00Z");
const MIN = 60_000;
const TENANT_A = "00000000-0000-4000-8000-00000000000a";
const TENANT_B = "00000000-0000-4000-8000-00000000000b";
let seq = 0;

function obs(over: Partial<StoredAuthObservation> & { at: number }): StoredAuthObservation {
  seq++;
  const { at, ...rest } = over;
  return {
    timestamp: new Date(BASE + at * MIN).toISOString(),
    account: "victim@example.com",
    sourceIp: "203.0.113.20",
    hostOrTenant: TENANT_A,
    outcome: "interrupted",
    mfaDetail: "denied",
    mfaConfirmed: true,
    resultCode: "500121",
    locator: `record:${seq}`,
    importer: "m365",
    importBatch: "m1",
    recordId: `rec-${seq}`,
    ...rest,
  };
}
const prompt = (at: number, over: Partial<StoredAuthObservation> = {}) => obs({ at, ...over });
const success = (at: number, over: Partial<StoredAuthObservation> = {}) =>
  obs({
    at,
    outcome: "success",
    mfaDetail: "approved",
    mfaConfirmed: undefined,
    resultCode: "0",
    sourceIp: "198.51.100.7",
    ...over,
  });

describe("isFatiguePrompt", () => {
  it("counts a denied or timed-out interruption, never 'required' or an unconfirmed failure", () => {
    expect(isFatiguePrompt(prompt(0))).toBe(true);
    expect(isFatiguePrompt(prompt(0, { mfaDetail: "timed out" }))).toBe(true);
    expect(isFatiguePrompt(prompt(0, { mfaDetail: "required", resultCode: "50074" }))).toBe(false);
    expect(isFatiguePrompt(prompt(0, { mfaDetail: "unconfirmed" }))).toBe(false);
    expect(isFatiguePrompt(prompt(0, { outcome: "failed" }))).toBe(false);
  });
});

describe("mfaFatigueEpisodes", () => {
  it(`fires on ${MFA_FATIGUE_THRESHOLD} denied/timed-out prompts then a success`, () => {
    const eps = mfaFatigueEpisodes([prompt(0), prompt(2, { mfaDetail: "timed out" }), prompt(4), success(6)]);
    expect(eps).toHaveLength(1);
    expect(eps[0]).toMatchObject({ prompts: 3, denied: 2, timedOut: 1, hostOrTenant: TENANT_A });
    expect(eps[0].success.sourceIp).toBe("198.51.100.7");
  });

  it("does not fire below the threshold, or without a success", () => {
    expect(mfaFatigueEpisodes([prompt(0), prompt(1), success(2)])).toHaveLength(0);
    expect(mfaFatigueEpisodes([prompt(0), prompt(1), prompt(2), prompt(3)])).toHaveLength(0);
  });

  it("does not fire on 50074 'MFA required' interruptions alone", () => {
    const required = (at: number) => prompt(at, { mfaDetail: "required", resultCode: "50074" });
    expect(mfaFatigueEpisodes([required(0), required(1), required(2), required(3), success(4)])).toHaveLength(
      0,
    );
  });

  it("window edge: a prompt exactly at the window boundary counts, one minute past it does not", () => {
    const w = MFA_FATIGUE_WINDOW_MINUTES;
    expect(mfaFatigueEpisodes([prompt(0), prompt(w - 2), prompt(w - 1), success(w)])).toHaveLength(1);
    expect(mfaFatigueEpisodes([prompt(-1), prompt(w - 2), prompt(w - 1), success(w)])).toHaveLength(0);
  });

  it("tenant isolation: prompts in one tenant never pair with a success in another", () => {
    const eps = mfaFatigueEpisodes([
      prompt(0),
      prompt(1),
      prompt(2, { hostOrTenant: TENANT_B }),
      success(3),
      success(4, { hostOrTenant: TENANT_B }),
    ]);
    expect(eps).toHaveLength(0);
  });

  it("accounts are matched trimmed + lowercased; a different account never pairs", () => {
    expect(
      mfaFatigueEpisodes([prompt(0), prompt(1, { account: " Victim@Example.com" }), prompt(2), success(3)]),
    ).toHaveLength(1);
    expect(
      mfaFatigueEpisodes([prompt(0), prompt(1), prompt(2), success(3, { account: "other@example.com" })]),
    ).toHaveLength(0);
  });

  it("a success resets the count: prompts before an earlier success do not carry over", () => {
    expect(mfaFatigueEpisodes([prompt(0), prompt(1), success(2), prompt(3), success(4)])).toHaveLength(0);
  });

  it("is order-independent (deterministic over a shuffled input)", () => {
    const rows = [prompt(0), prompt(1), prompt(2), success(3)];
    const a = mfaFatigueEpisodes(rows).map((e) => e.identity);
    const b = mfaFatigueEpisodes([...rows].reverse()).map((e) => e.identity);
    expect(a).toEqual(b);
  });
});

describe("episodesInSpan — only episodes whose whole window was read", () => {
  it("keeps an episode whose success lies inside the import's span, drops one whose window was cut off", () => {
    const rows = [prompt(0), prompt(1), prompt(2), success(3)];
    const iso = (m: number) => new Date(BASE + m * MIN).toISOString();
    expect(episodesInSpan(rows, { earliest: iso(0), latest: iso(3) })).toHaveLength(1);
    // the success is before this import's earliest observation: its window may predate the read
    expect(episodesInSpan(rows, { earliest: iso(4), latest: iso(10) })).toHaveLength(0);
  });
});

describe("fatigueEventId — the stable forensic-timeline id", () => {
  it("is the same for the same episode, whatever import emits it, and absent for other rows", () => {
    const eps = mfaFatigueEpisodes([prompt(0), prompt(1), prompt(2), success(3)]);
    const row = fatigueRows(eps, { truncatedHistory: false })[0];
    const id = fatigueEventId(row);
    expect(id).toBe(`mfa-fatigue-${eps[0].identity}`);
    expect(fatigueEventId({ aggKey: "entra-signin|x" })).toBeUndefined();
    expect(fatigueEventId({})).toBeUndefined();
  });
});

describe("legacy observations (stored before #2306)", () => {
  it("a 'denied' row without the confirmed-detail mark never counts", () => {
    const legacy = (at: number) => prompt(at, { mfaConfirmed: undefined });
    expect(isFatiguePrompt(legacy(0))).toBe(false);
    expect(mfaFatigueEpisodes([legacy(0), legacy(1), legacy(2), success(3)])).toHaveLength(0);
  });
});

describe("fatigueRows", () => {
  it("renders one High row above Info with T1621 and source-record references", () => {
    const eps = mfaFatigueEpisodes([prompt(0), prompt(1), prompt(2), success(3)]);
    const rows = fatigueRows(eps, { truncatedHistory: false });
    expect(rows).toHaveLength(1);
    const r = rows[0];
    expect(r.severity).toBe("High");
    expect(r.mitre).toContain("T1621");
    expect(r.description).toMatch(
      /^Possible MFA fatigue: 3 rejected or timed-out MFA prompts for victim@example\.com, then a successful sign-in/,
    );
    const refs = r.canonical!.evidence.rawRecords;
    expect(refs).toHaveLength(4);
    expect(refs.every((x) => x.locator.startsWith("m1:record:"))).toBe(true);
    expect(refs.map((x) => x.recordId)).toContain(eps[0].success.recordId);
  });

  it("the same episode renders the same aggKey, timestamp and description (stable identity)", () => {
    const rows = [prompt(0), prompt(1), prompt(2), success(3)];
    const a = fatigueRows(mfaFatigueEpisodes(rows), { truncatedHistory: false })[0];
    const b = fatigueRows(mfaFatigueEpisodes([...rows].reverse()), { truncatedHistory: false })[0];
    expect([a.aggKey, a.timestamp, a.description]).toEqual([b.aggKey, b.timestamp, b.description]);
  });

  it("discloses a capped history read", () => {
    const eps = mfaFatigueEpisodes([prompt(0), prompt(1), prompt(2), success(3)]);
    expect(fatigueRows(eps, { truncatedHistory: true })[0].description).toContain("may be a floor");
  });
});
