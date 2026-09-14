// #933 item 19, second half (#1024): an intel assertion is superseded only by a fresh assertion of
// the same identity, never erased by a miss; an errored provider keeps its last-known state; a
// check that read an incomplete result concludes no absence; history appends only on material
// change and is bounded with an auditable compaction count.
import { describe, expect, it } from "vitest";
import {
  appendHistory,
  assertionIdFor,
  fingerprintOf,
  foldCheck,
  HISTORY_KEPT_TAIL,
  HISTORY_PER_ASSERTION_MAX,
  mergeIntelState,
  statusAtCheck,
} from "../../src/analysis/intelHistory.js";
import type { IOC, IocEnrichment } from "../../src/analysis/stateTypes.js";

const T = "2026-06-01T00:00:00.000Z";
const at = (h: number) => new Date(Date.parse(T) + h * 3_600_000).toISOString();
const ioc = (over: Partial<IOC> = {}): IOC => ({
  id: "i1",
  type: "ip",
  value: "203.0.113.5",
  firstSeen: T,
  ...over,
});
const hit = (over: Partial<IocEnrichment> = {}): IocEnrichment => {
  const base: IocEnrichment = {
    source: "ThreatFox",
    provider: "Hunting.ch",
    verdict: "malicious",
    fetchedAt: at(0),
    providerRecordId: "tf-1",
    ...over,
  };
  return {
    ...base,
    assertionId: base.assertionId ?? assertionIdFor(base, "203.0.113.5"),
    status: base.status ?? statusAtCheck(base, base.fetchedAt),
  };
};

describe("identity and fingerprint", () => {
  it("the identity is (owner, source, provider record id); the IOC value stands in when the provider names no record", () => {
    expect(
      assertionIdFor({ provider: "Hunting.ch", source: "ThreatFox", providerRecordId: "tf-1" }, "x"),
    ).toBe(assertionIdFor({ provider: "hunting.ch", source: "threatfox", providerRecordId: "tf-1" }, "y"));
    expect(assertionIdFor({ source: "VirusTotal" }, "abc")).toBe(
      assertionIdFor({ source: "VirusTotal" }, "ABC"),
    );
    expect(assertionIdFor({ source: "VirusTotal" }, "abc")).not.toBe(
      assertionIdFor({ source: "VirusTotal" }, "abd"),
    );
    expect(
      assertionIdFor({ provider: "Hunting.ch", source: "ThreatFox", providerRecordId: "tf-1" }, "x"),
    ).not.toBe(assertionIdFor({ provider: "Hunting.ch", source: "URLhaus", providerRecordId: "tf-1" }, "x"));
  });
  it("a verdict string is not the identity; the fingerprint covers every material field", () => {
    const a = hit({ verdict: "malicious" });
    const b = hit({ verdict: "suspicious" });
    expect(a.assertionId).toBe(b.assertionId);
    expect(fingerprintOf(a)).not.toBe(fingerprintOf(b));
    expect(fingerprintOf(hit({ tags: ["b", "a"] }))).toBe(fingerprintOf(hit({ tags: ["a", "b"] })));
  });
  it("the status at the check is the provider's own fact: revoked, expired by validity, else live", () => {
    expect(statusAtCheck(hit({ revoked: true }), at(0))).toBe("revoked");
    expect(statusAtCheck(hit({ validity: { until: at(-1) } }), at(0))).toBe("expired");
    expect(statusAtCheck(hit({ validity: { until: at(1) } }), at(0))).toBe("live");
  });
});

describe("foldCheck — supersession, misses, errors, incomplete reads", () => {
  it("a fresh assertion supersedes the one with its identity; a same-provider check that does not return a known assertion marks it not-returned, never erased", () => {
    const first = ioc({
      enrichments: [
        hit({ providerRecordId: "tf-1" }),
        hit({ providerRecordId: "tf-2", verdict: "suspicious" }),
      ],
    });
    const fresh = hit({ providerRecordId: "tf-1", verdict: "suspicious", fetchedAt: at(2) });
    const out = foldCheck(
      first,
      [fresh],
      [{ provider: "Hunting.ch", backend: "ThreatFox", outcome: "hit" }],
      at(2),
    );
    const byRecord = new Map(out.enrichments!.map((e) => [e.providerRecordId, e]));
    expect(byRecord.get("tf-1")).toMatchObject({ verdict: "suspicious", status: "live", fetchedAt: at(2) });
    expect(byRecord.get("tf-2")).toMatchObject({
      verdict: "suspicious",
      status: "not-returned",
      lastMissAt: at(2),
    });
    expect(out.enrichments).toHaveLength(2);
    expect(out.intelChecks).toMatchObject({ "Hunting.ch|ThreatFox": { outcome: "hit", at: at(2) } });
  });
  it("an errored backend keeps its assertions as last-known and is remembered even with no prior assertion", () => {
    const first = ioc({ enrichments: [hit()] });
    const out = foldCheck(
      first,
      [],
      [
        { provider: "Hunting.ch", backend: "ThreatFox", outcome: "error", detail: "timeout" },
        { provider: "Hunting.ch", backend: "URLhaus", outcome: "miss" },
      ],
      at(2),
    );
    expect(out.enrichments![0]).toMatchObject({ status: "errored-last-known", verdict: "malicious" });
    expect(out.intelChecks!["Hunting.ch|ThreatFox"]).toMatchObject({ outcome: "error", detail: "timeout" });
    const never = foldCheck(
      ioc(),
      [],
      [{ provider: "Hunting.ch", backend: "ThreatFox", outcome: "error" }],
      at(0),
    );
    expect(never.enrichments).toBeUndefined();
    expect(never.intelChecks!["Hunting.ch|ThreatFox"].outcome).toBe("error");
  });
  it("an incomplete read applies no absence; a miss by another backend does not touch this backend's assertion", () => {
    const first = ioc({ enrichments: [hit()] });
    const incomplete = foldCheck(
      first,
      [],
      [{ provider: "Hunting.ch", backend: "ThreatFox", outcome: "miss", incomplete: true }],
      at(2),
    );
    expect(incomplete.enrichments![0].status).toBe("live");
    const other = foldCheck(
      first,
      [],
      [{ provider: "Hunting.ch", backend: "URLhaus", outcome: "miss" }],
      at(2),
    );
    expect(other.enrichments![0].status).toBe("live");
    const revoked = foldCheck(
      ioc({ enrichments: [hit({ status: "revoked", revoked: true })] }),
      [],
      [{ provider: "Hunting.ch", backend: "ThreatFox", outcome: "miss" }],
      at(2),
    );
    expect(revoked.enrichments![0].status).toBe("revoked");
  });
  it("a legacy hit (no tracking) reads as legacy-unverified and is superseded by the fresh assertion of its identity", () => {
    const legacy: IocEnrichment = { source: "VirusTotal", verdict: "malicious", fetchedAt: at(-24) };
    const first = ioc({ enrichments: [legacy] });
    const fresh = hit({
      source: "VirusTotal",
      provider: undefined,
      providerRecordId: undefined,
      fetchedAt: at(0),
    });
    const out = foldCheck(first, [fresh], [{ provider: "VirusTotal", outcome: "hit" }], at(0));
    expect(out.enrichments).toHaveLength(1);
    expect(out.enrichments![0].status).toBe("live");
    const untouched = foldCheck(first, [], [{ provider: "AbuseIPDB", outcome: "miss" }], at(0));
    expect(untouched.enrichments![0].status).toBe("legacy-unverified");
  });
  it("a retired provider's hit whose source a fresh result of another owner now emits is superseded, recorded in history", () => {
    const stale: IocEnrichment = {
      source: "MalwareBazaar",
      verdict: "malicious",
      fetchedAt: at(-24),
      score: "old",
    };
    const fresh = hit({
      source: "MalwareBazaar",
      provider: "Hunting.ch",
      providerRecordId: "sha",
      score: "new",
    });
    const out = foldCheck(
      ioc({ enrichments: [stale] }),
      [fresh],
      [{ provider: "Hunting.ch", backend: "MalwareBazaar", outcome: "hit" }],
      at(0),
    );
    expect(out.enrichments).toHaveLength(1);
    expect(out.enrichments![0].score).toBe("new");
    expect(out.intelHistory!.some((r) => r.status === "superseded" && r.source === "MalwareBazaar")).toBe(
      true,
    );
  });
});

describe("history — material change, coalescing, the bound", () => {
  it("identical consecutive checks coalesce onto one record; a material change appends", () => {
    let h = appendHistory(undefined, hit(), at(0));
    h = appendHistory(h, hit({ fetchedAt: at(1) }), at(1));
    expect(h).toHaveLength(1);
    expect(h[0]).toMatchObject({ checkCount: 2, firstCheckedAt: at(0), lastCheckedAt: at(1) });
    h = appendHistory(h, hit({ verdict: "suspicious", fetchedAt: at(2) }), at(2));
    expect(h).toHaveLength(2);
    expect(h[1]).toMatchObject({ verdict: "suspicious", checkCount: 1 });
    // A reassigned address whose reputation flipped: both states stay, the newest is the latest.
    h = appendHistory(h, hit({ verdict: "malicious", fetchedAt: at(3) }), at(3));
    expect(h).toHaveLength(3);
  });
  it("past the per-assertion bound the first record and the newest tail are kept, the rest counted", () => {
    let h = appendHistory(undefined, hit({ score: "s0" }), at(0));
    for (let i = 1; i <= HISTORY_PER_ASSERTION_MAX + 10; i += 1)
      h = appendHistory(h, hit({ score: `s${i}`, fetchedAt: at(i) }), at(i));
    // Compaction runs when the bound is crossed: the first record and the newest tail survive it,
    // records appended after it accumulate again until the next crossing.
    expect(h.length).toBeLessThanOrEqual(HISTORY_PER_ASSERTION_MAX);
    expect(h.length).toBe(1 + HISTORY_KEPT_TAIL + 10);
    expect(h[0].score).toBe("s0");
    expect(h[0].compacted).toBe(HISTORY_PER_ASSERTION_MAX - HISTORY_KEPT_TAIL);
    expect(h[h.length - 1].score).toBe(`s${HISTORY_PER_ASSERTION_MAX + 10}`);
  });
  it("foldCheck appends only when the state changed and records the check regardless", () => {
    const first = ioc({ enrichments: [hit()], intelHistory: appendHistory(undefined, hit(), at(0)) });
    const same = foldCheck(
      first,
      [hit({ fetchedAt: at(1) })],
      [{ provider: "Hunting.ch", backend: "ThreatFox", outcome: "hit" }],
      at(1),
    );
    expect(same.intelHistory).toHaveLength(1);
    expect(same.intelHistory![0].checkCount).toBe(2);
  });
});

describe("mergeIntelState — two versions of one IOC", () => {
  it("the newest check per assertion wins; histories union by (id, fingerprint, first check); checks by newest time", () => {
    const base = ioc({
      enrichments: [hit({ status: "revoked", revoked: true, fetchedAt: at(2) })],
      intelHistory: [
        ...appendHistory(undefined, hit(), at(0)),
        ...appendHistory(undefined, hit({ status: "revoked", revoked: true }), at(2)),
      ],
      intelChecks: { "Hunting.ch|ThreatFox": { outcome: "hit", at: at(2) } },
    });
    const stale = ioc({
      enrichments: [hit({ fetchedAt: at(1) })],
      intelHistory: appendHistory(undefined, hit(), at(0)),
      intelChecks: { "Hunting.ch|ThreatFox": { outcome: "hit", at: at(1) } },
    });
    const merged = mergeIntelState(base, stale);
    expect(merged.enrichments![0].status).toBe("revoked");
    expect(merged.intelHistory).toHaveLength(2);
    expect(merged.intelChecks!["Hunting.ch|ThreatFox"].at).toBe(at(2));
    expect(mergeIntelState(ioc(), ioc())).toEqual({});
  });
});
