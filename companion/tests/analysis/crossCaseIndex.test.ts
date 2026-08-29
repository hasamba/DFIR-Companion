import { describe, it, expect } from "vitest";
import {
  buildCrossCaseIndex,
  relatedCases,
  searchCrossCaseIocs,
  normalizeCrossCaseValue,
  pivotWeight,
  INTERNAL_PIVOT_WEIGHT,
  MIN_SUBSTRING_QUERY,
  type CaseIocSnapshot,
} from "../../src/analysis/crossCaseIndex.js";
import type { IOC } from "../../src/analysis/stateTypes.js";

// The cross-case IOC pivot (#679). Everything here is a pure function of the snapshots handed in —
// the permission gate that decides WHICH snapshots exist lives in routes/crossCase.ts and is tested
// in tests/server/crossCaseRoutes.test.ts.

function ioc(over: Partial<IOC> & Pick<IOC, "id" | "type" | "value">): IOC {
  return { firstSeen: "2026-01-01T00:00:00Z", ...over };
}

function malicious(over: Partial<IOC> & Pick<IOC, "id" | "type" | "value">): IOC {
  return ioc({
    ...over,
    enrichments: [{ source: "VirusTotal", verdict: "malicious", fetchedAt: "2026-01-02T00:00:00Z" }],
  });
}

function snapshot(caseId: string, iocs: IOC[], over: Partial<CaseIocSnapshot> = {}): CaseIocSnapshot {
  return { caseId, name: `Case ${caseId}`, status: "open", iocs, ...over };
}

describe("crossCaseIndex — building the index", () => {
  it("folds case and whitespace but nothing else", () => {
    expect(normalizeCrossCaseValue("  EVIL.com ")).toBe("evil.com");
    // Not folded: the index must not invent an equivalence the analyst never asserted.
    expect(normalizeCrossCaseValue("www.evil.com")).not.toBe(normalizeCrossCaseValue("evil.com"));
  });

  it("keeps a URL's path and query case-sensitive while folding scheme and host", () => {
    // RFC 3986 leaves the path and query to the origin server, and a Unix-backed host serves
    // /Object and /object as different resources. Folding the whole value would key them the same
    // and assert a shared indicator between two cases that never touched the same URL.
    expect(normalizeCrossCaseValue("HTTPS://Example.TEST:8443/Object?A=b#Frag", "url")).toBe(
      "https://example.test:8443/Object?A=b#Frag",
    );
    expect(normalizeCrossCaseValue("https://example.test/Object", "url")).not.toBe(
      normalizeCrossCaseValue("https://example.test/object", "url"),
    );
  });

  it("preserves userinfo case, which the host half of the authority does not", () => {
    // Userinfo may carry a password, and a password is case-sensitive — so the fold stops at the
    // "@". The fixture deliberately carries no `user:pass` half: the branch slices the whole
    // userinfo verbatim either way, and a synthetic credential in the tree is exactly what the
    // repo's secret scanners exist to flag.
    expect(normalizeCrossCaseValue("http://UserInfo@Host.TEST/p", "url")).toBe("http://UserInfo@host.test/p");
  });

  it("still folds a value that is not URL-shaped, whatever its type says", () => {
    expect(normalizeCrossCaseValue("EVIL.COM", "url")).toBe("evil.com");
    expect(normalizeCrossCaseValue("  Evil.COM  ", "domain")).toBe("evil.com");
  });

  it("does not link two cases holding URLs that differ only in path case", () => {
    const index = buildCrossCaseIndex([
      snapshot("a", [ioc({ id: "i1", type: "url", value: "https://example.test/Object" })]),
      snapshot("b", [ioc({ id: "i9", type: "url", value: "https://example.test/object" })]),
    ]);
    expect(relatedCases(index, "a")).toEqual([]);
  });

  it("still links two cases whose URLs differ only in host or scheme case", () => {
    const index = buildCrossCaseIndex([
      snapshot("a", [ioc({ id: "i1", type: "url", value: "HTTPS://Example.TEST/p" })]),
      snapshot("b", [ioc({ id: "i9", type: "url", value: "https://example.test/p" })]),
    ]);
    expect(relatedCases(index, "a")).toHaveLength(1);
  });

  it("indexes only the pivotable types by default", () => {
    const index = buildCrossCaseIndex([
      snapshot("a", [
        ioc({ id: "i1", type: "domain", value: "evil.com" }),
        ioc({ id: "i2", type: "process", value: "powershell.exe" }),
        ioc({ id: "i3", type: "file", value: "C:\\Windows\\Temp" }),
        ioc({ id: "i4", type: "sid", value: "S-1-5-18" }),
      ]),
    ]);
    expect([...index.byValue.keys()]).toEqual(["evil.com"]);
    expect(index.iocCount).toBe(1);
    expect(index.caseCount).toBe(1);
  });

  it("indexes a wider type set when the caller asks for one", () => {
    const index = buildCrossCaseIndex(
      [snapshot("a", [ioc({ id: "i1", type: "process", value: "rundll32.exe" })])],
      { types: ["process"] },
    );
    expect(index.byValue.has("rundll32.exe")).toBe(true);
  });

  it("indexes an analyst-merged alias alongside the canonical value", () => {
    // Without this, the per-case near-duplicate merge (#82) would destroy the very cross-case link
    // it was meant to clarify: case A folded "www.evil.com" into "evil.com", case B only ever saw
    // the "www." spelling.
    const index = buildCrossCaseIndex([
      snapshot("a", [ioc({ id: "i1", type: "domain", value: "evil.com", aliasValues: ["www.evil.com"] })]),
      snapshot("b", [ioc({ id: "i9", type: "domain", value: "WWW.Evil.com" })]),
    ]);
    expect(index.byValue.get("www.evil.com")?.caseIds).toEqual(["a", "b"]);
    // The IOC is counted once, however many keys it lands under.
    expect(index.iocCount).toBe(2);
  });

  it("reports the value each case actually stores, not the index key", () => {
    const index = buildCrossCaseIndex([
      snapshot("a", [ioc({ id: "i1", type: "domain", value: "EVIL.com" })]),
    ]);
    expect(index.byValue.get("evil.com")?.hits[0].value).toBe("EVIL.com");
  });

  it("skips an IOC whose value is only whitespace", () => {
    const index = buildCrossCaseIndex([snapshot("a", [ioc({ id: "i1", type: "domain", value: "   " })])]);
    expect(index.byValue.size).toBe(0);
    expect(index.iocCount).toBe(0);
  });
});

describe("crossCaseIndex — pivot weight", () => {
  it("counts a private address for a quarter of an external one", () => {
    expect(pivotWeight("ip", "10.1.2.3", false)).toBe(INTERNAL_PIVOT_WEIGHT);
    expect(pivotWeight("ip", "203.0.113.9", false)).toBe(1);
  });

  it("weighs a shared file hash above a shared domain", () => {
    expect(pivotWeight("hash", "a".repeat(64), false)).toBeGreaterThan(
      pivotWeight("domain", "evil.com", false),
    );
  });

  it("raises an indicator third-party intel already graded", () => {
    expect(pivotWeight("domain", "evil.com", true)).toBeGreaterThan(pivotWeight("domain", "evil.com", false));
  });

  it("keeps a private address low even with a verdict on it", () => {
    // A malicious verdict on the estate's own DC is a sign of stale intel, not of a shared
    // adversary — the same reasoning iocAnchors.ts uses for `internalConflict`.
    expect(pivotWeight("ip", "192.168.1.10", true)).toBe(INTERNAL_PIVOT_WEIGHT);
  });
});

describe("crossCaseIndex — searching", () => {
  const index = buildCrossCaseIndex([
    snapshot("a", [
      malicious({ id: "i1", type: "domain", value: "evil.com" }),
      ioc({ id: "i2", type: "ip", value: "10.0.0.5" }),
    ]),
    snapshot("b", [ioc({ id: "i7", type: "domain", value: "evil.com" })]),
    snapshot("c", [ioc({ id: "i8", type: "domain", value: "mail.evil.com" })]),
  ]);

  it("finds every case holding an exact value", () => {
    const result = searchCrossCaseIocs(index, "  EVIL.COM ");
    expect(result.query).toBe("evil.com");
    expect(result.entries[0].caseIds).toEqual(["a", "b"]);
    expect(result.entries[0].hits.some((h) => h.malicious)).toBe(true);
  });

  it("lists the exact match before its substring neighbours", () => {
    const result = searchCrossCaseIocs(index, "evil.com");
    expect(result.entries.map((e) => e.value)).toEqual(["evil.com", "mail.evil.com"]);
  });

  it("refuses to match on substring below the minimum query length", () => {
    const short = "ev".slice(0, MIN_SUBSTRING_QUERY - 1);
    expect(searchCrossCaseIocs(index, short).entries).toEqual([]);
  });

  it("answers an empty query with nothing rather than everything", () => {
    expect(searchCrossCaseIocs(index, "   ")).toEqual({
      query: "",
      entries: [],
      total: 0,
      truncated: false,
    });
  });

  it("can be narrowed to values held by more than one case", () => {
    const result = searchCrossCaseIocs(index, "evil", { minCases: 2 });
    expect(result.entries.map((e) => e.value)).toEqual(["evil.com"]);
  });

  it("filters by type and drops an entry left with no hits", () => {
    expect(searchCrossCaseIocs(index, "evil.com", { types: ["ip"] }).entries).toEqual([]);
    expect(searchCrossCaseIocs(index, "10.0.0.5", { types: ["ip"] }).entries).toHaveLength(1);
  });

  it("matches a URL-cased query on substring but not as an exact link", () => {
    // The two match modes fold case differently on purpose: a substring hit is a place to look, an
    // exact key is a claim that two cases hold the same indicator.
    const urls = buildCrossCaseIndex([
      snapshot("a", [ioc({ id: "i1", type: "url", value: "https://example.test/Object" })]),
      snapshot("b", [ioc({ id: "i9", type: "url", value: "https://example.test/object" })]),
    ]);
    const found = searchCrossCaseIocs(urls, "example.test/object");
    expect(found.entries.map((e) => e.value).sort()).toEqual([
      "https://example.test/Object",
      "https://example.test/object",
    ]);
    // …but they remain two separate entries, each held by one case.
    for (const entry of found.entries) expect(entry.caseIds).toHaveLength(1);
  });

  it("reports the true total when the limit truncates", () => {
    const result = searchCrossCaseIocs(index, "evil", { limit: 1 });
    expect(result.entries).toHaveLength(1);
    expect(result.total).toBe(2);
    expect(result.truncated).toBe(true);
  });
});

describe("crossCaseIndex — related cases", () => {
  it("finds the case sharing an indicator and names what it shares", () => {
    const index = buildCrossCaseIndex([
      snapshot("a", [ioc({ id: "i1", type: "domain", value: "evil.com" })]),
      snapshot("b", [ioc({ id: "i9", type: "domain", value: "evil.com" })], { name: "Phishing wave" }),
    ]);
    const related = relatedCases(index, "a");
    expect(related).toHaveLength(1);
    expect(related[0]).toMatchObject({ caseId: "b", name: "Phishing wave", sharedCount: 1 });
    expect(related[0].shared[0].value).toBe("evil.com");
  });

  it("never reports the subject case as related to itself", () => {
    const index = buildCrossCaseIndex([
      snapshot("a", [ioc({ id: "i1", type: "domain", value: "evil.com" })]),
    ]);
    expect(relatedCases(index, "a")).toEqual([]);
  });

  it("ranks a flagged external indicator above a private address", () => {
    const index = buildCrossCaseIndex([
      snapshot("a", [
        malicious({ id: "i1", type: "domain", value: "evil.com" }),
        ioc({ id: "i2", type: "ip", value: "10.0.0.5" }),
      ]),
      snapshot("weak", [ioc({ id: "w1", type: "ip", value: "10.0.0.5" })]),
      snapshot("strong", [ioc({ id: "s1", type: "domain", value: "evil.com" })]),
    ]);
    expect(relatedCases(index, "a").map((r) => r.caseId)).toEqual(["strong", "weak"]);
  });

  it("carries one side's intel verdict onto the shared indicator", () => {
    // Case B has not been enriched yet. The link is still the graded one, so the panel must say so.
    const index = buildCrossCaseIndex([
      snapshot("a", [malicious({ id: "i1", type: "domain", value: "evil.com" })]),
      snapshot("b", [ioc({ id: "i9", type: "domain", value: "evil.com" })]),
    ]);
    const [b] = relatedCases(index, "a");
    expect(b.shared[0].malicious).toBe(true);
    expect(b.maliciousCount).toBe(1);
  });

  it("marks a private address as an internal, de-rated link", () => {
    const index = buildCrossCaseIndex([
      snapshot("a", [ioc({ id: "i1", type: "ip", value: "10.0.0.5" })]),
      snapshot("b", [ioc({ id: "i9", type: "ip", value: "10.0.0.5" })]),
    ]);
    const [b] = relatedCases(index, "a");
    expect(b.shared[0].isInternal).toBe(true);
    expect(b.score).toBe(INTERNAL_PIVOT_WEIGHT);
  });

  it("counts one shared indicator once when both cases hold both spellings", () => {
    // Both cases carry the canonical value AND the alias, so the value-keyed index links the same
    // pair of IOCs twice. Tallying per matched key would double the count and the score.
    const withAlias = (id: string) =>
      ioc({ id, type: "domain", value: "evil.com", aliasValues: ["www.evil.com"] });
    const index = buildCrossCaseIndex([snapshot("a", [withAlias("i1")]), snapshot("b", [withAlias("i9")])]);
    const [b] = relatedCases(index, "a");
    expect(b.sharedCount).toBe(1);
    expect(b.score).toBe(1);
  });

  // THE THREE DEDUP GUARDS, ONE TEST EACH, EACH ISOLATED.
  //
  // The guards shadow one another: in any scenario with a single row on one side, two of the three
  // fire together, so a test built that way passes with any one of them deleted and pins nothing.
  // Each case below is shaped so exactly ONE guard can catch the duplicate pass, and each fails if
  // that guard is removed.

  it("counts one value once when BOTH cases hold it on two rows (the value guard)", () => {
    // Four combinations; the last has a fresh row on both sides, so neither row guard sees it and
    // only the value has been counted before. Same-value/different-id rows are supported existing
    // state: iocRepair.ts deliberately leaves them alone.
    const index = buildCrossCaseIndex([
      snapshot("a", [
        ioc({ id: "i1", type: "domain", value: "evil.com" }),
        ioc({ id: "i2", type: "domain", value: "EVIL.com" }),
      ]),
      snapshot("b", [
        ioc({ id: "i9", type: "domain", value: "evil.com" }),
        ioc({ id: "i8", type: "domain", value: "evil.com" }),
      ]),
    ]);
    const [b] = relatedCases(index, "a");
    expect(b.sharedCount).toBe(1);
    expect(b.score).toBe(1);
  });

  it("counts one indicator once when only THIS case merged the alias (the own-row guard)", () => {
    // a folded both spellings onto one row; b carries them as two. The second pass has a fresh
    // value and a fresh row on b's side — only a's row identity has been counted before.
    const index = buildCrossCaseIndex([
      snapshot("a", [ioc({ id: "i1", type: "domain", value: "evil.com", aliasValues: ["www.evil.com"] })]),
      snapshot("b", [
        ioc({ id: "i9", type: "domain", value: "evil.com" }),
        ioc({ id: "i8", type: "domain", value: "www.evil.com" }),
      ]),
    ]);
    const [b] = relatedCases(index, "a");
    expect(b.sharedCount).toBe(1);
    expect(b.shared[0].value).toBe("evil.com");
  });

  it("counts one indicator once when only the OTHER case merged the alias (the other-row guard)", () => {
    // The mirror: a holds two rows, b folded both onto one. a alone would call that two shared
    // indicators, but b has already declared them one thing, and one row is what is shared.
    const index = buildCrossCaseIndex([
      snapshot("a", [
        ioc({ id: "i1", type: "domain", value: "evil.com" }),
        ioc({ id: "i2", type: "domain", value: "www.evil.com" }),
      ]),
      snapshot("b", [ioc({ id: "i9", type: "domain", value: "evil.com", aliasValues: ["www.evil.com"] })]),
    ]);
    expect(relatedCases(index, "a")[0].sharedCount).toBe(1);
  });

  it("counts one indicator once when both sides merged the same alias", () => {
    const both = (id: string) =>
      ioc({ id, type: "domain", value: "evil.com", aliasValues: ["www.evil.com"] });
    const index = buildCrossCaseIndex([snapshot("a", [both("i1")]), snapshot("b", [both("i9")])]);
    expect(relatedCases(index, "a")[0].sharedCount).toBe(1);
  });

  it("does not collapse two genuinely different shared indicators", () => {
    // The guard against over-counting must not become an under-count: distinct rows carrying
    // distinct values on both sides are two shared indicators.
    const index = buildCrossCaseIndex([
      snapshot("a", [
        ioc({ id: "i1", type: "domain", value: "evil.com" }),
        ioc({ id: "i2", type: "domain", value: "bad.com" }),
      ]),
      snapshot("b", [
        ioc({ id: "i9", type: "domain", value: "evil.com" }),
        ioc({ id: "i8", type: "domain", value: "bad.com" }),
      ]),
    ]);
    const [b] = relatedCases(index, "a");
    expect(b.sharedCount).toBe(2);
    expect(b.shared.map((x) => x.value).sort()).toEqual(["bad.com", "evil.com"]);
  });

  it("does not let a duplicate row double the malicious tally", () => {
    const flagged = (id: string) => malicious({ id, type: "domain", value: "evil.com" });
    const index = buildCrossCaseIndex([
      snapshot("a", [flagged("i1"), flagged("i2")]),
      snapshot("b", [flagged("i9")]),
    ]);
    expect(relatedCases(index, "a")[0].maliciousCount).toBe(1);
  });

  it("reports every shared indicator in the count while listing only the strongest", () => {
    const many = Array.from({ length: 5 }, (_, n) =>
      ioc({ id: `i${n}`, type: "domain", value: `bad${n}.com` }),
    );
    const index = buildCrossCaseIndex([snapshot("a", many), snapshot("b", many)]);
    const [b] = relatedCases(index, "a", { sharedLimit: 2 });
    expect(b.sharedCount).toBe(5);
    expect(b.shared).toHaveLength(2);
  });

  it("caps the number of related cases returned", () => {
    const shared = [ioc({ id: "i1", type: "domain", value: "evil.com" })];
    const index = buildCrossCaseIndex([
      snapshot("a", shared),
      ...Array.from({ length: 4 }, (_, n) => snapshot(`other${n}`, shared)),
    ]);
    expect(relatedCases(index, "a", { limit: 2 })).toHaveLength(2);
  });

  it("drops a link below minScore", () => {
    const index = buildCrossCaseIndex([
      snapshot("a", [ioc({ id: "i1", type: "ip", value: "10.0.0.5" })]),
      snapshot("b", [ioc({ id: "i9", type: "ip", value: "10.0.0.5" })]),
    ]);
    expect(relatedCases(index, "a", { minScore: 1 })).toEqual([]);
  });

  it("carries the other case's lifecycle status so a closed case reads as one", () => {
    const shared = [ioc({ id: "i1", type: "domain", value: "evil.com" })];
    const index = buildCrossCaseIndex([
      snapshot("a", shared),
      snapshot("b", [ioc({ id: "i9", type: "domain", value: "evil.com" })], { status: "archived" }),
    ]);
    expect(relatedCases(index, "a")[0].status).toBe("archived");
  });
});
