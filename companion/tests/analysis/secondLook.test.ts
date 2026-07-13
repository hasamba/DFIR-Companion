import { describe, it, expect } from "vitest";
import {
  extractSignalTokens,
  buildSecondLookRequests,
  resolveSecondLookRequests,
  buildSecondLookPlan,
  summarizeSecondLook,
  deriveWindow,
  type SecondLookRequest,
} from "../../src/analysis/secondLook.js";
import type { ForensicEvent, InvestigationQuestion } from "../../src/analysis/stateTypes.js";
import type { Hypothesis } from "../../src/analysis/hypothesis.js";
import type { IocAnchor } from "../../src/analysis/iocAnchors.js";

function ev(partial: Partial<ForensicEvent> & { id: string }): ForensicEvent {
  return {
    timestamp: "2026-01-02T10:00:00.000Z",
    description: "",
    severity: "Info",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    ...partial,
  };
}

function hyp(partial: Partial<Hypothesis> & { id: string; title: string }): Hypothesis {
  return {
    description: "",
    expectedOutcome: "",
    status: "open",
    relatedTechniques: [],
    relatedEventIds: [],
    relatedIocIds: [],
    assignee: "",
    notes: "",
    source: "synthesis",
    analystTouched: false,
    createdAt: "2026-01-01T00:00:00Z",
    updatedAt: "2026-01-01T00:00:00Z",
    ...partial,
  };
}

describe("extractSignalTokens", () => {
  it("keeps structured identifiers and drops prose stopwords", () => {
    const tokens = extractSignalTokens(
      "an archive .zip written shortly before an outbound transfer to nfs-01 via rsync",
    );
    expect(tokens).toContain("nfs-01");
    expect(tokens).toContain("rsync");
    expect(tokens).toContain(".zip");
    expect(tokens).not.toContain("shortly");
    expect(tokens).not.toContain("outbound");
    expect(tokens).not.toContain("transfer");
  });

  it("captures hosts, domains, ips and paths", () => {
    const tokens = extractSignalTokens("beacon to evil.com 10.0.0.5 from C:/temp/x.exe powershell.exe");
    expect(tokens).toEqual(expect.arrayContaining(["evil.com", "10.0.0.5", "powershell.exe"]));
    expect(tokens.some((t) => t.includes("temp"))).toBe(true);
  });

  it("returns [] for empty input and dedupes", () => {
    expect(extractSignalTokens(undefined)).toEqual([]);
    expect(extractSignalTokens("rsync rsync rsync")).toEqual(["rsync"]);
  });
});

describe("buildSecondLookRequests", () => {
  it("mines open hypotheses (ioc values + tokens), skipping non-open ones", () => {
    const requests = buildSecondLookRequests({
      hypotheses: [
        hyp({ id: "h_a", title: "Data staged before exfil", expectedOutcome: "an archive to nfs-01 via rsync", relatedIocIds: ["i1"], status: "open" }),
        hyp({ id: "h_b", title: "Refuted theory", status: "refuted" }),
      ],
      iocValueById: new Map([["i1", "evil.com"]]),
      window: { from: "2026-01-01T00:00:00Z", to: "2026-01-31T00:00:00Z" },
    });
    expect(requests).toHaveLength(1);
    expect(requests[0].source).toBe("hypothesis");
    expect(requests[0].tag).toBe("[second-look: h1]");
    expect(requests[0].keywords).toEqual(expect.arrayContaining(["evil.com", "nfs-01", "rsync"]));
    expect(requests[0].from).toBe("2026-01-01T00:00:00Z");
  });

  it("mines unknown/partial questions that carry a collect target, with host", () => {
    const questions: InvestigationQuestion[] = [
      { id: "q1", question: "Was there exfil?", status: "unknown", answer: "", pointer: "",
        collect: { host: "FS01.corp.local", artifact: "Windows.EventLogs.Evtx", logSource: "proxy access logs", expectedOutcome: "large POST to megaupload" } },
      { id: "q2", question: "answered one", status: "answered", answer: "yes", pointer: "" },
    ];
    const requests = buildSecondLookRequests({ keyQuestions: questions });
    expect(requests).toHaveLength(1);
    expect(requests[0].source).toBe("question");
    expect(requests[0].host).toBe("fs01");             // shortHost of FS01.corp.local (lowercased)
    expect(requests[0].keywords).toEqual(expect.arrayContaining(["megaupload"]));
  });

  it("turns top connective IOCs into per-value requests", () => {
    const anchors: IocAnchor[] = [
      { value: "10.10.10.10", type: "ip", hosts: ["a", "b"], accounts: [], tools: ["zeek"], malicious: true, suspicious: false, internalConflict: false, score: 12 },
    ];
    const requests = buildSecondLookRequests({ connectiveIocs: anchors });
    expect(requests).toHaveLength(1);
    expect(requests[0].source).toBe("connective-ioc");
    expect(requests[0].keywords).toEqual(["10.10.10.10"]);
  });

  it("honors model requests with their own time window overriding the active one", () => {
    const requests = buildSecondLookRequests({
      window: { from: "2026-01-01T00:00:00Z", to: "2026-01-31T00:00:00Z" },
      modelRequests: [{ host: "DC01", keywords: ["kerberoast", "spn"], reason: "check for kerberoasting", timeWindow: { from: "2026-01-10T00:00:00Z" } }],
    });
    expect(requests).toHaveLength(1);
    expect(requests[0].source).toBe("model");
    expect(requests[0].from).toBe("2026-01-10T00:00:00Z");   // model window wins
    expect(requests[0].to).toBe("2026-01-31T00:00:00Z");     // inherits active upper bound
    expect(requests[0].host).toBe("dc01");
  });

  it("drops keyword-less requests and dedupes identical searches", () => {
    const requests = buildSecondLookRequests({
      hypotheses: [hyp({ id: "h_empty", title: "the and for", expectedOutcome: "with that this" })], // all stopwords → no keywords
      connectiveIocs: [
        { value: "evil.com", type: "domain", hosts: ["a"], accounts: [], tools: ["t"], malicious: true, suspicious: false, internalConflict: false, score: 5 },
        { value: "evil.com", type: "domain", hosts: ["a"], accounts: [], tools: ["t"], malicious: true, suspicious: false, internalConflict: false, score: 5 },
      ],
    });
    // hypothesis produced no keywords → dropped; two identical IOC requests → deduped to one
    expect(requests).toHaveLength(1);
    expect(requests[0].keywords).toEqual(["evil.com"]);
  });
});

describe("resolveSecondLookRequests", () => {
  const req: SecondLookRequest = {
    source: "hypothesis", tag: "[second-look: h1]", label: "h1", keywords: ["rsync", "nfs-01"],
    from: "2026-01-01T00:00:00Z", to: "2026-01-31T00:00:00Z", reason: "staging",
  };

  it("matches ANY keyword across broad fields and separates promotable (not-yet-in-timeline) events", () => {
    const candidates = [
      ev({ id: "s1", description: "rsync -a /data nfs-01:/backup", timestamp: "2026-01-05T00:00:00Z" }),
      ev({ id: "s2", message: "connection to NFS-01 share", timestamp: "2026-01-06T00:00:00Z" }),
      ev({ id: "s3", description: "unrelated login", timestamp: "2026-01-06T00:00:00Z" }),
      ev({ id: "e9", description: "rsync already in timeline", timestamp: "2026-01-04T00:00:00Z" }),
    ];
    const [res] = resolveSecondLookRequests([req], candidates, new Set(["e9"]));
    expect(res.matchedEventIds.sort()).toEqual(["e9", "s1", "s2"]);
    expect(res.promotable.map((e) => e.id).sort()).toEqual(["s1", "s2"]); // e9 excluded (already present)
  });

  it("respects the time window (undated kept) and host restriction", () => {
    const hostReq: SecondLookRequest = { ...req, host: "FS01", keywords: ["exfil"] };
    const candidates = [
      ev({ id: "a", description: "exfil", asset: "FS01.corp", timestamp: "2026-01-10T00:00:00Z" }),
      ev({ id: "b", description: "exfil", asset: "DC01", timestamp: "2026-01-10T00:00:00Z" }),   // wrong host
      ev({ id: "c", description: "exfil", asset: "FS01", timestamp: "2020-01-10T00:00:00Z" }),   // out of window
      ev({ id: "d", description: "exfil", asset: "FS01", timestamp: "not-a-date" }),             // undated → kept
    ];
    const [res] = resolveSecondLookRequests([hostReq], candidates, new Set());
    expect(res.promotable.map((e) => e.id).sort()).toEqual(["a", "d"]);
  });

  it("caps matches per request", () => {
    const candidates = Array.from({ length: 10 }, (_, i) =>
      ev({ id: `s${i}`, description: "rsync", timestamp: `2026-01-05T00:00:0${i}Z` }));
    const [res] = resolveSecondLookRequests([req], candidates, new Set(), { perTerm: 3 });
    expect(res.promotable).toHaveLength(3);
  });
});

describe("buildSecondLookPlan", () => {
  it("dedupes promoted events across requests, unions tags, and enforces the sweep cap", () => {
    const shared = ev({ id: "s1", description: "rsync nfs-01" });
    const resolutions = [
      { request: { source: "hypothesis", tag: "[second-look: h1]", label: "", keywords: ["rsync"], reason: "" } as SecondLookRequest,
        matchedEventIds: ["s1", "s2"], promotable: [shared, ev({ id: "s2" })] },
      { request: { source: "question", tag: "[second-look: q1]", label: "", keywords: ["nfs-01"], reason: "" } as SecondLookRequest,
        matchedEventIds: ["s1", "s3"], promotable: [shared, ev({ id: "s3" })] },
    ];
    const plan = buildSecondLookPlan(resolutions, { sweep: 2 });
    expect(plan.promotions.map((e) => e.id)).toEqual(["s1", "s2"]); // s3 dropped by sweep cap
    expect(plan.tagById["s1"]).toEqual(["[second-look: h1]", "[second-look: q1]"]); // both tags
    expect(plan.truncated).toBe(true);
  });

  it("surfaces zero-match requests as collection leads", () => {
    const resolutions = [
      { request: { source: "model", tag: "[second-look: model1]", label: "", keywords: ["kerberoast"], reason: "check kerberoasting" } as SecondLookRequest,
        matchedEventIds: [], promotable: [] },
    ];
    const plan = buildSecondLookPlan(resolutions);
    expect(plan.promotions).toHaveLength(0);
    expect(plan.leads).toHaveLength(1);
    expect(plan.leads[0].reason).toBe("check kerberoasting");
  });
});

describe("summarizeSecondLook", () => {
  it("summarizes promotions with per-request tallies", () => {
    const plan = buildSecondLookPlan([
      { request: { source: "hypothesis", tag: "[second-look: h2]", label: "", keywords: ["rsync", "nfs-01"], reason: "" } as SecondLookRequest,
        matchedEventIds: ["s1"], promotable: [ev({ id: "s1" }), ev({ id: "s2" })] },
    ]);
    const line = summarizeSecondLook(plan);
    expect(line).toContain("2 raw event(s) promoted");
    expect(line).toContain("h2 (rsync, nfs-01) +2");
  });

  it("reports leads when nothing was promoted", () => {
    const plan = buildSecondLookPlan([
      { request: { source: "model", tag: "[second-look: model1]", label: "", keywords: ["x"], reason: "r" } as SecondLookRequest,
        matchedEventIds: [], promotable: [] },
    ]);
    expect(summarizeSecondLook(plan)).toContain("collection lead");
  });
});

describe("deriveWindow", () => {
  it("returns earliest and latest dated timestamps", () => {
    const w = deriveWindow([
      ev({ id: "a", timestamp: "2026-01-05T00:00:00.000Z" }),
      ev({ id: "b", timestamp: "2026-01-01T00:00:00.000Z" }),
      ev({ id: "c", timestamp: "bad" }),
    ]);
    expect(w.from).toBe("2026-01-01T00:00:00.000Z");
    expect(w.to).toBe("2026-01-05T00:00:00.000Z");
  });

  it("returns {} when nothing is dated", () => {
    expect(deriveWindow([ev({ id: "a", timestamp: "bad" })])).toEqual({});
  });
});
