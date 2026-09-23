import { describe, it, expect } from "vitest";
import {
  extractSignalTokens,
  buildSecondLookRequests,
  resolveSecondLookRequests,
  buildSecondLookPlan,
  summarizeSecondLook,
  deriveWindow,
  type SecondLookRequest,
  type SecondLookResolution,
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
    contradictingEventIds: [],
    discriminator: "",
    exhausted: false,
    exhaustedReason: "",
    needsReview: false,
    reviewReason: "",
    alternativeIds: [],
    excludedEvidence: [],
    assignee: "",
    notes: "",
    source: "synthesis",
    analystTouched: false,
    createdAt: "2026-01-01T00:00:00Z",
    updatedAt: "2026-01-01T00:00:00Z",
    statusHistory: [],
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
        hyp({
          id: "h_a",
          title: "Data staged before exfil",
          expectedOutcome: "an archive to nfs-01 via rsync",
          relatedIocIds: ["i1"],
          status: "open",
        }),
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
      {
        id: "q1",
        question: "Was there exfil?",
        status: "unknown",
        answer: "",
        pointer: "",
        collect: {
          host: "FS01.corp.local",
          artifact: "Windows.EventLogs.Evtx",
          logSource: "proxy access logs",
          expectedOutcome: "large POST to megaupload",
        },
      },
      { id: "q2", question: "answered one", status: "answered", answer: "yes", pointer: "" },
    ];
    const requests = buildSecondLookRequests({ keyQuestions: questions });
    expect(requests).toHaveLength(1);
    expect(requests[0].source).toBe("question");
    expect(requests[0].host).toBe("fs01"); // shortHost of FS01.corp.local (lowercased)
    expect(requests[0].keywords).toEqual(expect.arrayContaining(["megaupload"]));
  });

  it("turns top connective IOCs into per-value requests", () => {
    const anchors: IocAnchor[] = [
      {
        value: "10.10.10.10",
        type: "ip",
        hosts: ["a", "b"],
        accounts: [],
        tools: ["zeek"],
        malicious: true,
        suspicious: false,
        internalConflict: false,
        score: 12,
      },
    ];
    const requests = buildSecondLookRequests({ connectiveIocs: anchors });
    expect(requests).toHaveLength(1);
    expect(requests[0].source).toBe("connective-ioc");
    expect(requests[0].keywords).toEqual(["10.10.10.10"]);
  });

  it("honors model requests with their own time window overriding the active one", () => {
    const requests = buildSecondLookRequests({
      window: { from: "2026-01-01T00:00:00Z", to: "2026-01-31T00:00:00Z" },
      modelRequests: [
        {
          host: "DC01",
          keywords: ["kerberoast", "spn"],
          reason: "check for kerberoasting",
          timeWindow: { from: "2026-01-10T00:00:00Z" },
        },
      ],
    });
    expect(requests).toHaveLength(1);
    expect(requests[0].source).toBe("model");
    expect(requests[0].from).toBe("2026-01-10T00:00:00Z"); // model window wins
    expect(requests[0].to).toBe("2026-01-31T00:00:00Z"); // inherits active upper bound
    expect(requests[0].host).toBe("dc01");
  });

  it("drops keyword-less requests and dedupes identical searches", () => {
    const requests = buildSecondLookRequests({
      hypotheses: [hyp({ id: "h_empty", title: "the and for", expectedOutcome: "with that this" })], // all stopwords → no keywords
      connectiveIocs: [
        {
          value: "evil.com",
          type: "domain",
          hosts: ["a"],
          accounts: [],
          tools: ["t"],
          malicious: true,
          suspicious: false,
          internalConflict: false,
          score: 5,
        },
        {
          value: "evil.com",
          type: "domain",
          hosts: ["a"],
          accounts: [],
          tools: ["t"],
          malicious: true,
          suspicious: false,
          internalConflict: false,
          score: 5,
        },
      ],
    });
    // hypothesis produced no keywords → dropped; two identical IOC requests → deduped to one
    expect(requests).toHaveLength(1);
    expect(requests[0].keywords).toEqual(["evil.com"]);
  });
});

describe("resolveSecondLookRequests", () => {
  const req: SecondLookRequest = {
    source: "hypothesis",
    tag: "[second-look: h1]",
    label: "h1",
    keywords: ["rsync", "nfs-01"],
    from: "2026-01-01T00:00:00Z",
    to: "2026-01-31T00:00:00Z",
    reason: "staging",
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
      ev({ id: "b", description: "exfil", asset: "DC01", timestamp: "2026-01-10T00:00:00Z" }), // wrong host
      ev({ id: "c", description: "exfil", asset: "FS01", timestamp: "2020-01-10T00:00:00Z" }), // out of window
      ev({ id: "d", description: "exfil", asset: "FS01", timestamp: "not-a-date" }), // undated → kept
    ];
    const [res] = resolveSecondLookRequests([hostReq], candidates, new Set());
    expect(res.promotable.map((e) => e.id).sort()).toEqual(["a", "d"]);
  });

  it("caps matches per request", () => {
    const candidates = Array.from({ length: 10 }, (_, i) =>
      ev({ id: `s${i}`, description: "rsync", timestamp: `2026-01-05T00:00:0${i}Z` }),
    );
    const [res] = resolveSecondLookRequests([req], candidates, new Set(), { perTerm: 3 });
    expect(res.promotable).toHaveLength(3);
  });
});

describe("buildSecondLookPlan", () => {
  it("dedupes promoted events across requests, unions tags, and enforces the sweep cap", () => {
    const shared = ev({ id: "s1", description: "rsync nfs-01" });
    const resolutions = [
      {
        request: {
          source: "hypothesis",
          tag: "[second-look: h1]",
          label: "",
          keywords: ["rsync"],
          reason: "",
        } as SecondLookRequest,
        matchedEventIds: ["s1", "s2"],
        promotable: [shared, ev({ id: "s2" })],
      },
      {
        request: {
          source: "question",
          tag: "[second-look: q1]",
          label: "",
          keywords: ["nfs-01"],
          reason: "",
        } as SecondLookRequest,
        matchedEventIds: ["s1", "s3"],
        promotable: [shared, ev({ id: "s3" })],
      },
    ];
    const plan = buildSecondLookPlan(resolutions, { sweep: 2 });
    expect(plan.promotions.map((e) => e.id)).toEqual(["s1", "s2"]); // s3 dropped by sweep cap
    expect(plan.tagById["s1"]).toEqual(["[second-look: h1]", "[second-look: q1]"]); // both tags
    expect(plan.truncated).toBe(true);
  });

  it("surfaces zero-match requests as collection leads", () => {
    const resolutions = [
      {
        request: {
          source: "model",
          tag: "[second-look: model1]",
          label: "",
          keywords: ["kerberoast"],
          reason: "check kerberoasting",
        } as SecondLookRequest,
        matchedEventIds: [],
        promotable: [],
      },
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
      {
        request: {
          source: "hypothesis",
          tag: "[second-look: h2]",
          label: "",
          keywords: ["rsync", "nfs-01"],
          reason: "",
        },
        matchedEventIds: ["s1"],
        promotable: [ev({ id: "s1" }), ev({ id: "s2" })],
      },
    ]);
    const line = summarizeSecondLook(plan);
    expect(line).toContain("2 raw event(s) promoted");
    expect(line).toContain("h2 (rsync, nfs-01) +2");
  });

  it("reports leads when nothing was promoted", () => {
    const plan = buildSecondLookPlan([
      {
        request: { source: "model", tag: "[second-look: model1]", label: "", keywords: ["x"], reason: "r" },
        matchedEventIds: [],
        promotable: [],
      },
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

// ── #1554 fix A: the per-request allowance is spent on rows the AI has NOT already seen ──────────
describe("resolveSecondLookRequests — the allowance buys unseen rows", () => {
  const req: SecondLookRequest = {
    source: "question",
    tag: "[second-look: q1]",
    label: "q1",
    keywords: ["powershell"],
    reason: "how did they run code?",
  };

  // Measured on a real case: 35% of archive rows are already in the forensic timeline, and three of
  // six open questions promoted ZERO rows because their earliest 50 matches were all already
  // analysed. Filling the allowance from the promotable rows is the whole fix.
  it("skips already-analysed matches instead of spending the allowance on them", () => {
    const candidates = [
      ev({ id: "a1", description: "powershell one", timestamp: "2026-01-01T00:00:01Z" }),
      ev({ id: "a2", description: "powershell two", timestamp: "2026-01-01T00:00:02Z" }),
      ev({ id: "a3", description: "powershell three", timestamp: "2026-01-01T00:00:03Z" }),
      ev({ id: "s1", description: "powershell four", timestamp: "2026-01-01T00:00:04Z" }),
      ev({ id: "s2", description: "powershell five", timestamp: "2026-01-01T00:00:05Z" }),
    ];
    const analysed = new Set(["a1", "a2", "a3"]);
    const [res] = resolveSecondLookRequests([req], candidates, analysed, { perTerm: 3 });
    expect(res.promotable.map((e) => e.id)).toEqual(["s1", "s2"]);
  });

  // The trap: matchedEventIds.length === 0 is the SOLE lead trigger. A request whose every hit is
  // already analysed FOUND its evidence — it is satisfied, not a blind spot.
  it("keeps a request whose every match is already analysed out of the leads", () => {
    const candidates = [
      ev({ id: "a1", description: "powershell one", timestamp: "2026-01-01T00:00:01Z" }),
      ev({ id: "a2", description: "powershell two", timestamp: "2026-01-01T00:00:02Z" }),
    ];
    const resolutions = resolveSecondLookRequests([req], candidates, new Set(["a1", "a2"]), { perTerm: 3 });
    expect(resolutions[0].promotable).toHaveLength(0);
    expect(resolutions[0].matchedEventIds.length).toBeGreaterThan(0);
    expect(buildSecondLookPlan(resolutions).leads).toHaveLength(0);
  });

  it("still records a request that matched nothing anywhere as a collection lead", () => {
    const candidates = [ev({ id: "x1", description: "unrelated", timestamp: "2026-01-01T00:00:01Z" })];
    const resolutions = resolveSecondLookRequests([req], candidates, new Set());
    expect(resolutions[0].matchedEventIds).toEqual([]);
    expect(buildSecondLookPlan(resolutions).leads).toHaveLength(1);
  });

  it("bounds matchedEventIds when the whole archive is already analysed", () => {
    const candidates = Array.from({ length: 400 }, (_, i) =>
      ev({
        id: `a${i}`,
        description: "powershell",
        timestamp: `2026-01-01T00:00:00.${String(i).padStart(3, "0")}Z`,
      }),
    );
    const analysed = new Set(candidates.map((e) => e.id));
    const [res] = resolveSecondLookRequests([req], candidates, analysed, { perTerm: 3 });
    expect(res.matchedEventIds).toHaveLength(3);
  });
});

describe("buildSecondLookPlan — round-robin coverage", () => {
  function resolution(tag: string, ids: string[], description = ""): SecondLookResolution {
    return {
      request: { source: "question", tag, label: tag, keywords: ["k"], reason: tag },
      matchedEventIds: ids,
      promotable: ids.map((id) => ev({ id, description })),
    };
  }

  // Before this, the first request to claim the budget took it all — and the model's own "I was not
  // shown this" requests are built LAST, so they starved first.
  it("gives every request a turn before any request gets a second row", () => {
    const plan = buildSecondLookPlan(
      [
        resolution("[second-look: q1]", ["q1a", "q1b", "q1c"]),
        resolution("[second-look: q2]", ["q2a", "q2b", "q2c"]),
        resolution("[second-look: model1]", ["m1a", "m1b", "m1c"]),
      ],
      { sweep: 3 },
    );
    expect(plan.promotions.map((e) => e.id)).toEqual(["q1a", "q2a", "m1a"]);
    expect(plan.truncated).toBe(true);
  });

  it("spends every request's whole allowance when the sweep budget allows", () => {
    const plan = buildSecondLookPlan([
      resolution("[second-look: q1]", ["q1a", "q1b"]),
      resolution("[second-look: model1]", ["m1a", "m1b"]),
    ]);
    expect(plan.promotions.map((e) => e.id)).toEqual(["q1a", "m1a", "q1b", "m1b"]);
    expect(plan.truncated).toBe(false);
  });
});

// ── #1554 fix B: 40% of what the sweep promoted was near-duplicate ───────────────────────────────
describe("buildSecondLookPlan — per-shape cap", () => {
  const SIGMA =
    "Velociraptor [Windows.Sigma.Base] Sigma: Potentially Malicious PwSh - Windows PowerShell Script block logged";
  const DETECTRAPTOR = "DetectRaptor Evtx detection: Powershell Suspicious CommandLet — IN DEVELOPMENT";
  const CHAINSAW =
    "[Windows.EventLogs.Chainsaw] Chainsaw/PowerShell Script: PowerShell - Script Block Auditing";

  function one(tag: string, events: ForensicEvent[]): SecondLookResolution {
    return {
      request: { source: "question", tag, label: tag, keywords: ["k"], reason: tag },
      matchedEventIds: events.map((e) => e.id),
      promotable: events,
    };
  }

  it("promotes only a few rows of one normalised shape, whatever the digits inside them", () => {
    const rows = Array.from({ length: 10 }, (_, i) =>
      ev({ id: `r${i}`, description: `${SIGMA} (EventID 4104, record ${1000 + i})`, asset: "ws-01" }),
    );
    const plan = buildSecondLookPlan([one("[second-look: q1]", rows)], { perShape: 3 });
    expect(plan.promotions).toHaveLength(3);
    expect(plan.shapeCapped).toBe(7);
  });

  it("keeps the three real repeat shapes apart", () => {
    const rows = [SIGMA, DETECTRAPTOR, CHAINSAW].flatMap((shape, s) =>
      Array.from({ length: 5 }, (_, i) =>
        ev({ id: `r${s}_${i}`, description: `${shape} (record ${100 + i})`, asset: "ws-01" }),
      ),
    );
    const plan = buildSecondLookPlan([one("[second-look: q1]", rows)], { perShape: 2 });
    expect(plan.promotions).toHaveLength(6); // 2 per distinct shape, not 2 overall
    expect(plan.shapeCapped).toBe(9);
  });

  it("counts a shape per host, so the same detection on a second host is not crowded out", () => {
    const rows = ["ws-01", "ws-02"].flatMap((asset) =>
      Array.from({ length: 4 }, (_, i) =>
        ev({ id: `${asset}_${i}`, description: `${SIGMA} (record ${i})`, asset }),
      ),
    );
    const plan = buildSecondLookPlan([one("[second-look: q1]", rows)], { perShape: 2 });
    expect(plan.promotions.map((e) => e.asset)).toEqual(["ws-01", "ws-01", "ws-02", "ws-02"]);
  });

  it("never caps a row that has no stable shape", () => {
    const rows = Array.from({ length: 6 }, (_, i) => ev({ id: `n${i}`, description: "" }));
    const plan = buildSecondLookPlan([one("[second-look: q1]", rows)], { perShape: 2 });
    expect(plan.promotions).toHaveLength(6);
    expect(plan.shapeCapped).toBe(0);
  });

  it("frees the budget for a starved request instead of repeating one detection", () => {
    const repeats = Array.from({ length: 6 }, (_, i) =>
      ev({ id: `rep${i}`, description: `${SIGMA} (record ${i})`, asset: "ws-01" }),
    );
    const distinct = [ev({ id: "d1", description: "schtasks /create /tn updater", asset: "ws-01" })];
    const plan = buildSecondLookPlan(
      [one("[second-look: q1]", repeats), one("[second-look: model1]", distinct)],
      { sweep: 4, perShape: 2 },
    );
    expect(plan.promotions.map((e) => e.id)).toContain("d1");
  });

  it("tells the analyst in the summary how many repeat rows were held back", () => {
    const rows = Array.from({ length: 5 }, (_, i) =>
      ev({ id: `r${i}`, description: `${SIGMA} (record ${i})`, asset: "ws-01" }),
    );
    const line = summarizeSecondLook(buildSecondLookPlan([one("[second-look: q1]", rows)], { perShape: 2 }));
    expect(line).toContain("3 repeat row(s)");
    expect(line).toContain("super-timeline");
  });
});
