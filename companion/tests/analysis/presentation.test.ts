import { describe, it, expect } from "vitest";
import {
  buildPresentationDeck,
  presentationEnvOptions,
  worstVerdict,
  type PresentationBranding,
  type PresentationOptions,
} from "../../src/analysis/presentation.js";
import {
  emptyState,
  type Finding,
  type ForensicEvent,
  type IOC,
  type InvestigationState,
  type IocEnrichment,
} from "../../src/analysis/stateTypes.js";

const branding: PresentationBranding = {
  title: "Incident Investigation",
  subtitle: "Acme Corp",
  accentColor: "#2d6cdf",
  companyName: "Contoso DFIR",
};

const baseOpts = (over: Partial<PresentationOptions> = {}): PresentationOptions => ({ branding, ...over });

const finding = (over: Partial<Finding> & Pick<Finding, "id" | "severity">): Finding => ({
  title: "t", description: "d", relatedIocs: [], sourceScreenshots: [], mitreTechniques: [],
  firstSeen: "2026-01-01T00:00:00Z", lastUpdated: "2026-01-01T00:00:00Z", status: "open", ...over,
});

const ev = (over: Partial<ForensicEvent> & Pick<ForensicEvent, "id" | "severity">): ForensicEvent => ({
  timestamp: "2026-01-01T00:00:00Z", description: "happened", mitreTechniques: [],
  relatedFindingIds: [], sourceScreenshots: [], ...over,
});

const enrich = (verdict: IocEnrichment["verdict"]): IocEnrichment => ({
  source: "VirusTotal", verdict, fetchedAt: "2026-01-01T00:00:00Z",
});

const ioc = (over: Partial<IOC> & Pick<IOC, "id" | "type" | "value">): IOC => ({
  firstSeen: "2026-01-01T00:00:00Z", ...over,
});

function stateWith(over: Partial<InvestigationState>): InvestigationState {
  return { ...emptyState("CASE-1"), ...over };
}

describe("worstVerdict", () => {
  it("returns null when never enriched and the worst across engines otherwise", () => {
    expect(worstVerdict({ enrichments: [] })).toBeNull();
    expect(worstVerdict({ enrichments: [enrich("harmless"), enrich("malicious")] })).toBe("malicious");
  });
});

describe("buildPresentationDeck", () => {
  it("emits a single title slide for an empty case", () => {
    const deck = buildPresentationDeck(emptyState("CASE-EMPTY"), baseOpts());
    expect(deck.caseId).toBe("CASE-EMPTY");
    expect(deck.slides).toHaveLength(1);
    const title = deck.slides[0];
    expect(title.kind).toBe("title");
    expect(title.counts).toEqual({ findings: 0, events: 0, iocs: 0 });
    expect(title.branding).toEqual(branding);
  });

  it("falls back to the caseId when no caseName/branding title is given", () => {
    const deck = buildPresentationDeck(emptyState("CASE-EMPTY"), baseOpts({ branding: { ...branding, title: "  " } }));
    expect(deck.caseName).toBe("CASE-EMPTY");
    expect(deck.slides[0].title).toBe("CASE-EMPTY");
  });

  it("stamps generatedAt and minSeverity from the options", () => {
    const deck = buildPresentationDeck(emptyState("C"), baseOpts({ generatedAt: "2026-06-29T00:00:00Z", minSeverity: "High" }));
    expect(deck.generatedAt).toBe("2026-06-29T00:00:00Z");
    expect(deck.minSeverity).toBe("High");
  });

  it("builds summary / narrative / attacker-path slides only when present", () => {
    const deck = buildPresentationDeck(
      stateWith({ lastSummary: "exec summary", narrativeTimeline: "the story", attackerPath: "phish → C2" }),
      baseOpts(),
    );
    const summaries = deck.slides.filter((s) => s.kind === "summary");
    expect(summaries.map((s) => s.title)).toEqual(["Summary", "Incident narrative", "Attacker path"]);
    expect(summaries[0].body).toBe("exec summary");
  });

  it("orders findings worst-first under a Key findings section", () => {
    const deck = buildPresentationDeck(
      stateWith({
        findings: [
          finding({ id: "f1", severity: "Low", title: "low one" }),
          finding({ id: "f2", severity: "Critical", title: "crit one" }),
          finding({ id: "f3", severity: "Medium", title: "med one" }),
        ],
      }),
      baseOpts(),
    );
    const findingSlides = deck.slides.filter((s) => s.kind === "finding");
    expect(findingSlides.map((s) => s.title)).toEqual(["crit one", "med one", "low one"]);
    // a "Key findings" section divider precedes them
    expect(deck.slides.some((s) => s.kind === "section" && s.title === "Key findings")).toBe(true);
  });

  it("orders events chronologically (undated last) under a Timeline section", () => {
    const deck = buildPresentationDeck(
      stateWith({
        forensicTimeline: [
          ev({ id: "e1", severity: "High", description: "second", timestamp: "2026-01-02T00:00:00Z" }),
          ev({ id: "e2", severity: "High", description: "first", timestamp: "2026-01-01T00:00:00Z" }),
          ev({ id: "e3", severity: "High", description: "undated", timestamp: "" }),
        ],
      }),
      baseOpts(),
    );
    const eventSlides = deck.slides.filter((s) => s.kind === "event");
    expect(eventSlides.map((s) => s.description)).toEqual(["first", "second", "undated"]);
  });

  it("applies the severity floor to findings and events", () => {
    const deck = buildPresentationDeck(
      stateWith({
        findings: [finding({ id: "f1", severity: "Critical" }), finding({ id: "f2", severity: "Low" })],
        forensicTimeline: [ev({ id: "e1", severity: "High" }), ev({ id: "e2", severity: "Info" })],
      }),
      baseOpts({ minSeverity: "High" }),
    );
    expect(deck.slides.filter((s) => s.kind === "finding")).toHaveLength(1);
    expect(deck.slides.filter((s) => s.kind === "event")).toHaveLength(1);
    const title = deck.slides[0];
    expect(title.counts).toEqual({ findings: 1, events: 1, iocs: 0 });
  });

  it("treats an Info floor as no floor", () => {
    const deck = buildPresentationDeck(
      stateWith({ forensicTimeline: [ev({ id: "e1", severity: "Info" }), ev({ id: "e2", severity: "Low" })] }),
      baseOpts({ minSeverity: "Info" }),
    );
    expect(deck.minSeverity).toBeNull();
    expect(deck.slides.filter((s) => s.kind === "event")).toHaveLength(2);
  });

  it("resolves an event's supporting IOCs by exact-token match (boundary-aware), worst-first, capped", () => {
    const deck = buildPresentationDeck(
      stateWith({
        forensicTimeline: [
          ev({ id: "e1", severity: "High", description: "beacon to 10.0.0.1 and evil.com", srcIp: "10.0.0.1" }),
        ],
        iocs: [
          ioc({ id: "i1", type: "ip", value: "10.0.0.1", enrichments: [enrich("suspicious")] }),
          ioc({ id: "i2", type: "domain", value: "evil.com", enrichments: [enrich("malicious")] }),
          ioc({ id: "i3", type: "ip", value: "10.0.0.10" }), // must NOT match inside 10.0.0.1
        ],
      }),
      baseOpts({ maxIocsPerSlide: 5 }),
    );
    const event = deck.slides.find((s) => s.kind === "event");
    expect(event?.iocs?.map((i) => i.value)).toEqual(["evil.com", "10.0.0.1"]); // malicious before suspicious
  });

  it("resolves a finding's IOCs from relatedIocs", () => {
    const deck = buildPresentationDeck(
      stateWith({
        findings: [finding({ id: "f1", severity: "High", relatedIocs: ["i1", "missing"] })],
        iocs: [ioc({ id: "i1", type: "hash", value: "abc123" })],
      }),
      baseOpts(),
    );
    const f = deck.slides.find((s) => s.kind === "finding");
    expect(f?.iocs?.map((i) => i.value)).toEqual(["abc123"]);
  });

  it("caps findings and events", () => {
    const deck = buildPresentationDeck(
      stateWith({
        findings: [finding({ id: "f1", severity: "High" }), finding({ id: "f2", severity: "High" })],
        forensicTimeline: [ev({ id: "e1", severity: "High" }), ev({ id: "e2", severity: "High" }), ev({ id: "e3", severity: "High" })],
      }),
      baseOpts({ maxFindings: 1, maxEvents: 2 }),
    );
    expect(deck.slides.filter((s) => s.kind === "finding")).toHaveLength(1);
    expect(deck.slides.filter((s) => s.kind === "event")).toHaveLength(2);
  });

  it("does not mutate the input state arrays", () => {
    const state = stateWith({
      findings: [finding({ id: "f1", severity: "Low" }), finding({ id: "f2", severity: "Critical" })],
    });
    const before = state.findings.map((f) => f.id);
    buildPresentationDeck(state, baseOpts());
    expect(state.findings.map((f) => f.id)).toEqual(before);
  });
});

describe("presentationEnvOptions", () => {
  it("uses defaults when env is unset", () => {
    delete process.env.DFIR_PRESENT_MAX_FINDINGS;
    delete process.env.DFIR_PRESENT_MAX_EVENTS;
    expect(presentationEnvOptions()).toEqual({ maxFindings: 40, maxEvents: 200 });
  });

  it("reads valid env overrides and ignores invalid ones", () => {
    process.env.DFIR_PRESENT_MAX_FINDINGS = "10";
    process.env.DFIR_PRESENT_MAX_EVENTS = "not-a-number";
    expect(presentationEnvOptions()).toEqual({ maxFindings: 10, maxEvents: 200 });
    delete process.env.DFIR_PRESENT_MAX_FINDINGS;
    delete process.env.DFIR_PRESENT_MAX_EVENTS;
  });
});
