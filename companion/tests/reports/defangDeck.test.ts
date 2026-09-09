import { describe, expect, it } from "vitest";
import { defangDeck } from "../../src/reports/defangDeck.js";
import type { PresentationDeck, PresentationSlide } from "../../src/analysis/presentation.js";

// The standalone presentation export is a deliverable in the same sense the report is: it is served
// as an attachment so it can be handed to a stakeholder, and the saved file opens from file:// with
// no CSP. This pass makes its indicators inert; the LIVE viewer renders the same deck undefanged,
// which is why the pass sits at the export boundary and not in buildPresentationDeck. #892.

const deck = (over: Partial<PresentationDeck> = {}): PresentationDeck => ({
  caseId: "c1",
  caseName: "Case",
  generatedAt: "2026-06-01T00:00:00.000Z",
  minSeverity: null,
  branding: { title: "T", subtitle: "S", accentColor: "#000000", companyName: "Acme" },
  slides: [],
  slideCount: 0,
  ...over,
});

// Every string left in the deck carrying a live `http://` after the pass, as dotted paths. The pass
// is deliberately partial — defangSlide rewrites prose and IOC values and knowingly leaves the rest
// — so the tripwire is the SET of survivors, not the absence of one.
function liveUrlPaths(value: unknown, path = ""): string[] {
  if (typeof value === "string") return value.includes("http://") ? [path] : [];
  if (Array.isArray(value)) return value.flatMap((v, i) => liveUrlPaths(v, `${path}.${i}`));
  if (value && typeof value === "object") {
    return Object.entries(value).flatMap(([k, v]) => liveUrlPaths(v, path ? `${path}.${k}` : k));
  }
  return [];
}

describe("defangDeck (#892)", () => {
  it("defangs IOC values, which are the deck's only raw indicator field", () => {
    const out = defangDeck(
      deck({
        slides: [
          {
            kind: "event",
            title: "Beacon",
            iocs: [
              { value: "http://evil.example/c2", type: "url", verdict: "malicious" },
              { value: "203.0.113.10", type: "ip", verdict: null },
            ],
          },
        ],
      }),
    );

    expect(out.slides[0].iocs?.map((i) => i.value)).toEqual([
      "hxxp://evil[.]example/c2",
      "203[.]0[.]113[.]10",
    ]);
  });

  it("keeps the IOC type and verdict, so the slide still badges the indicator correctly", () => {
    const out = defangDeck(
      deck({
        slides: [
          { kind: "event", title: "T", iocs: [{ value: "203.0.113.10", type: "ip", verdict: "malicious" }] },
        ],
      }),
    );

    expect(out.slides[0].iocs?.[0]).toMatchObject({ type: "ip", verdict: "malicious" });
  });

  it("defangs slide prose — title, body and description", () => {
    const out = defangDeck(
      deck({
        slides: [
          { kind: "summary", title: "C2 at http://evil.example", body: "Beaconed to 203.0.113.10 hourly" },
          { kind: "event", title: "Drop", description: "wget http://evil.example/x from a@b.example" },
        ],
      }),
    );

    expect(out.slides[0].title).toBe("C2 at hxxp://evil[.]example");
    expect(out.slides[0].body).toBe("Beaconed to 203[.]0[.]113[.]10 hourly");
    expect(out.slides[1].description).toBe("wget hxxp://evil[.]example/x from a[@]b[.]example");
  });

  it("uses the deck's own domain IOCs to defang bare hostnames without guessing at filenames", () => {
    const out = defangDeck(
      deck({
        slides: [
          {
            kind: "event",
            title: "T",
            description: "callback to evil.test, wrote History.db",
            iocs: [{ value: "evil.test", type: "domain", verdict: null }],
          },
        ],
      }),
    );

    expect(out.slides[0].description).toBe("callback to evil[.]test, wrote History.db");
  });

  it("pools the domain IOCs across slides, so one slide's indicator defangs another's prose", () => {
    const out = defangDeck(
      deck({
        slides: [
          { kind: "summary", title: "Summary", body: "Beaconing to evil.test all week" },
          { kind: "event", title: "Callback", iocs: [{ value: "evil.test", type: "domain", verdict: null }] },
        ],
      }),
    );

    expect(out.slides[0].body).toBe("Beaconing to evil[.]test all week");
  });

  it("defangs clickable forms even when the deck names no domain IOC at all", () => {
    // The pool only ever governs BARE hostnames. URLs, IPv4 addresses and email addresses — the
    // forms a reader can actually act on — are rendered inert whatever the pool holds.
    const out = defangDeck(
      deck({
        slides: [
          { kind: "event", title: "T", description: "http://evil.example/x, 203.0.113.10, a@b.example" },
        ],
      }),
    );

    expect(out.slides[0].description).toBe("hxxp://evil[.]example/x, 203[.]0[.]113[.]10, a[@]b[.]example");
  });

  it("leaves absent optional fields absent rather than stamping undefined onto the slide", () => {
    const out = defangDeck(deck({ slides: [{ kind: "section", title: "Lateral Movement" }] }));

    expect(out.slides[0]).toEqual({ kind: "section", title: "Lateral Movement" });
  });

  it("is idempotent — re-exporting the same case is stable", () => {
    const once = defangDeck(
      deck({
        slides: [{ kind: "event", title: "T", description: "http://evil.example/x and 203.0.113.10" }],
      }),
    );

    expect(defangDeck(once)).toEqual(once);
  });

  // #901. defangSlide rewrites title, body, description and IOC values, and knowingly leaves the rest
  // alone: asset and sources are host/source names, screenshot is a filename the builder resolves,
  // and branding/caseName are case metadata an analyst controls. Nothing reaching those can carry a
  // live indicator today — but that is a claim about the BUILDER, re-derived by hand every time a
  // slide field is added. This pins it instead, in both directions. The fixture is typed
  // Required<PresentationSlide>, so a new field on the interface fails typecheck until it is poisoned
  // here; the path assertion then fails until it is classified as rewritten or knowingly exempt.
  it("pins which fields survive the pass, so a new slide field cannot smuggle a live URL into the export", () => {
    const poisoned: Required<PresentationSlide> = {
      kind: "event",
      title: "C2 at http://evil.example/title",
      branding: {
        title: "http://evil.example/slide-brand-title",
        subtitle: "http://evil.example/slide-brand-subtitle",
        accentColor: "#000000", // hex-validated, never free text
        companyName: "http://evil.example/slide-brand-company",
      },
      counts: { findings: 1, events: 1, iocs: 1 },
      severityCounts: { Critical: 1, High: 0, Medium: 0, Low: 0, Info: 0 },
      body: "beaconed to http://evil.example/body",
      severity: "High",
      // ISO stamps, enums and technique ids are format-constrained, so they are not poisoned.
      timestamp: "2026-06-01T00:00:00.000Z",
      endTimestamp: "2026-06-01T01:00:00.000Z",
      description: "wget http://evil.example/description",
      asset: "http://evil.example/asset",
      sources: ["http://evil.example/source"],
      mitreTechniques: ["T1071"],
      iocs: [{ value: "http://evil.example/ioc", type: "url", verdict: "malicious" }],
      screenshot: "http://evil.example/shot.png",
      confidence: 0.9,
      count: 2,
    };

    const out = defangDeck(
      deck({
        caseName: "http://evil.example/case-name",
        branding: {
          title: "http://evil.example/deck-brand-title",
          subtitle: "http://evil.example/deck-brand-subtitle",
          accentColor: "#000000",
          companyName: "http://evil.example/deck-brand-company",
        },
        slides: [poisoned],
        slideCount: 1,
      }),
    );

    // Everything the pass claims to rewrite loses the clickable scheme.
    expect(out.slides[0].title).toBe("C2 at hxxp://evil[.]example/title");
    expect(out.slides[0].body).toBe("beaconed to hxxp://evil[.]example/body");
    expect(out.slides[0].description).toBe("wget hxxp://evil[.]example/description");
    expect(out.slides[0].iocs?.[0].value).toBe("hxxp://evil[.]example/ioc");

    // ...and exactly these survive, every one of them inert at render (safe-dom text nodes, no
    // autolinker). A field added later shows up here as an unclassified path.
    expect(liveUrlPaths(out).sort()).toEqual([
      "branding.companyName",
      "branding.subtitle",
      "branding.title",
      "caseName",
      "slides.0.asset",
      "slides.0.branding.companyName",
      "slides.0.branding.subtitle",
      "slides.0.branding.title",
      "slides.0.screenshot",
      "slides.0.sources.0",
    ]);
  });
});
