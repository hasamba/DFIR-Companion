import { describe, expect, it } from "vitest";
import { defangDeck } from "../../src/reports/defangDeck.js";
import type { PresentationDeck } from "../../src/analysis/presentation.js";

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
});
