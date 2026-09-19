import { describe, it, expect } from "vitest";
import { parseMacos } from "../../src/analysis/macosImport.js";
import { parseHindsight } from "../../src/analysis/hindsightImport.js";
import {
  linkQuarantineVisitOrigin,
  ORIGIN_VISITED_MARKER,
  DATA_URL_VISITED_MARKER,
  PRECEDED_QUARANTINE_MARKER,
} from "../../src/analysis/quarantineVisitOrigin.js";
import { mergeDelta } from "../../src/analysis/stateMerge.js";
import { emptyState, type ForensicEvent } from "../../src/analysis/stateTypes.js";
import type { AnalysisDelta } from "../../src/analysis/responseSchema.js";

// #1037 link 3: the quarantine record's origin page (and the download URL itself) against the
// browser-history visits that PRECEDE the record — joined by URL equality alone, never a host, a
// basename or a time. A visit before the record says the browser reached the page before the
// download event was logged; it never says the visit caused the download.

const UUID = "8f1c2d3e-4a5b-6c7d-8e9f-0a1b2c3d4e5f";
const COCOA = 619336364; // 2020-08-17T05:52:44Z
const ORIGIN = "https://lure.example.invalid/promo";
const DATA = "https://cdn.example.invalid/installer.dmg";

type Ev = ForensicEvent;
const asForensic = (
  e: { description: string; timestamp: string; severity: string; sources?: string[] },
  id: string,
  over: Partial<Ev> = {},
): Ev =>
  ({ ...e, id, mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [], ...over }) as unknown as Ev;

const dbRow = (over: Record<string, unknown> = {}, host?: string): Ev => {
  const rec = {
    LSQuarantineEventIdentifier: UUID,
    LSQuarantineTimeStamp: COCOA,
    LSQuarantineAgentName: "Safari",
    LSQuarantineDataURLString: DATA,
    LSQuarantineOriginURLString: ORIGIN,
    ...(host ? { hostname: host } : {}),
    ...over,
  };
  const e = parseMacos(JSON.stringify([rec]), { aggregate: false }).events.find((x) =>
    x.description.startsWith("macOS quarantine ["),
  )!;
  return asForensic(e, "db1");
};

/** A Velociraptor browser-history "Visited" row, as velociraptorImport.ts's mapBrowserHistory writes it. */
const veloVisit = (url: string, iso: string, id: string, asset?: string): Ev =>
  asForensic(
    {
      description: `Velociraptor [Chrome.History]: Visited: "Promo" — ${url}`,
      timestamp: iso,
      severity: "Info",
      sources: ["Velociraptor"],
    },
    id,
    asset ? { asset } : {},
  );

/** A Hindsight visit row, as hindsightImport.ts writes it. */
const hindsightVisit = (url: string, iso: string, id: string): Ev => {
  const e = parseHindsight(JSON.stringify([{ type: "url", timestamp: iso, url, title: "Promo" }]), {
    aggregate: false,
  }).events[0];
  return asForensic(e, id);
};

const BEFORE = "2020-08-17T05:50:00Z";
const AFTER = "2020-08-17T05:55:00Z";

describe("quarantine record ↔ browser visit (#1037 link 3)", () => {
  it("a Velociraptor visit to the origin page before the record is noted on both rows, and both are raised to Medium", () => {
    const out = linkQuarantineVisitOrigin([dbRow(), veloVisit(ORIGIN, BEFORE, "v1")]);
    const db = out.find((e) => e.id === "db1")!;
    const v = out.find((e) => e.id === "v1")!;
    expect(db.description).toContain(`${ORIGIN_VISITED_MARKER} visited the origin page:`);
    expect(db.description).toContain("2020-08-17T05:50:00");
    expect(db.severity).toBe("Medium");
    expect(v.description).toContain(`${PRECEDED_QUARANTINE_MARKER} ${DATA}`);
    expect(v.severity).toBe("Medium");
    expect(db.description).not.toMatch(/caused|drive-by/);
  });

  it("a Hindsight visit joins the same way; a visit to the download URL itself is its own note", () => {
    const out = linkQuarantineVisitOrigin([dbRow(), hindsightVisit(DATA, BEFORE, "h1")]);
    const db = out.find((e) => e.id === "db1")!;
    expect(db.description).toContain(`${DATA_URL_VISITED_MARKER} visited the download URL:`);
    expect(db.description).not.toContain(ORIGIN_VISITED_MARKER);
    expect(out.find((e) => e.id === "h1")!.description).toContain(PRECEDED_QUARANTINE_MARKER);
  });

  it("a visit after the record, in the same second, or to another page on the same host joins nothing", () => {
    const rows = [
      dbRow(),
      veloVisit(ORIGIN, AFTER, "after"),
      veloVisit(ORIGIN, "2020-08-17T05:52:44Z", "same"),
      veloVisit("https://lure.example.invalid/other", BEFORE, "other"),
      veloVisit("https://lure.example.invalid/", BEFORE, "root"),
    ];
    const out = linkQuarantineVisitOrigin(rows);
    expect(out.find((e) => e.id === "db1")!.description).not.toMatch(/visited the/);
    for (const id of ["after", "same", "other", "root"]) {
      const e = out.find((x) => x.id === id)!;
      expect(e.description).not.toContain(PRECEDED_QUARANTINE_MARKER);
      expect(e.severity).toBe("Info");
    }
  });

  it("two named hosts must agree; an unnamed side attaches only when one host is named, and says so", () => {
    const agree = linkQuarantineVisitOrigin([dbRow({}, "mac-01"), veloVisit(ORIGIN, BEFORE, "v1", "mac-01")]);
    expect(agree.find((e) => e.id === "db1")!.description).toContain(ORIGIN_VISITED_MARKER);
    const differ = linkQuarantineVisitOrigin([
      dbRow({}, "mac-01"),
      veloVisit(ORIGIN, BEFORE, "v1", "mac-02"),
    ]);
    expect(differ.find((e) => e.id === "db1")!.description).not.toContain(ORIGIN_VISITED_MARKER);
    const oneNamed = linkQuarantineVisitOrigin([dbRow({}, "mac-01"), veloVisit(ORIGIN, BEFORE, "v1")]);
    expect(oneNamed.find((e) => e.id === "db1")!.description).toContain("host not named on one record");
  });

  it("is recomputed on every pass", () => {
    const once = linkQuarantineVisitOrigin([dbRow(), veloVisit(ORIGIN, BEFORE, "v1")]);
    const twice = linkQuarantineVisitOrigin(once);
    expect(twice.map((e) => e.description)).toEqual(once.map((e) => e.description));
    const alone = linkQuarantineVisitOrigin([once.find((e) => e.id === "db1")!]);
    expect(alone[0].description).not.toContain(ORIGIN_VISITED_MARKER);
  });

  it("runs inside the merge", () => {
    const base = {
      findings: [],
      iocs: [],
      mitreTechniques: [],
      threadsOpened: [],
      threadsClosed: [],
      timelineNote: "",
      summary: "",
    };
    const ctx = { windowSequence: 1, timestamp: "2026-01-03T00:00:00Z", sourceScreenshots: [] };
    const merged = mergeDelta(
      emptyState("c1"),
      { ...base, forensicEvents: [dbRow(), veloVisit(ORIGIN, BEFORE, "v1")] } as unknown as AnalysisDelta,
      ctx,
    );
    const db = merged.forensicTimeline.find((e) => e.description.startsWith("macOS quarantine ["))!;
    expect(db.description).toContain(ORIGIN_VISITED_MARKER);
    expect(db.severity).toBe("Medium");
  });
});
