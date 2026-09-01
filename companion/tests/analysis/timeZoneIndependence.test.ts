import { describe, it, expect, afterAll } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import { clampOutlierYears } from "../../src/analysis/timeYearClamp.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

// #757 — the year logic must give the SAME answer on every server, whatever TZ it runs in.
//
// Nothing forces the model to put a zone on the timestamp it returns: the prompts ask for a trailing
// "Z", deltaSchema only asked for a string, and an operator may replace either prompt outright via
// DFIR_AI_CSV_PROMPT / DFIR_AI_LOG_PROMPT (a replacement is NOT covered by the prompt-drift guard,
// which knows only SYNTH/TAGGERRULE/OBSERVE). So a naive stamp does reach the importer, and
// `Date.parse` reads a naive stamp in the SERVER's zone. Within |offset| hours of a year boundary the
// year that parse reports differs from the year the string shows, and the damage went both ways:
//
//   • east of UTC — a RECORDED year read as guessed, so real evidence became clamp-eligible: the #739
//     defect, reintroduced silently and only off UTC;
//   • west of UTC — a GUESSED year read as recorded, so the clamp could never correct it;
//   • and once marked, the clamp's own parse moved the event ~364 days rather than leaving it on the
//     dominant year, breaking its documented "preserve month/day/time" contract.
//
// Every case below therefore runs in several zones on both sides of UTC. `process.env.TZ` is honoured
// at runtime, so mutating it here really does change what Date.parse means.
const ZONES = ["UTC", "Asia/Jerusalem", "Europe/Berlin", "America/Los_Angeles", "Pacific/Auckland"];

const ORIGINAL_TZ = process.env.TZ;

function restoreTz(): void {
  if (ORIGINAL_TZ === undefined) delete process.env.TZ;
  else process.env.TZ = ORIGINAL_TZ;
}

afterAll(restoreTz);

/** Run `body` once per zone, restoring the ambient zone afterwards even when an expectation fails. */
async function inEachZone(body: (zone: string) => Promise<void> | void): Promise<void> {
  for (const zone of ZONES) {
    process.env.TZ = zone;
    try {
      await body(zone);
    } finally {
      restoreTz();
    }
  }
}

/**
 * A pipeline over a FRESH case whose model returns exactly one event, at `timestamp`.
 *
 * Fresh per call, not per test: these cases run the same import once per zone, and a shared case
 * would accumulate one event per zone — leaving `forensicTimeline[0]` owned by whichever zone ran
 * first, so the assertion would pass in every zone without ever reading the later zones' events.
 */
async function importOneEvent(timestamp: string, csv: string): Promise<ForensicEvent> {
  const root = await mkdtemp(join(tmpdir(), "dfir-tz-"));
  const caseStore = new CaseStore(root);
  await caseStore.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: "mock" });
  const pipeline = new AnalysisPipeline({
    provider: {
      name: "spy",
      model: "mock-model",
      analyze: async () => ({
        rawText: JSON.stringify({
          findings: [],
          iocs: [],
          mitreTechniques: [],
          threadsOpened: [],
          threadsClosed: [],
          timelineNote: "read rows",
          summary: "",
          forensicEvents: [
            {
              id: "e1",
              timestamp,
              description: "row event",
              severity: "High",
              mitreTechniques: [],
              relatedFindingIds: [],
            },
          ],
        }),
      }),
    },
    stateStore: new StateStore(caseStore),
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  const state = await pipeline.analyzeCsv("c1", csv, {
    label: "0001_results.csv",
    idPrefix: "m1",
    importedAt: "2026-06-01T00:00:00Z",
  });
  expect(state.forensicTimeline).toHaveLength(1);
  return state.forensicTimeline[0];
}

describe("year provenance is timezone-independent (#757)", () => {
  it("keeps a RECORDED year recorded when the model drops the 'Z' near New Year", async () => {
    // "2026" is literally in the CSV, so this year was read out of the source, not invented — the
    // clamp must never be allowed near it. On a UTC+2 host the old parse called it 2025, missed the
    // source-year match, and marked it guessed.
    await inEachZone(async (zone) => {
      const event = await importOneEvent(
        "2026-01-01T00:30:00",
        "Time,Process\n2026-01-01T00:30:00Z,a.exe\n2026-01-01T00:31:00Z,b.exe\n",
      );
      expect(event.yearInferred, zone).toBeUndefined();
    });
  });

  it("still marks a GUESSED year when the model drops the 'Z' near New Year", async () => {
    // The file only ever says 2026, so a 2025 stamp was supplied by the model. On a UTC-8 host the
    // old parse called it 2026, matched the source year, and let an invented year pass as recorded.
    await inEachZone(async (zone) => {
      const event = await importOneEvent(
        "2025-12-31T23:30:00",
        "Time,Process\n2026-06-01T00:30:00Z,a.exe\n2026-06-01T00:31:00Z,b.exe\n",
      );
      expect(event.yearInferred, zone).toBe(true);
    });
  });

  it("stores the model's naive stamp as the instant it shows, not the server's reading of it", async () => {
    await inEachZone(async (zone) => {
      const event = await importOneEvent("2026-01-01T00:30:00", "Time,Process\n2026-01-01T00:30:00Z,a.exe\n");
      expect(event.timestamp, zone).toBe("2026-01-01T00:30:00Z");
    });
  });
});

function ev(id: string, timestamp: string, extra: Partial<ForensicEvent> = {}): ForensicEvent {
  return {
    id,
    timestamp,
    description: id,
    severity: "Info",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    ...extra,
  };
}

describe("clampOutlierYears is timezone-independent (#757)", () => {
  // 14 recorded events — past YEAR_CLAMP_MIN_EVENTS, and a single dominant year.
  const dominant2026 = Array.from({ length: 14 }, (_, i) => ev(`d${i}`, `2026-03-0${(i % 9) + 1}T10:00:00Z`));

  it("leaves a naive guessed stamp alone when it already sits on the dominant year", async () => {
    // A case imported before the deltaSchema fix can still hold a naive stamp, so the clamp has to
    // read one correctly on its own. On a UTC+2 host this used to become 2026-12-31T22:30:00.000Z —
    // the clamp saw year 2025, "re-anchored" to 2026, and rebuilt the date from the shifted UTC
    // month/day, moving the event 364 days.
    await inEachZone((zone) => {
      const out = clampOutlierYears([
        ...dominant2026,
        ev("g1", "2026-01-01T00:30:00", { yearInferred: true }),
      ]);
      const got = out.find((e) => e.id === "g1")!;
      expect(got.timestamp, zone).toBe("2026-01-01T00:30:00");
      expect(got.yearClampedFrom, zone).toBeUndefined();
    });
  });

  it("re-anchors a naive guessed stamp from an outlier year, preserving the month/day it shows", async () => {
    await inEachZone((zone) => {
      const out = clampOutlierYears([
        ...dominant2026,
        ev("g1", "2025-01-01T00:30:00", { yearInferred: true }),
      ]);
      const got = out.find((e) => e.id === "g1")!;
      expect(got.timestamp, zone).toBe("2026-01-01T00:30:00.000Z");
      expect(got.yearClampedFrom, zone).toBe("2025-01-01T00:30:00");
    });
  });
});
