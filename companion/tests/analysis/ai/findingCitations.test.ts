import { describe, expect, it } from "vitest";
import {
  citationRunWarnings,
  needsCitationRetry,
  recoverProseCitations,
  uncitedFindingIds,
} from "../../../src/analysis/ai/findingCitations.js";
import { deltaSchema } from "../../../src/analysis/responseSchema.js";

/**
 * #1754 — on INC-2026-022 one Opus synthesis stored 13 findings, each with an empty relatedEventIds.
 * f12 named 29e20, 29e21 and 29e33 in its description, and f10 named 4e378 and 12e54. With nothing
 * cited, the High backfill raised 82 auto findings, some on rows a dismissed finding had explained.
 */

const finding = (id: string, description: string, relatedEventIds?: string[], status = "open") => ({
  id,
  severity: "High",
  title: `finding ${id}`,
  description,
  relatedIocs: [],
  mitreTechniques: [],
  status,
  ...(relatedEventIds ? { relatedEventIds } : {}),
});

const delta = (findings: unknown[]) =>
  deltaSchema.parse({
    findings,
    iocs: [],
    mitreTechniques: [],
    threadsOpened: [],
    threadsClosed: [],
    timelineNote: "",
    summary: "s",
  });

const KNOWN = new Set(["29e20", "29e21", "29e33", "4e378", "12e54", "4e37", "cld-e1"]);

describe("uncitedFindingIds", () => {
  it("names each finding with no id that resolves to a known event", () => {
    const d = delta([
      finding("f1", "x", ["29e20"]),
      finding("f2", "x", []),
      finding("f3", "x"),
      finding("f4", "x", ["99e99"]), // dangling only
      finding("f5", "x", ["[cld-e1]"]), // decorated, resolves
    ]);
    expect(uncitedFindingIds(d, KNOWN)).toEqual(["f2", "f3", "f4"]);
  });
});

describe("needsCitationRetry", () => {
  it("retries a wholly uncited answer and a mostly uncited one", () => {
    expect(needsCitationRetry(13, 13)).toBe(true);
    expect(needsCitationRetry(12, 13)).toBe(true);
    expect(needsCitationRetry(2, 3)).toBe(true);
  });

  it("does not retry an empty answer, one lone uncited finding, or a minority", () => {
    expect(needsCitationRetry(0, 0)).toBe(false);
    expect(needsCitationRetry(1, 1)).toBe(false);
    expect(needsCitationRetry(2, 4)).toBe(false);
    expect(needsCitationRetry(3, 13)).toBe(false);
  });
});

describe("recoverProseCitations", () => {
  it("recovers the ids an uncited finding names in its text", () => {
    const d = delta([
      finding("f12", "YARA hit on files 29e20, 29e21 and 29e33 created at 15:00."),
      finding(
        "f10",
        "The 11:57 InboxIMEs script block (4e378, 12e54) is a normal Windows script.",
        [],
        "dismissed",
      ),
    ]);
    const { delta: out, recovered } = recoverProseCitations(d, KNOWN, KNOWN);
    expect(out.findings[0].relatedEventIds).toEqual(["29e20", "29e21", "29e33"]);
    expect(out.findings[1].relatedEventIds).toEqual(["4e378", "12e54"]);
    expect(recovered).toEqual([
      { findingId: "f12", eventIds: ["29e20", "29e21", "29e33"] },
      { findingId: "f10", eventIds: ["4e378", "12e54"] },
    ]);
  });

  it("reads the title too", () => {
    const d = delta([{ ...finding("f1", "nothing here"), title: "Burst at 29e20" }]);
    expect(recoverProseCitations(d, KNOWN, KNOWN).delta.findings[0].relatedEventIds).toEqual(["29e20"]);
  });

  it("never touches a finding that already cites a known event", () => {
    const d = delta([finding("f1", "see also 29e21", ["29e20"])]);
    const { delta: out, recovered } = recoverProseCitations(d, KNOWN, KNOWN);
    expect(out).toBe(d);
    expect(recovered).toEqual([]);
  });

  it("replaces a dangling-only citation list with the ids the text names", () => {
    const d = delta([finding("f1", "row 29e20 shows it", ["99e99"])]);
    expect(recoverProseCitations(d, KNOWN, KNOWN).delta.findings[0].relatedEventIds).toEqual(["29e20"]);
  });

  it("matches whole ids only — 4e37 is not read inside 4e378, nor 29e2 inside 29e20", () => {
    const d = delta([finding("f1", "row 4e378 and 29e205")]);
    expect(recoverProseCitations(d, KNOWN, KNOWN).delta.findings[0].relatedEventIds).toEqual(["4e378"]);
  });

  it("recovers only ids printed in the prompt, not grouped members or omitted rows", () => {
    const literal = new Set(["29e20"]);
    const d = delta([finding("f1", "rows 29e20 and 29e21")]);
    expect(recoverProseCitations(d, literal, KNOWN).delta.findings[0].relatedEventIds).toEqual(["29e20"]);
  });

  it("skips a sentence that contrasts or negates the event", () => {
    const d = delta([
      finding(
        "f1",
        "Unlike 29e20, this came from the sample corpus. 29e21 does not support this. " +
          "The corpus rows (29e33) are samples. 4e378 is benign, but 12e54 is not.",
        [],
        "dismissed",
      ),
    ]);
    expect(recoverProseCitations(d, KNOWN, KNOWN).delta.findings[0].relatedEventIds).toEqual(["29e33"]);
  });

  it("leaves a finding that names no id unchanged, and returns the same delta", () => {
    const d = delta([finding("f1", "Defender real-time protection was disabled")]);
    const r = recoverProseCitations(d, KNOWN, KNOWN);
    expect(r.delta).toBe(d);
    expect(r.recovered).toEqual([]);
  });

  it("handles ids with regex characters literally", () => {
    const known = new Set(["a.b+1"]);
    const d = delta([finding("f1", "row a.b+1 and axb+1")]);
    expect(recoverProseCitations(d, known, known).delta.findings[0].relatedEventIds).toEqual(["a.b+1"]);
  });
});

describe("citationRunWarnings", () => {
  it("says how many AI findings cite no event", () => {
    expect(citationRunWarnings({ uncited: 11, total: 13 })).toEqual([
      "11 of 13 AI finding(s) cite no event, so the High backfill cannot tell which rows they cover",
    ]);
  });

  it("says when the citation retry ran", () => {
    expect(citationRunWarnings({ uncited: 0, total: 13, retriedAfter: { uncited: 13, total: 13 } })).toEqual([
      "citation retry ran: the first answer left 13 of 13 AI finding(s) with no cited event",
    ]);
  });

  it("is silent for a fully cited run and for an answer with no findings", () => {
    expect(citationRunWarnings({ uncited: 0, total: 13 })).toEqual([]);
    expect(citationRunWarnings({ uncited: 0, total: 0 })).toEqual([]);
  });
});
