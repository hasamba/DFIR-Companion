import { describe, expect, it } from "vitest";
import {
  describeLookup,
  parseLookup,
  WATSON_LOOKUP_LIMITS,
} from "../../../src/analysis/ai/watson/lookupSchema.js";
import {
  renderLookup,
  selectLookupEvents,
  timelineRow,
  WATSON_LOOKUP_MAX_CHARS,
  WATSON_LOOKUP_MAX_EVENTS,
} from "../../../src/analysis/ai/watson/timelineLookup.js";
import { sanitizeWatsonReply, watsonReplySchema } from "../../../src/analysis/ai/watson/replySchema.js";
import type { Finding, ForensicEvent, InvestigationState } from "../../../src/analysis/stateTypes.js";

// Task 11: Watson looks up forensic-timeline events on demand. The request is untrusted model JSON:
// anything invalid is dropped with a reason, never thrown.

const ev = (id: string, over: Partial<ForensicEvent> = {}): ForensicEvent => ({
  id,
  timestamp: "2026-01-01T10:00:00Z",
  description: `event ${id}`,
  severity: "High",
  mitreTechniques: [],
  relatedFindingIds: [],
  sourceScreenshots: [],
  ...over,
});

const finding = (id: string, relatedEventIds: string[]): Finding =>
  ({ id, title: id, severity: "High", relatedEventIds }) as unknown as Finding;

const stateOf = (events: ForensicEvent[], findings: Finding[] = []) =>
  ({ forensicTimeline: events, findings }) as unknown as InvestigationState;

describe("parseLookup", () => {
  it("no lookup asked: null for absent or null", () => {
    expect(parseLookup(undefined)).toBeNull();
    expect(parseLookup(null)).toBeNull();
  });

  it("accepts each criterion on its own", () => {
    expect(parseLookup({ findingIds: ["f6"] })).toEqual({ ok: true, query: { findingIds: ["f6"] } });
    expect(parseLookup({ eventIds: ["e1", "e2"] })).toEqual({ ok: true, query: { eventIds: ["e1", "e2"] } });
    expect(parseLookup({ host: " WS-01 " })).toEqual({ ok: true, query: { host: "WS-01" } });
    expect(parseLookup({ text: "mimikatz" })).toEqual({ ok: true, query: { text: "mimikatz" } });
    expect(parseLookup({ from: "2026-01-01T15:55:00Z", to: "2026-01-01T16:50:00Z" })).toEqual({
      ok: true,
      query: { from: "2026-01-01T15:55:00Z", to: "2026-01-01T16:50:00Z" },
    });
  });

  it("treats null fields and empty lists as not given, and needs at least one criterion", () => {
    expect(parseLookup({ host: "WS-01", text: null, eventIds: [], from: null })).toEqual({
      ok: true,
      query: { host: "WS-01" },
    });
    const none = parseLookup({ eventIds: [], host: null });
    expect(none).toMatchObject({ ok: false });
    expect(parseLookup({})).toMatchObject({ ok: false });
  });

  it("drops a request over a limit instead of clamping it", () => {
    const tooMany = (n: number) => Array.from({ length: n }, (_, i) => `x${i}`);
    expect(parseLookup({ findingIds: tooMany(WATSON_LOOKUP_LIMITS.findingIds + 1) })).toMatchObject({
      ok: false,
    });
    expect(parseLookup({ eventIds: tooMany(WATSON_LOOKUP_LIMITS.eventIds + 1) })).toMatchObject({
      ok: false,
    });
    expect(parseLookup({ host: "h".repeat(201) })).toMatchObject({ ok: false });
    expect(parseLookup({ text: "t".repeat(201) })).toMatchObject({ ok: false });
    expect(parseLookup({ eventIds: tooMany(50) })).toMatchObject({ ok: true });
  });

  it("a time window needs both ends, in order, at most 7 days apart, as real timestamps", () => {
    expect(parseLookup({ from: "2026-01-01T00:00:00Z" })).toMatchObject({ ok: false });
    expect(parseLookup({ to: "2026-01-01T00:00:00Z" })).toMatchObject({ ok: false });
    expect(parseLookup({ from: "2026-01-02T00:00:00Z", to: "2026-01-01T00:00:00Z" })).toMatchObject({
      ok: false,
    });
    expect(parseLookup({ from: "2026-01-01T00:00:00Z", to: "2026-01-08T00:00:01Z" })).toMatchObject({
      ok: false,
    });
    expect(parseLookup({ from: "2026-01-01T00:00:00Z", to: "2026-01-08T00:00:00Z" })).toMatchObject({
      ok: true,
    });
    expect(parseLookup({ from: "yesterday", to: "today" })).toMatchObject({ ok: false });
  });

  it("drops a value of the wrong type with a reason", () => {
    const out = parseLookup({ eventIds: "e1" });
    expect(out).toMatchObject({ ok: false });
    expect(out && !out.ok && out.why.length).toBeGreaterThan(0);
    expect(parseLookup("e1")).toMatchObject({ ok: false });
  });

  it("describes the lookup in plain words", () => {
    const text = describeLookup({
      findingIds: ["f6", "f2"],
      from: "2026-01-01T15:55:00Z",
      to: "2026-01-01T16:50:00Z",
      host: "WS-01",
      text: "rar",
    });
    expect(text).toContain("cited by finding f6, f2");
    expect(text).toContain("2026-01-01T15:55:00Z");
    expect(text).toContain("WS-01");
    expect(text).toContain('"rar"');
  });
});

describe("the reply schema carries one lookup", () => {
  const base = {
    message: "m",
    workingOn: "",
    learned: "",
    questionUpdates: [],
    newQuestions: [],
    request: null,
    memory: "",
  };
  const sanitize = (raw: Record<string, unknown>) =>
    sanitizeWatsonReply(watsonReplySchema.parse({ ...base, ...raw }), new Set(), new Set(["p1"]), new Set());

  it("keeps a valid lookup and never throws on a broken one", () => {
    expect(sanitize({ lookup: { host: "WS-01" } }).lookup).toEqual({ ok: true, query: { host: "WS-01" } });
    expect(sanitize({ lookup: { eventIds: 7 } }).lookup).toMatchObject({ ok: false });
    expect(sanitize({}).lookup ?? null).toBeNull();
  });

  it("search and lookup together: the search is kept and the lookup dropped with a reason", () => {
    const out = sanitize({ search: { pasteId: "p1", terms: ["x"] }, lookup: { host: "WS-01" } });
    expect(out.search).toEqual({ pasteId: "p1", terms: ["x"] });
    expect(out.lookup).toMatchObject({ ok: false });
    expect(out.lookup && !out.lookup.ok && out.lookup.why).toMatch(/search/);
  });

  it("an invalid search does not block a valid lookup", () => {
    const out = sanitize({ search: { pasteId: "nope", terms: ["x"] }, lookup: { host: "WS-01" } });
    expect(out.search).toBeNull();
    expect(out.lookup).toEqual({ ok: true, query: { host: "WS-01" } });
  });
});

describe("selectLookupEvents", () => {
  const events = [
    ev("e3", {
      timestamp: "2026-01-01T16:10:00Z",
      asset: "WS-01.corp.local",
      description: "rar.exe a loot.rar",
    }),
    ev("e1", { timestamp: "2026-01-01T15:00:00Z", asset: "WS-02" }),
    ev("e2", { timestamp: "2026-01-01T15:56:00Z", asset: "ws-01", path: "c:\\temp\\Mimikatz.exe" }),
    ev("e4", { timestamp: "", asset: "WS-01", description: "undated" }),
  ];

  it("finding ids select the events the finding cites, ordered by time", () => {
    const state = stateOf(events, [finding("f6", ["e3", "e1", "missing"])]);
    expect(selectLookupEvents(events, state, { findingIds: ["f6"] }).map((e) => e.id)).toEqual(["e1", "e3"]);
  });

  it("follows a folded event alias to its live event", () => {
    const state = {
      ...stateOf(events, [finding("f6", ["old-e2"])]),
      eventAliases: { "old-e2": "e2" },
    } as unknown as InvestigationState;
    expect(selectLookupEvents(events, state, { findingIds: ["f6"] }).map((e) => e.id)).toEqual(["e2"]);
  });

  it("event ids and finding ids union; window, host and text narrow", () => {
    const state = stateOf(events, [finding("f1", ["e1"])]);
    expect(
      selectLookupEvents(events, state, { findingIds: ["f1"], eventIds: ["e3"] }).map((e) => e.id),
    ).toEqual(["e1", "e3"]);
    expect(
      selectLookupEvents(events, state, { from: "2026-01-01T15:55:00Z", to: "2026-01-01T16:50:00Z" }).map(
        (e) => e.id,
      ),
    ).toEqual(["e2", "e3"]);
    expect(selectLookupEvents(events, state, { host: "ws-01" }).map((e) => e.id)).toEqual(["e2", "e3", "e4"]);
    expect(selectLookupEvents(events, state, { text: "MIMIKATZ" }).map((e) => e.id)).toEqual(["e2"]);
    expect(selectLookupEvents(events, state, { text: "loot" }).map((e) => e.id)).toEqual(["e3"]);
    expect(selectLookupEvents(events, state, { host: "ws-01", text: "rar" }).map((e) => e.id)).toEqual([
      "e3",
    ]);
  });

  it("text matches the event's account name; host follows the case's host aliases", () => {
    const acct = ev("a1", { canonical: { account: { name: "svc_backup" } } as ForensicEvent["canonical"] });
    expect(selectLookupEvents([acct], stateOf([acct]), { text: "SVC_BACKUP" }).map((e) => e.id)).toEqual([
      "a1",
    ]);
    const merged = ev("m1", { asset: "10.0.0.5" });
    const aliases = {
      canonicalOf: new Map([["10.0.0.5", "ws-01.corp.local"]]),
      aliasesOf: new Map([["ws-01.corp.local", new Set(["10.0.0.5"])]]),
    };
    expect(
      selectLookupEvents([merged], stateOf([merged]), { host: "ws-01.corp.local" }, aliases),
    ).toHaveLength(1);
    expect(selectLookupEvents([merged], stateOf([merged]), { host: "ws-01.corp.local" })).toHaveLength(0);
  });

  it("two FQDNs never match on their first label alone", () => {
    const prod = ev("p1", { asset: "web.prod.example" });
    expect(selectLookupEvents([prod], stateOf([prod]), { host: "web.dev.example" })).toHaveLength(0);
    expect(selectLookupEvents([prod], stateOf([prod]), { host: "WEB" })).toHaveLength(1);
  });

  it("an id that is not in the events it was given is never returned", () => {
    const scoped = events.filter((e) => e.id !== "e2");
    const state = stateOf(events);
    expect(selectLookupEvents(scoped, state, { eventIds: ["e2", "raw-only"] })).toEqual([]);
  });
});

describe("renderLookup", () => {
  it("renders rows exactly as the case-context timeline does", () => {
    const e = ev("e1", { description: "line one\nline two" });
    const out = renderLookup([e]);
    expect(out.text).toBe(timelineRow(e));
    expect(out).toMatchObject({ shown: 1, matched: 1 });
  });

  it("caps at 200 events and says how many matched", () => {
    const many = Array.from({ length: 450 }, (_, i) => ev(`e${i}`));
    const out = renderLookup(many);
    expect(out.shown).toBe(WATSON_LOOKUP_MAX_EVENTS);
    expect(out.matched).toBe(450);
    expect(out.text).toContain("(showing 200 of 450 matching events — narrow the lookup)");
  });

  it("stays inside its character budget", () => {
    const many = Array.from({ length: 150 }, (_, i) => ev(`e${i}`, { description: "x".repeat(400) }));
    const out = renderLookup(many);
    expect(out.text.length).toBeLessThanOrEqual(WATSON_LOOKUP_MAX_CHARS);
    expect(out.shown).toBeLessThan(150);
    expect(out.text).toContain(`(showing ${out.shown} of 150 matching events — narrow the lookup)`);
  });

  it("says so when nothing matched", () => {
    expect(renderLookup([])).toMatchObject({ shown: 0, matched: 0, text: "(no event matched the lookup)" });
  });
});
