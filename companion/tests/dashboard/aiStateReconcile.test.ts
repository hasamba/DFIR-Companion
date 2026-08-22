// The pill is corrected from the case, not remembered from the event stream.
//
// `ai_status` is pushed from 155 call sites and the header pill was its only consumer, so the
// pill's state existed nowhere else. Three bugs came out of that single gap — a wrong event, an
// absent event, and no event at all — and the third is the plainest: the pill's starting state came
// from `/health`, which is server-wide and cannot know anything about a case, so a reload on a held
// case read "ready (waiting for activity)" beside a cockpit reading "on hold".
//
// These assertions are about WIRING — which call sites exist — so they read the client source.
// deriveAiState's own behaviour is covered in tests/analysis/aiState.test.ts and the composition in
// tests/server/aiStateRoute.test.ts; this is the layer that makes either of them reach the screen.
import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";

// Newlines are normalised because the assertions below bound the DISTANCE between two anchors, and
// a CRLF checkout adds a character per line inside that window. The idle-event assertion spans 499
// characters against a 500 limit on Linux and 506 on Windows — it failed there for the sole reason
// that the file had \r\n endings.
const read = (f: string) =>
  readFileSync(new URL(`../../../public/js/${f}`, import.meta.url), "utf8").replace(/\r\n/g, "\n");

const connect = read("dashboard-case-connect.js");
const status = read("dashboard-ai-status.js");
const duplicates = read("dashboard-host-duplicates.js");
const presidio = read("dashboard-presidio.js");

describe("the pill's starting state", () => {
  // THE REGRESSION. /health has no case in scope; deriving a per-case status from it is the bug.
  it("is no longer taken from /health's server-wide aiEnabled flag", () => {
    expect(
      connect,
      '/health cannot know about a case — a per-case "ready" claimed from it is the reload bug',
    ).not.toMatch(/if \(h\.aiEnabled\) setAi\("idle"/);
  });

  it("still paints the no-provider case immediately, before the derived read returns", () => {
    expect(connect).toMatch(/if \(!h\.aiEnabled\) setAi\("off"/);
  });

  it("is read from the case on connect, beside the two gate chips", () => {
    expect(connect).toMatch(/\["aiState", \(\) => refreshAiState\(caseId\)\]/);
  });
});

describe("the four moments the pill re-derives", () => {
  it("re-reads when the websocket reconnects, because the gap delivered nothing", () => {
    expect(connect).toMatch(/ws\.onopen[\s\S]{0,300}refreshAiState\(/);
  });

  // "idle" is the event most likely to be wrong: it is emitted by whichever run just finished, and
  // that run knows nothing about a gate still holding the next one.
  it("verifies an idle event against the case", () => {
    // The bound only has to say "these two are in the same stanza", and 500 left one character of
    // headroom over the actual 499 — so any two-character edit to that region of the source would
    // have reddened this for a reason unrelated to what it checks.
    expect(status).toMatch(/evt\.status === "idle"[\s\S]{0,900}refreshAiState\(activeCaseId\)/);
  });

  it("re-reads after a duplicate-host pair is resolved", () => {
    expect(duplicates).toMatch(/refreshAiState\(caseId\)/);
  });

  // Both Presidio paths, not just approve: suppress clears the gate exactly as much as approve does.
  it("re-reads after either Presidio resolution", () => {
    expect(presidio.match(/refreshAiState\(caseId\)/g) ?? []).toHaveLength(2);
  });
});

describe("the corrector itself", () => {
  it("reads the derived endpoint", () => {
    expect(status).toMatch(/\/ai-state/);
  });

  // A failed correction must leave the pill alone rather than invent a state — otherwise the thing
  // added to stop the pill lying becomes another way for it to lie.
  it("leaves the pill untouched when the read fails", () => {
    expect(status).toMatch(/if \(!r\.ok\) return;/);
  });

  // A hold rides alongside the state: a running import is real work even while synthesis is held,
  // and collapsing that to "blocked" would hide it — the first bug in reverse.
  it("renders a hold alongside running work rather than instead of it", () => {
    expect(status).toMatch(/holds && s\.holds\.length \? " \(analysis on hold\)"/);
  });
});
