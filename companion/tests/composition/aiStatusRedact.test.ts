import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { redactAiStatusEvent } from "../../src/composition/aiStatusRedact.js";
import type { AiStatusEvent } from "../../src/composition/appOptions.js";

// #1029 — the HTTP error surface strips absolute paths (#250), but `onAiStatus` events reach the
// WebSocket feed through a different seam. Nine route sites put a raw `err.message` in `detail`,
// so an fs error on a background import would broadcast the cases root to every subscribed
// dashboard. The redaction lives once at the wiring seam, not per call site.

const ROOT = "/srv/dfir/cases";
const AT = "2026-09-13T00:00:00.000Z";

describe("redactAiStatusEvent", () => {
  it("replaces an absolute path inside detail with the placeholder", () => {
    const event: AiStatusEvent = {
      status: "error",
      at: AT,
      detail: `EACCES: permission denied, open '${ROOT}/ACME-2026-07/state/state.json'`,
    };
    const out = redactAiStatusEvent(event, [ROOT]);
    expect(out.detail).toBe("EACCES: permission denied, open '<path>'");
    expect(out.detail).not.toContain("ACME-2026-07");
  });

  it("redacts a Windows path too", () => {
    const event: AiStatusEvent = {
      status: "error",
      at: AT,
      detail: "ENOENT: no such file or directory, open 'C:\\Users\\jsmith\\cases\\ACME\\state.json'",
    };
    expect(redactAiStatusEvent(event, [ROOT]).detail).toBe(
      "ENOENT: no such file or directory, open '<path>'",
    );
  });

  it("leaves a detail with no path untouched, and keeps every other field", () => {
    const event: AiStatusEvent = { status: "analyzing", at: AT, phase: "synthesizing", detail: "window 4" };
    expect(redactAiStatusEvent(event, [ROOT])).toEqual(event);
  });

  it("passes an event without detail through with the same shape", () => {
    const event: AiStatusEvent = { status: "idle", at: AT };
    const out = redactAiStatusEvent(event, [ROOT]);
    expect(out).toEqual(event);
    expect("detail" in out).toBe(false);
  });

  it("returns a new object and never mutates the input", () => {
    const event: AiStatusEvent = { status: "error", at: AT, detail: `boom ${ROOT}/x` };
    const out = redactAiStatusEvent(event, [ROOT]);
    expect(out).not.toBe(event);
    expect(event.detail).toBe(`boom ${ROOT}/x`);
  });
});

describe("appWiring routes onAiStatus through the redactor", () => {
  // A contract on the wiring line itself: the seam is one arrow function, and a future edit that
  // spreads the raw event again would silently reopen the leak with every unit test still green.
  // Since #1438 the seam is createAiStatusHandler: the handler redacts once and hands the
  // redacted event to `broadcast`; the wiring block must still name the redactor, and the
  // broadcast line must still spread the redacted value, never the raw event.
  it("the ai_status broadcast spreads the redacted event, not the raw one", () => {
    const src = readFileSync(join(import.meta.dirname, "../../src/composition/appWiring.ts"), "utf8");
    const start = src.indexOf("onAiStatus: createAiStatusHandler(");
    expect(start).toBeGreaterThan(-1);
    const block = src.slice(start, src.indexOf("onCapture:", start));
    expect(block).toContain("redact: (event) => redactAiStatusEvent(event, [store.casesRoot])");
    const line = block.split("\n").find((l) => l.includes('type: "ai_status"'));
    expect(line).toBeDefined();
    expect(line).not.toMatch(/\.\.\.event\b/);
  });
});
