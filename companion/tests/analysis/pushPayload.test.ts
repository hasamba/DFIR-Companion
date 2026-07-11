import { describe, it, expect } from "vitest";
import { extractPushPayload } from "../../src/analysis/pushPayload.js";

describe("extractPushPayload", () => {
  it("unwraps { source, events:[...] } → the events array, labeled by source", () => {
    const p = extractPushPayload({ source: "velociraptor-monitor", events: [{ a: 1 }, { a: 2 }] });
    expect(p.source).toBe("velociraptor-monitor");
    expect(JSON.parse(p.text)).toEqual([{ a: 1 }, { a: 2 }]);
    expect(p.filename).toContain("velociraptor-monitor");
  });

  it("accepts alternate array keys (rows / records / data / results)", () => {
    expect(JSON.parse(extractPushPayload({ rows: [{ x: 1 }] }).text)).toEqual([{ x: 1 }]);
    expect(JSON.parse(extractPushPayload({ records: [{ x: 1 }] }).text)).toEqual([{ x: 1 }]);
    expect(JSON.parse(extractPushPayload({ data: [{ x: 1 }] }).text)).toEqual([{ x: 1 }]);
    expect(JSON.parse(extractPushPayload({ results: [{ x: 1 }] }).text)).toEqual([{ x: 1 }]);
  });

  it("accepts a raw string body", () => {
    const p = extractPushPayload("line1\nline2");
    expect(p.text).toBe("line1\nline2");
  });

  it("accepts { text } / { json } / { csv } string fields", () => {
    expect(extractPushPayload({ text: "hi" }).text).toBe("hi");
    expect(extractPushPayload({ json: "{}" }).text).toBe("{}");
    const csv = extractPushPayload({ csv: "a,b\n1,2" });
    expect(csv.text).toBe("a,b\n1,2");
    expect(csv.filename).toMatch(/\.csv$/);
  });

  it("pushes an arbitrary JSON object whole (e.g. a Velociraptor artifact-map)", () => {
    const map = { "Windows.Events.ProcessCreation": [{ Pid: 1 }] };
    const p = extractPushPayload(map);
    expect(JSON.parse(p.text)).toEqual(map);
  });

  it("honors an explicit filename for detection hints", () => {
    const p = extractPushPayload({ source: "x", filename: "Velociraptor-Win.json", events: [{}] });
    expect(p.filename).toBe("Velociraptor-Win.json");
  });

  it("sanitizes the source label and defaults it", () => {
    expect(extractPushPayload({ events: [{}] }).source).toBe("push");
    expect(extractPushPayload({ source: "../../etc/passwd", events: [{}] }).source).not.toContain("/");
  });

  it("stringifies array / primitive bodies", () => {
    expect(JSON.parse(extractPushPayload([{ a: 1 }]).text)).toEqual([{ a: 1 }]);
  });

  it("an empty JSON object body yields empty text, not the non-empty string \"{}\"", () => {
    // A caller's `if (!text.trim())` empty-payload guard must catch this — JSON.stringify({})
    // is the non-empty string "{}", which used to slip past that check and get imported as a
    // junk event with no real content.
    expect(extractPushPayload({}).text).toBe("");
  });
});
