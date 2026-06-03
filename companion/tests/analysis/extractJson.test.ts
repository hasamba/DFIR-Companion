import { describe, it, expect } from "vitest";
import { extractJsonText, repairTruncatedJson, parseJsonLoose } from "../../src/analysis/extractJson.js";

describe("extractJsonText", () => {
  it("returns plain JSON unchanged", () => {
    const json = '{"a":1,"b":[2,3]}';
    expect(JSON.parse(extractJsonText(json))).toEqual({ a: 1, b: [2, 3] });
  });

  it("strips a ```json fenced block (the real failure case)", () => {
    const raw = "```json\n{\n  \"summary\": \"ok\"\n}\n```";
    expect(JSON.parse(extractJsonText(raw))).toEqual({ summary: "ok" });
  });

  it("strips a bare ``` fence with no language tag", () => {
    const raw = "```\n{\"x\": 1}\n```";
    expect(JSON.parse(extractJsonText(raw))).toEqual({ x: 1 });
  });

  it("extracts JSON from a fenced block surrounded by prose", () => {
    const raw = "Here is the delta you asked for:\n```json\n{\"ok\":true}\n```\nLet me know if you need more.";
    expect(JSON.parse(extractJsonText(raw))).toEqual({ ok: true });
  });

  it("slices bare JSON out of leading/trailing prose when there is no fence", () => {
    const raw = "Sure! {\"findings\": []} — hope that helps";
    expect(JSON.parse(extractJsonText(raw))).toEqual({ findings: [] });
  });
});

describe("repairTruncatedJson / parseJsonLoose", () => {
  it("repairs a response truncated mid-array (the max_tokens cut-off case)", () => {
    // Model hit max_tokens partway through the 3rd finding's description.
    const truncated = '{"findings":[{"id":"f1","title":"a"},{"id":"f2","title":"b"},{"id":"f3","title":"c';
    const parsed = parseJsonLoose(truncated) as { findings: { id: string }[] };
    expect(parsed.findings.map((f) => f.id)).toEqual(["f1", "f2"]); // last complete objects survive
  });

  it("drops a dangling comma after the last complete element", () => {
    const truncated = '{"iocs":[{"id":"i1","value":"x"},{"id":"i2","value":"y"},';
    const parsed = parseJsonLoose(truncated) as { iocs: { id: string }[] };
    expect(parsed.iocs.map((i) => i.id)).toEqual(["i1", "i2"]);
  });

  it("drops an incomplete trailing object and closes nested open structures", () => {
    // Truncated deep inside the 2nd finding (nested object) — the 1st survives.
    const truncated = '{"findings":[{"id":"f1","mitre":["T1"]},{"id":"f2","ev":{"x":1';
    const repaired = repairTruncatedJson(truncated);
    expect(() => JSON.parse(repaired)).not.toThrow();
    expect((JSON.parse(repaired) as { findings: { id: string }[] }).findings.map((f) => f.id)).toEqual(["f1"]);
  });

  it("leaves valid JSON untouched", () => {
    const ok = '{"findings":[{"id":"f1"}],"iocs":[]}';
    expect(parseJsonLoose(ok)).toEqual({ findings: [{ id: "f1" }], iocs: [] });
  });

  it("repairs truncation even inside a markdown fence", () => {
    const fenced = '```json\n{"findings":[{"id":"f1"},{"id":"f2"';
    const parsed = parseJsonLoose(fenced) as { findings: { id: string }[] };
    expect(parsed.findings.map((f) => f.id)).toEqual(["f1"]);
  });
});
