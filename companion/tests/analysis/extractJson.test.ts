import { describe, it, expect } from "vitest";
import { extractJsonText } from "../../src/analysis/extractJson.js";

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
