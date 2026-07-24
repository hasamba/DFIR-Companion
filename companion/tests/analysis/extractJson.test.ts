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

  // Found by /qa on 2026-07-23: an exec-summary call failed twice in a row with
  // "Bad control character in string literal in JSON at position 2566", burning a full
  // AI call per retry. The model emits a LITERAL newline/tab inside a string value
  // instead of the \n / \t escape, which JSON.parse rejects outright — and the
  // truncation repair can't help, because the bad byte sits mid-response.
  it("escapes a literal newline emitted inside a string value", () => {
    const raw = '{"summary":"line one\nline two","ok":true}';
    const parsed = parseJsonLoose(raw) as { summary: string; ok: boolean };
    expect(parsed.ok).toBe(true);
    expect(parsed.summary).toBe("line one\nline two");
  });

  it("escapes a literal tab emitted inside a string value", () => {
    const raw = '{"summary":"col1\tcol2"}';
    expect((parseJsonLoose(raw) as { summary: string }).summary).toBe("col1\tcol2");
  });

  it("handles a control character AND truncation in the same response", () => {
    const raw = '{"findings":[{"id":"f1","d":"a\nb"},{"id":"f2"';
    const parsed = parseJsonLoose(raw) as { findings: { id: string; d?: string }[] };
    expect(parsed.findings.map((f) => f.id)).toEqual(["f1"]);
    expect(parsed.findings[0].d).toBe("a\nb");
  });

  it("leaves structural whitespace between tokens alone", () => {
    // Newlines/tabs BETWEEN tokens are legal JSON whitespace — escaping those would
    // corrupt the document. Only control chars inside string literals get escaped.
    const pretty = '{\n\t"a": 1,\n\t"b": [2, 3]\n}';
    expect(parseJsonLoose(pretty)).toEqual({ a: 1, b: [2, 3] });
  });

  it("does not corrupt an already-escaped \\n inside a string", () => {
    const raw = '{"cmd":"line1\\nline2"}';
    expect((parseJsonLoose(raw) as { cmd: string }).cmd).toBe("line1\nline2");
  });

  it("prefers whole-response JSON over a fence that only appears INSIDE a string value", () => {
    // A finding description quoting a fenced command block: fence-extraction would slice the
    // response apart mid-string and throw, even though the raw response is already valid JSON.
    const raw = '{"findings":[{"id":"f1","description":"the operator ran ```powershell\\niex(...)``` on the host"}]}';
    const parsed = parseJsonLoose(raw) as { findings: { id: string; description: string }[] };
    expect(parsed.findings[0].id).toBe("f1");
    expect(parsed.findings[0].description).toContain("powershell");
  });
});
