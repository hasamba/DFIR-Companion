import { describe, it, expect } from "vitest";
import {
  extractJsonText,
  repairTruncatedJson,
  parseJsonLoose,
  closeTruncatedJsonArray,
} from "../../src/analysis/extractJson.js";

describe("extractJsonText", () => {
  it("returns plain JSON unchanged", () => {
    const json = '{"a":1,"b":[2,3]}';
    expect(JSON.parse(extractJsonText(json))).toEqual({ a: 1, b: [2, 3] });
  });

  it("strips a ```json fenced block (the real failure case)", () => {
    const raw = '```json\n{\n  "summary": "ok"\n}\n```';
    expect(JSON.parse(extractJsonText(raw))).toEqual({ summary: "ok" });
  });

  it("strips a bare ``` fence with no language tag", () => {
    const raw = '```\n{"x": 1}\n```';
    expect(JSON.parse(extractJsonText(raw))).toEqual({ x: 1 });
  });

  it("extracts JSON from a fenced block surrounded by prose", () => {
    const raw = 'Here is the delta you asked for:\n```json\n{"ok":true}\n```\nLet me know if you need more.';
    expect(JSON.parse(extractJsonText(raw))).toEqual({ ok: true });
  });

  it("slices bare JSON out of leading/trailing prose when there is no fence", () => {
    const raw = 'Sure! {"findings": []} — hope that helps';
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
    expect((JSON.parse(repaired) as { findings: { id: string }[] }).findings.map((f) => f.id)).toEqual([
      "f1",
    ]);
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
    const raw =
      '{"findings":[{"id":"f1","description":"the operator ran ```powershell\\niex(...)``` on the host"}]}';
    const parsed = parseJsonLoose(raw) as { findings: { id: string; description: string }[] };
    expect(parsed.findings[0].id).toBe("f1");
    expect(parsed.findings[0].description).toContain("powershell");
  });

  it("#2: recovers the outer object when a string contains a fenced block AND a raw control char (direct parse fails)", () => {
    // Direct JSON.parse fails on the raw \n inside the description. The previous code fell through
    // to extractJsonText, which matched the INNER ```json fence and returned only the snippet —
    // the whole synthesis (findings + summary) was silently lost. The fix retries
    // escapeControlCharsInStrings on the trimmed text before fence extraction, recovering the
    // outer object. (Inner JSON quotes are escaped, as a model emitting valid JSON inside a
    // description string would do.)
    const raw =
      '{"findings":[{"id":"f1","description":"cmd was:\n```json\\n{\\"cmd\\":\\"x\\"}\\n```\\ndone"}],"summary":"ok"}';
    const parsed = parseJsonLoose(raw) as {
      findings: { id: string; description: string }[];
      summary: string;
    };
    expect(parsed.findings).toHaveLength(1);
    expect(parsed.findings[0].id).toBe("f1");
    expect(parsed.summary).toBe("ok");
    // The inner fenced snippet must NOT be what we get back.
    expect(parsed).not.toEqual({ cmd: "x" });
  });

  it("#4: repairTruncatedJson recovers a partial object when truncation lands inside the first object's string (no '}' exists)", () => {
    // Model hit max_tokens mid-description of the FIRST finding — no '}' exists yet. The previous
    // behavior returned the input unchanged, leaving an unterminated string; JSON.parse failed on
    // "Unterminated string" and the whole response was thrown away. The fix closes the open
    // string and appends structural closers, recovering the finding's id + title (and a truncated
    // description) — more useful than throwing the whole response away.
    const truncated =
      '{"findings":[{"id":"f1","title":"Ransom","description":"Ransomware deployed at 10:20 on SRV-01 by js';
    const repaired = repairTruncatedJson(truncated);
    const parsed = JSON.parse(repaired) as { findings: { id: string; title: string; description: string }[] };
    expect(parsed.findings).toHaveLength(1);
    expect(parsed.findings[0].id).toBe("f1");
    expect(parsed.findings[0].title).toBe("Ransom");
    // The description was truncated mid-string; the repair closed the string, so it parses.
    expect(parsed.findings[0].description).toContain("Ransomware deployed");
  });

  it("#4: parseJsonLoose recovers a partial result from a first-object-string truncation", () => {
    const raw =
      '{"findings":[{"id":"f1","title":"Ransom","description":"Ransomware deployed at 10:20 on SRV-01 by js';
    const parsed = parseJsonLoose(raw) as { findings: { id: string; title: string }[] };
    expect(parsed.findings).toHaveLength(1);
    expect(parsed.findings[0].id).toBe("f1");
  });

  // The repair has to pick between "close the open string" and "cut back to the last complete
  // pair" — doing both at once emits a stray quote onto an already-cut prefix (`{"a":1` + `"` →
  // `{"a":1"}`), which parses nowhere. Each of these lands on a different candidate; all must
  // produce VALID JSON, never a plausible-looking string that JSON.parse still rejects.
  it("#4: every no-'}' truncation shape repairs to valid JSON, whichever candidate wins", () => {
    const shapes: [string, unknown][] = [
      // Truncated inside a later key's VALUE, with an earlier complete pair → close the string.
      ['{"a":1,"b":"unterminated', { a: 1, b: "unterminated" }],
      // Truncated inside a nested ARRAY's string element → close the string, balance [ and {.
      ['{"summary":"ok","findings":["a","b', { summary: "ok", findings: ["a", "b"] }],
      // Truncated inside a KEY — closing the string leaves a key with no value, so cut instead.
      ['{"a":1,"bcd', { a: 1 }],
      // Truncated right after a ':' — nothing to close; cut back to the last complete pair.
      ['{"a":1,"b":', { a: 1 }],
      // Truncated on the separator after a complete pair — drop the dangling comma.
      ['{"observations":[{"summary":"x"}, ', { observations: [{ summary: "x" }] }],
      // Nothing but the opening brace.
      ["{", {}],
    ];
    for (const [truncated, expected] of shapes) {
      const repaired = repairTruncatedJson(truncated);
      expect(() => JSON.parse(repaired), `repair of ${truncated} → ${repaired}`).not.toThrow();
      expect(JSON.parse(repaired)).toEqual(expected);
    }
  });
});

// #953. POST /cases/:id/import-file classifies from a bounded 256 KB head, and a JSON array cut
// mid-way is not a value, so every array-rooted export over that size read as "unknown" from the one
// route that exists for large files. The head is completed BEFORE the detector sees it — in the
// route's own sniff, never inside the detector, which the whole-file paths share (a malformed whole
// file must still be refused, not classified from its one good row and then imported as nothing).
//
// Precision is the whole point, hence a scan rather than repairTruncatedJson's lastIndexOf("}"):
//   • string-aware — a `}` inside a string value (a command line, an embedded script) is not a
//     record boundary;
//   • depth-aware — only a `}` that returns to array depth ends a top-level element, so a cut inside
//     the FIRST record yields nothing rather than a partial object the generic signatures would
//     claim as some other kind.
describe("closeTruncatedJsonArray", () => {
  const rows = (n: number, extra: Record<string, unknown> = {}) =>
    Array.from({ length: n }, (_, i) => ({ id: i, nested: { a: 1 }, ...extra }));

  it("leaves text that already parses alone", () => {
    expect(closeTruncatedJsonArray(JSON.stringify(rows(3)))).toBeNull();
    expect(closeTruncatedJsonArray("[]")).toBeNull();
  });

  it("returns null for anything not array-rooted — a partial single object is never a safe sample", () => {
    const big = JSON.stringify({ info: { id: 1 }, signatures: rows(50) });
    expect(closeTruncatedJsonArray(big.slice(0, big.length - 40))).toBeNull();
    expect(closeTruncatedJsonArray("not json")).toBeNull();
  });

  it("keeps every complete top-level element and drops the cut one", () => {
    const whole = JSON.stringify(rows(5));
    // Cut inside the 4th element: after its nested object closed, before its own closing brace.
    const cut = whole.indexOf('"id":3') + '"id":3,"nested":{"a":1}'.length;
    const out = closeTruncatedJsonArray(whole.slice(0, cut));
    expect(out).not.toBeNull();
    expect(JSON.parse(out!)).toEqual(rows(3));
  });

  it("is string-aware: a `}` inside a string value is not a record boundary (review P1)", () => {
    const whole = JSON.stringify(rows(4, { cmd: "powershell -c { Get-Process }" }));
    // Cut just after the `}` that lives INSIDE the 3rd row's cmd string.
    const third = whole.indexOf('"id":2');
    const cut = whole.indexOf("Get-Process }", third) + "Get-Process }".length;
    const out = closeTruncatedJsonArray(whole.slice(0, cut));
    expect(out).not.toBeNull();
    // lastIndexOf("}") would have cut inside the string and produced nothing parseable; the scan
    // keeps exactly the two complete rows before it.
    expect(JSON.parse(out!)).toEqual(rows(2, { cmd: "powershell -c { Get-Process }" }));
  });

  it("is depth-aware: a cut inside the FIRST record yields nothing, not a partial object (review P2)", () => {
    const whole = JSON.stringify(rows(3));
    // Inside the first element, after its nested object closed: lastIndexOf("}") finds that nested
    // brace and a naive repair would manufacture {"id":0,"nested":{"a":1}} as a "complete" record.
    const cut = whole.indexOf('"nested":{"a":1}') + '"nested":{"a":1}'.length;
    expect(closeTruncatedJsonArray(whole.slice(0, cut))).toBeNull();
  });

  it("handles a cut inside a nested object, inside an escape, and between elements", () => {
    const extra = { s: 'a "quoted" \\ value' };
    const whole = JSON.stringify(rows(3, extra));
    const second = whole.indexOf('"id":1');
    const cases: Array<[string, number, number]> = [
      ["inside the 2nd row's nested object", second + 20, 1],
      ["inside the 2nd row's escaped backslash", whole.indexOf("\\\\", second) + 1, 1],
      ["between the 2nd and 3rd rows", whole.indexOf("},{", second) + 2, 2],
    ];
    for (const [label, cut, complete] of cases) {
      const out = closeTruncatedJsonArray(whole.slice(0, cut));
      expect(out, label).not.toBeNull();
      expect(JSON.parse(out!), label).toEqual(rows(complete, extra));
    }
  });
});
