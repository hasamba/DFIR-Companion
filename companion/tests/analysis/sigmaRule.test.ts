import { describe, expect, it } from "vitest";
import {
  parseSigmaRule,
  SIGMA_MAX_RULE_BYTES,
  SIGMA_MAX_SELECTIONS,
  SIGMA_MAX_VALUES_PER_SELECTION,
  SIGMA_MAX_REGEX_LENGTH,
} from "../../src/analysis/sigmaRule.js";
import type { SigmaRule, SigmaSelection } from "../../src/analysis/sigmaRuleTypes.js";

// A parsed rule or the full refusal list — never a throw. Tests reach for `rule` only after
// asserting ok, so a refusal shows up as a readable list, not as a TypeError on undefined.
function parsed(yaml: string): SigmaRule {
  const r = parseSigmaRule(yaml);
  if (!r.ok)
    throw new Error(
      "expected ok, got refusals:\n" + r.refusals.map((x) => `${x.path}: ${x.message}`).join("\n"),
    );
  return r.rule;
}
function refusals(yaml: string): { path: string; message: string }[] {
  const r = parseSigmaRule(yaml);
  if (r.ok) throw new Error("expected refusals, but the rule parsed");
  return r.refusals;
}
const paths = (yaml: string) => refusals(yaml).map((r) => r.path);

const MINIMAL = `
title: Minimal
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\certutil.exe'
  condition: selection
`;

// A rule shaped exactly like the dashboard's per-finding "Export as Sigma draft" (findingSigmaYaml
// in public/js/dashboard-sigma-hunt.js): one selection block per indicator type, single-quoted
// values, and a "1 of sel_*" condition. #797 runs the real function through a vm; this copy pins
// the SHAPE the parser must accept so a draft never becomes unparseable by the Companion itself.
const DASHBOARD_DRAFT = `title: 'Suspicious certutil download'
status: experimental
description: 'certutil fetched a payload from a raw host'
references:
  - 'DFIR Companion finding f-12'
logsource:
  category: process_creation
  product: windows
detection:
  sel_process:
    Image|endswith:
      - '\\certutil.exe'
      - '\\powershell.exe'
    ParentImage|endswith: '\\cmd.exe'
  sel_hash:
    Hashes|contains:
      - 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
  sel_network_ip:
    DestinationIp:
      - '203.0.113.10'
  sel_network_domain:
    DestinationHostname|contains:
      - 'example.invalid'
  sel_file_path:
    TargetFilename|contains:
      - 'payload.ps1'
  condition: 1 of sel_*
falsepositives:
  - Unknown
level: high
tags:
  - attack.t1105
  - attack.command_and_control
  - attack.t1059.001
`;

describe("parseSigmaRule — metadata", () => {
  it("reads title, id, level, description, and keeps tags as written", () => {
    const rule = parsed(`
title: T
id: 2f0d4b8e-7d2a-4d4d-9c26-0a5d2b4c9e11
level: high
description: D
tags:
  - attack.t1059.001
  - attack.execution
logsource:
  category: process_creation
detection:
  sel:
    Image: x
  condition: sel
`);
    expect(rule.title).toBe("T");
    expect(rule.id).toBe("2f0d4b8e-7d2a-4d4d-9c26-0a5d2b4c9e11");
    expect(rule.level).toBe("high");
    expect(rule.description).toBe("D");
    expect(rule.tags).toEqual(["attack.t1059.001", "attack.execution"]);
  });

  it("turns attack.tNNNN[.NNN] tags into technique ids and leaves tactic tags out of the list", () => {
    const rule = parsed(DASHBOARD_DRAFT);
    expect(rule.mitreTechniques).toEqual(["T1105", "T1059.001"]);
  });

  it("keeps logsource category, product and service as written and does not judge the category", () => {
    const rule = parsed(`
title: T
logsource:
  category: made_up_category
  product: linux
  service: auditd
detection:
  sel:
    a: 1
  condition: sel
`);
    expect(rule.logsource).toEqual({ category: "made_up_category", product: "linux", service: "auditd" });
  });

  it("refuses a rule with no title, no logsource, or no detection, all in one list", () => {
    expect(paths("status: experimental\n")).toEqual(["title", "logsource", "detection"]);
  });
});

describe("parseSigmaRule — YAML boundary", () => {
  it("refuses malformed YAML with the YAML error, at path yaml", () => {
    const r = refusals("title: [unclosed\n");
    expect(r).toHaveLength(1);
    expect(r[0].path).toBe("yaml");
    expect(r[0].message).toMatch(/flow|sequence|unexpected|expected/i);
  });

  it("refuses a multi-document file with 'one rule per file'", () => {
    const r = refusals(MINIMAL + "---\n" + MINIMAL);
    expect(r).toEqual([{ path: "yaml", message: expect.stringMatching(/one rule per file/i) }]);
  });

  it("refuses a document that is not a map", () => {
    expect(refusals("- just\n- a list\n")[0].path).toBe("yaml");
  });

  it("refuses an anchor/alias expansion bomb as a YAML refusal instead of throwing (#805)", () => {
    // 432 bytes: nine aliases per level, eight levels deep. The yaml package stops it inside
    // toJS() with a ReferenceError and leaves doc.errors empty, so only a catch turns it into a
    // refusal — and the route above would otherwise answer 500.
    let bomb = 'k1: &a1 ["lol","lol","lol","lol","lol","lol","lol","lol","lol"]\n';
    for (let i = 2; i <= 9; i++)
      bomb += `k${i}: &a${i} [${Array(9)
        .fill(`*a${i - 1}`)
        .join(",")}]\n`;
    expect(Buffer.byteLength(bomb)).toBeLessThan(SIGMA_MAX_RULE_BYTES);
    const r = refusals(bomb);
    expect(r).toEqual([{ path: "yaml", message: expect.stringMatching(/too complex.*anchors or aliases/) }]);
  });

  it(`refuses text over ${SIGMA_MAX_RULE_BYTES} bytes before parsing it`, () => {
    const big = MINIMAL + "description: " + "x".repeat(SIGMA_MAX_RULE_BYTES) + "\n";
    const r = refusals(big);
    expect(r).toHaveLength(1);
    expect(r[0].path).toBe("yaml");
    expect(r[0].message).toMatch(/64 KB|65536|too large/i);
  });
});

describe("parseSigmaRule — selections", () => {
  it("parses a map selection as an AND of fields, with modifiers in order and a scalar as a one-item list", () => {
    const rule = parsed(`
title: T
logsource:
  category: process_creation
detection:
  sel:
    CommandLine|contains|all:
      - ' -enc '
      - ' -w hidden'
    Image|endswith: '\\powershell.exe'
  condition: sel
`);
    expect(rule.detection.selections).toEqual<SigmaSelection[]>([
      {
        kind: "map",
        name: "sel",
        fields: [
          { field: "CommandLine", modifiers: ["contains", "all"], values: [" -enc ", " -w hidden"] },
          { field: "Image", modifiers: ["endswith"], values: ["\\powershell.exe"] },
        ],
      },
    ]);
  });

  it("parses a list of maps as an OR of ANDs", () => {
    const rule = parsed(`
title: T
logsource:
  category: process_creation
detection:
  sel:
    - Image|endswith: '\\a.exe'
      CommandLine|contains: x
    - Image|endswith: '\\b.exe'
  condition: sel
`);
    expect(rule.detection.selections[0]).toEqual<SigmaSelection>({
      kind: "list",
      name: "sel",
      alternatives: [
        [
          { field: "Image", modifiers: ["endswith"], values: ["\\a.exe"] },
          { field: "CommandLine", modifiers: ["contains"], values: ["x"] },
        ],
        [{ field: "Image", modifiers: ["endswith"], values: ["\\b.exe"] }],
      ],
    });
  });

  it("parses a list of bare strings as keywords", () => {
    const rule = parsed(`
title: T
logsource:
  product: windows
detection:
  keywords:
    - 'mimikatz'
    - 'sekurlsa::'
  condition: keywords
`);
    expect(rule.detection.selections[0]).toEqual<SigmaSelection>({
      kind: "keywords",
      name: "keywords",
      values: ["mimikatz", "sekurlsa::"],
    });
  });

  it("keeps numbers and booleans typed, and keeps string bytes exact", () => {
    const rule = parsed(`
title: T
logsource:
  category: network_connection
detection:
  sel:
    DestinationPort: 4444
    Initiated: true
    Image: "C:\\\\Windows\\\\*.exe\\t"
  condition: sel
`);
    const sel = rule.detection.selections[0];
    if (sel.kind !== "map") throw new Error("expected map");
    expect(sel.fields.map((f) => f.values)).toEqual([[4444], [true], ["C:\\Windows\\*.exe\t"]]);
  });

  it("refuses a list that mixes maps and scalars", () => {
    const r = refusals(`
title: T
logsource:
  category: process_creation
detection:
  sel:
    - Image: a
    - 'bare keyword'
  condition: sel
`);
    expect(r).toEqual([{ path: "detection.sel", message: expect.stringMatching(/mix/i) }]);
  });

  it("refuses a null value by name", () => {
    const r = refusals(`
title: T
logsource:
  category: process_creation
detection:
  sel:
    Image: null
  condition: sel
`);
    expect(r).toEqual([{ path: "detection.sel.Image", message: expect.stringMatching(/null/i) }]);
  });

  it(`refuses more than ${SIGMA_MAX_SELECTIONS} selections and more than ${SIGMA_MAX_VALUES_PER_SELECTION} values`, () => {
    const many = Array.from(
      { length: SIGMA_MAX_SELECTIONS + 1 },
      (_, i) => `  s${i}:\n    Image: x${i}`,
    ).join("\n");
    expect(paths(`title: T\nlogsource:\n  category: c\ndetection:\n${many}\n  condition: 1 of s*\n`)).toEqual(
      ["detection"],
    );
    const values = Array.from({ length: SIGMA_MAX_VALUES_PER_SELECTION + 1 }, (_, i) => `      - v${i}`).join(
      "\n",
    );
    expect(
      paths(
        `title: T\nlogsource:\n  category: c\ndetection:\n  sel:\n    Image:\n${values}\n  condition: sel\n`,
      ),
    ).toEqual(["detection.sel"]);
  });
});

describe("parseSigmaRule — a selection that matches nothing is refused (#806)", () => {
  const withDetection = (detection: string) =>
    `title: T\nlogsource:\n  category: process_creation\ndetection:\n${detection}`;

  it("refuses an empty selection map at the selection's path", () => {
    expect(refusals(withDetection("  sel: {}\n  condition: sel\n"))).toEqual([
      { path: "detection.sel", message: expect.stringMatching(/no fields.*matches nothing/) },
    ]);
  });

  it("refuses an empty map inside a selection list, naming the entry", () => {
    const r = refusals(withDetection("  sel:\n    - {}\n    - Image: x\n  condition: sel\n"));
    expect(r).toEqual([
      { path: "detection.sel[0]", message: expect.stringMatching(/no fields.*matches nothing/) },
    ]);
    // A list whose maps all carry fields still parses as alternatives.
    const rule = parsed(withDetection("  sel:\n    - Image: x\n    - Image: y\n  condition: sel\n"));
    expect(rule.detection.selections[0].kind).toBe("list");
  });

  it("refuses '1 of them' and 'all of them' when the rule defines no selection", () => {
    for (const condition of ["1 of them", "all of them", "not 1 of them"]) {
      expect(refusals(withDetection(`  condition: ${condition}\n`))).toEqual([
        { path: "detection.condition", message: expect.stringMatching(/'them'.*defines none/) },
      ]);
    }
    // With one selection defined, `them` resolves to it as before.
    const rule = parsed(withDetection("  sel:\n    Image: x\n  condition: 1 of them\n"));
    expect(rule.detection.condition).toEqual({ kind: "oneOf", names: ["sel"] });
  });
});

describe("parseSigmaRule — modifiers", () => {
  const withField = (key: string, value: string) => `
title: T
logsource:
  category: process_creation
detection:
  sel:
    ${key}: ${value}
  condition: sel
`;

  it("accepts every supported modifier", () => {
    for (const key of [
      "Image|contains",
      "Image|startswith",
      "Image|endswith",
      "Image|contains|all",
      "Image|re",
      "DestinationIp|cidr",
      "Port|gt",
      "Port|gte",
      "Port|lt",
      "Port|lte",
    ]) {
      const value = key.endsWith("|cidr") ? "'10.0.0.0/8'" : /\|(gt|gte|lt|lte)$/.test(key) ? "1024" : "'x'";
      expect(parseSigmaRule(withField(key, value)).ok, key).toBe(true);
    }
  });

  it("refuses every unsupported modifier by name, one refusal per field", () => {
    for (const mod of [
      "base64",
      "base64offset",
      "utf16le",
      "utf16be",
      "utf16",
      "wide",
      "windash",
      "fieldref",
      "expand",
      "exists",
      "madeup",
    ]) {
      const r = refusals(withField(`CommandLine|${mod}`, "'x'"));
      expect(r, mod).toEqual([
        { path: `detection.sel.CommandLine|${mod}`, message: expect.stringContaining(mod) },
      ]);
    }
  });

  it("mutation: swapping one supported modifier for an unknown one turns an accepted rule into a refusal that names it", () => {
    for (const good of ["contains", "startswith", "endswith", "re"]) {
      expect(parseSigmaRule(withField(`Image|${good}`, "'x'")).ok).toBe(true);
      const r = refusals(withField(`Image|${good}x`, "'x'"));
      expect(r[0].message).toContain(`${good}x`);
    }
  });

  it("refuses a numeric modifier on a non-numeric value", () => {
    const r = refusals(withField("Port|gt", "'abc'"));
    expect(r).toEqual([{ path: "detection.sel.Port|gt", message: expect.stringMatching(/number/i) }]);
  });

  it("refuses a cidr value that is not a CIDR", () => {
    const r = refusals(withField("DestinationIp|cidr", "'10.0.0.1'"));
    expect(r).toEqual([{ path: "detection.sel.DestinationIp|cidr", message: expect.stringMatching(/CIDR/) }]);
  });

  it(`refuses a re value over ${SIGMA_MAX_REGEX_LENGTH} chars`, () => {
    const r = refusals(withField("Image|re", `'${"a".repeat(SIGMA_MAX_REGEX_LENGTH + 1)}'`));
    expect(r[0].path).toBe("detection.sel.Image|re");
    expect(r[0].message).toMatch(new RegExp(String(SIGMA_MAX_REGEX_LENGTH)));
  });

  it("accepts a leading RE2 inline flag group on a re value, which JavaScript's RegExp would reject", () => {
    expect(parseSigmaRule(withField("CommandLine|re", "'(?i)-enc\\s+[A-Za-z0-9+/=]{20,}'")).ok).toBe(true);
    expect(parseSigmaRule(withField("CommandLine|re", "'(?is)a.b'")).ok).toBe(true);
    expect(refusals(withField("CommandLine|re", "'(?i)^(a|aa)+b$'"))[0].path).toBe(
      "detection.sel.CommandLine|re",
    );
  });

  it("refuses a catastrophic re value through checkRegexSafety, with its reason", () => {
    const r = refusals(withField("Image|re", "'^(a|aa)+b$'"));
    expect(r[0].path).toBe("detection.sel.Image|re");
    expect(r[0].message.length).toBeGreaterThan(10);
  });
});

describe("parseSigmaRule — condition", () => {
  const withCondition = (condition: string, extra = "") => `
title: T
logsource:
  category: process_creation
detection:
  sel_a:
    Image: a
  sel_b:
    Image: b
  filter:
    Image: c
${extra}  condition: ${condition}
`;

  it("parses and / or / not with precedence not > and > or, and parentheses", () => {
    const rule = parsed(withCondition("sel_a or sel_b and not filter"));
    expect(rule.detection.condition).toEqual({
      kind: "or",
      operands: [
        { kind: "ref", name: "sel_a" },
        {
          kind: "and",
          operands: [
            { kind: "ref", name: "sel_b" },
            { kind: "not", operand: { kind: "ref", name: "filter" } },
          ],
        },
      ],
    });
    const grouped = parsed(withCondition("(sel_a or sel_b) and not filter"));
    expect(grouped.detection.condition).toEqual({
      kind: "and",
      operands: [
        {
          kind: "or",
          operands: [
            { kind: "ref", name: "sel_a" },
            { kind: "ref", name: "sel_b" },
          ],
        },
        { kind: "not", operand: { kind: "ref", name: "filter" } },
      ],
    });
  });

  it("resolves '1 of sel_*' and 'all of sel_*' to the selection names they match, so the compiler sees no wildcards", () => {
    expect(parsed(withCondition("1 of sel_*")).detection.condition).toEqual({
      kind: "oneOf",
      names: ["sel_a", "sel_b"],
    });
    expect(parsed(withCondition("all of sel_*")).detection.condition).toEqual({
      kind: "allOf",
      names: ["sel_a", "sel_b"],
    });
  });

  it("resolves '1 of them' and 'all of them' to every selection", () => {
    expect(parsed(withCondition("1 of them")).detection.condition).toEqual({
      kind: "oneOf",
      names: ["sel_a", "sel_b", "filter"],
    });
    expect(parsed(withCondition("all of them and not filter")).detection.condition).toEqual({
      kind: "and",
      operands: [
        { kind: "allOf", names: ["sel_a", "sel_b", "filter"] },
        { kind: "not", operand: { kind: "ref", name: "filter" } },
      ],
    });
  });

  it("refuses a condition that names a selection that does not exist, and a wildcard that matches none", () => {
    expect(refusals(withCondition("sel_a and nope"))).toEqual([
      { path: "detection.condition", message: expect.stringContaining("nope") },
    ]);
    expect(refusals(withCondition("1 of zzz_*"))[0].message).toContain("zzz_*");
  });

  it("refuses 'N of' with N other than 1", () => {
    expect(refusals(withCondition("2 of sel_*"))[0].message).toMatch(/1 of|all of/);
  });

  it("refuses aggregations, near, and timeframe by name", () => {
    expect(refusals(withCondition("sel_a | count() by Image > 3"))[0].message).toMatch(/aggregat/i);
    expect(refusals(withCondition("sel_a | near sel_b"))[0].message).toMatch(/near/i);
    expect(refusals(withCondition("sel_a", "  timeframe: 5m\n"))).toEqual([
      { path: "detection.timeframe", message: expect.stringMatching(/timeframe/i) },
    ]);
  });

  it("refuses a missing condition and a condition given as a list", () => {
    expect(paths(`title: T\nlogsource:\n  category: c\ndetection:\n  sel:\n    Image: a\n`)).toEqual([
      "detection.condition",
    ]);
    expect(
      paths(
        `title: T\nlogsource:\n  category: c\ndetection:\n  sel:\n    Image: a\n  condition:\n    - sel\n`,
      ),
    ).toEqual(["detection.condition"]);
  });

  it("refuses unbalanced parentheses and trailing garbage with the position", () => {
    expect(refusals(withCondition("(sel_a and sel_b"))[0].message).toMatch(/\)/);
    expect(refusals(withCondition("sel_a sel_b"))[0].message).toMatch(/unexpected/i);
  });
});

describe("parseSigmaRule — refusals are complete, and parsing is deterministic", () => {
  it("reports every problem in one list, in document order", () => {
    const r = refusals(`
title: T
logsource:
  category: process_creation
detection:
  sel_a:
    CommandLine|base64: x
    Image: null
  sel_b:
    - Image: a
    - 'kw'
  condition: sel_a and missing
`);
    expect(r.map((x) => x.path)).toEqual([
      "detection.sel_a.CommandLine|base64",
      "detection.sel_a.Image",
      "detection.sel_b",
      "detection.condition",
    ]);
  });

  it("writes refusal messages for an analyst: a sentence, no stack, no 'undefined'", () => {
    for (const { message } of refusals(
      `title: T\nlogsource:\n  category: c\ndetection:\n  sel:\n    Image|base64: x\n  condition: sel\n`,
    )) {
      expect(message).not.toMatch(/undefined|\bat\s+\w+\.(ts|js)/);
      expect(message.length).toBeGreaterThan(15);
    }
  });

  it("parses the dashboard draft shape in full", () => {
    const rule = parsed(DASHBOARD_DRAFT);
    expect(rule.detection.selections.map((s) => s.name)).toEqual([
      "sel_process",
      "sel_hash",
      "sel_network_ip",
      "sel_network_domain",
      "sel_file_path",
    ]);
    expect(rule.detection.condition).toEqual({
      kind: "oneOf",
      names: ["sel_process", "sel_hash", "sel_network_ip", "sel_network_domain", "sel_file_path"],
    });
    expect(rule.level).toBe("high");
  });

  it("gives deep-equal results on two parses of the same text", () => {
    expect(parseSigmaRule(DASHBOARD_DRAFT)).toEqual(parseSigmaRule(DASHBOARD_DRAFT));
  });
});
