import { describe, it, expect } from "vitest";
import { parseCapaResult, isCapaResult } from "../../src/analysis/capaResultImport.js";

// Field names/shapes verified live against a real serialized capa 9.4.0 static report
// (DefectDojo/django-DefectDojo's own test fixture, unittests/scans/capa/one_finding.json).
const SAMPLE = {
  md5: "7a450304b58917290f54ffbdccb095b6",
  sha1: "db054d79d4d913671732d9ff696dca69f911601a",
  sha256: "afed46612dce2c6fa48d95192426366dcc0a4517f4b56240f0c8e39a5104748a",
  path: "samples/sample.dll",
};

function meta(overrides: Record<string, unknown> = {}) {
  return {
    timestamp: "2026-08-08T20:30:07.562894",
    version: "9.4.0",
    argv: ["-j", "sample.dll"],
    sample: SAMPLE,
    flavor: "static",
    analysis: { format: "dotnet", arch: "amd64", os: "any", extractor: "DnfileFeatureExtractor" },
    ...overrides,
  };
}

// A minimal, realistic OR-node match: one failed leaf, one successful leaf with its own location.
function cliMatch(outerValue: number) {
  return [
    { type: "dn token", value: outerValue },
    {
      success: true,
      node: { type: "statement", statement: { type: "or" } },
      children: [
        {
          success: false,
          node: { type: "feature", feature: { type: "api", api: "GetCommandLine" } },
          children: [],
          locations: [],
          captures: {},
        },
        {
          success: true,
          node: { type: "feature", feature: { type: "api", api: "System.Environment::GetCommandLineArgs" } },
          children: [],
          locations: [{ type: "dn token offset", value: [outerValue, 0] }],
          captures: {},
        },
      ],
      locations: [],
      captures: {},
    },
  ];
}

function cliRule(matches: unknown[] = [cliMatch(100663300)]) {
  return {
    meta: {
      name: "accept command line arguments",
      namespace: "host-interaction/cli",
      authors: ["user@example.org"],
      scopes: { static: "function", dynamic: "call" },
      attack: [
        {
          parts: ["Execution", "Command and Scripting Interpreter"],
          tactic: "Execution",
          technique: "Command and Scripting Interpreter",
          subtechnique: "",
          id: "T1059",
        },
      ],
      mbc: [
        {
          parts: ["Execution"],
          objective: "Execution",
          behavior: "Command and Scripting Interpreter",
          method: "",
          id: "E1059",
        },
      ],
      references: [],
      examples: ["e5369ac309f1be6d77afeeb3edab0ed8:0x402760"],
      description: "",
      lib: false,
      is_subscope_rule: false,
      maec: {},
    },
    source: "rule:\n  meta:\n    name: accept command line arguments\n",
    matches,
  };
}

function packerRule(
  matches: unknown[] = [
    [
      { type: "no address" },
      {
        success: true,
        node: { type: "feature", feature: { type: "string", string: "UPX!" } },
        children: [],
        locations: [],
        captures: {},
      },
    ],
  ],
) {
  return {
    meta: {
      name: "packed with UPX",
      namespace: "anti-analysis/packer/upx",
      authors: ["user@example.org"],
      scopes: { static: "file", dynamic: "file" },
      attack: [],
      mbc: [
        {
          parts: ["Anti-Behavioral Analysis"],
          objective: "Anti-Behavioral Analysis",
          behavior: "Executable File Format Manipulation",
          method: "",
          id: "B0006",
        },
      ],
      references: [],
      examples: [],
      description: "",
      lib: false,
      is_subscope_rule: false,
      maec: {},
    },
    source: "rule:\n  meta:\n    name: packed with UPX\n",
    matches,
  };
}

function floss(rules: Record<string, unknown>, metaOverrides: Record<string, unknown> = {}): string {
  return JSON.stringify({ meta: meta(metaOverrides), rules });
}

describe("isCapaResult", () => {
  it("recognizes a real capa static results document", () => {
    expect(isCapaResult(JSON.parse(floss({ "accept command line arguments": cliRule() })))).toBe(true);
  });

  it("rejects a dynamic-flavor report", () => {
    expect(isCapaResult(JSON.parse(floss({}, { flavor: "dynamic" })))).toBe(false);
  });

  it("rejects a report missing a sample hash field", () => {
    const bad = JSON.parse(floss({}));
    delete bad.meta.sample.sha256;
    expect(isCapaResult(bad)).toBe(false);
  });

  it("accepts a static report with zero matched rules", () => {
    expect(isCapaResult(JSON.parse(floss({})))).toBe(true);
  });

  it("rejects a plain unrelated JSON object", () => {
    expect(isCapaResult({ hello: "world" })).toBe(false);
  });
});

describe("parseCapaResult — extracting evidence from a range statement (Codex code review finding)", () => {
  it("cites a successful range statement, whose location lives on the STATEMENT match, not a nested feature", () => {
    const rangeMatch: unknown[] = [
      { type: "no address" },
      {
        success: true,
        node: { type: "statement", statement: { type: "range", min: 2, max: 10 } },
        children: [
          {
            success: true,
            node: { type: "feature", feature: { type: "string", string: "cmd.exe" } },
            children: [],
            locations: [],
            captures: {},
          },
        ],
        locations: [{ type: "absolute", value: 4096 }],
        captures: {},
      },
    ];
    const r = parseCapaResult(floss({ "accept command line arguments": cliRule([rangeMatch]) }))!;
    expect(r.events).toHaveLength(1);
    const block = r.events[0].canonical!.capaMatch!;
    expect(block.evidence.length).toBeGreaterThanOrEqual(1);
    const rangeEvidence = block.evidence.find((e) => e.featureType === "statement:range");
    expect(rangeEvidence).toBeDefined();
    expect(rangeEvidence?.locations).toEqual([{ type: "absolute", value: 4096 }]);
  });
});

describe("parseCapaResult — a single rule match", () => {
  it("maps to an Info-severity, undated capability-match event with bounded evidence from the match tree, not just the outer address", () => {
    const r = parseCapaResult(floss({ "accept command line arguments": cliRule() }));
    expect(r).not.toBeNull();
    expect(r!.events).toHaveLength(1);
    const e = r!.events[0];
    expect(e.severity).toBe("Info");
    expect(e.timestamp).toBe("");
    const block = e.canonical!.capaMatch!;
    expect(block.ruleName).toBe("accept command line arguments");
    expect(block.ruleNamespace).toBe("host-interaction/cli");
    expect(block.evidence).toHaveLength(1); // only the SUCCESSFUL leaf feature
    expect(block.evidence[0].featureType).toBe("api");
    expect(block.evidence[0].detail).toContain("GetCommandLineArgs");
    expect(block.evidence[0].locations).toEqual([{ type: "dn token offset", value: [100663300, 0] }]);
    expect(e.description).toContain("not a verdict");
  });

  it("surfaces the ATT&CK id onto the event's own top-level mitre field", () => {
    const r = parseCapaResult(floss({ "accept command line arguments": cliRule() }))!;
    expect(r.events[0].mitreTechniques).toEqual(["T1059"]);
  });

  it("normalizes an empty subtechnique/method string to absent, not an empty string, at the canonical layer", () => {
    const r = parseCapaResult(floss({ "accept command line arguments": cliRule() }))!;
    const block = r.events[0].canonical!.capaMatch!;
    expect(block.attack[0].subtechnique).toBeUndefined();
    expect(block.mbc[0].method).toBeUndefined();
  });

  it("records the SAME mappingVersion on the canonical block and the producer metadata", () => {
    const r = parseCapaResult(floss({ "accept command line arguments": cliRule() }))!;
    const e = r.events[0];
    expect(e.canonical!.capaMatch!.mappingVersion).toBe("capa-rule-match-v1");
    expect(e.canonical!.producer.mappingVersion).toBe(e.canonical!.capaMatch!.mappingVersion);
  });

  it("fingerprints the rule's own YAML source, never copies it verbatim", () => {
    const r = parseCapaResult(floss({ "accept command line arguments": cliRule() }))!;
    const block = r.events[0].canonical!.capaMatch!;
    expect(block.ruleSourceFingerprint).toMatch(/^[a-f0-9]{64}$/);
  });
});

describe("parseCapaResult — sample hash and correlation", () => {
  it("validates, lowercases, and registers every valid hash as its own IOC linked to the event", () => {
    const r = parseCapaResult(floss({ "accept command line arguments": cliRule() }))!;
    const hashIocs = r.iocs.filter((i) => i.type === "hash").map((i) => i.value);
    expect(hashIocs).toContain(SAMPLE.md5);
    expect(hashIocs).toContain(SAMPLE.sha1);
    expect(hashIocs).toContain(SAMPLE.sha256);
    const sha256Ioc = r.iocs.find((i) => i.type === "hash" && i.value === SAMPLE.sha256);
    expect(sha256Ioc?.sourceAggKeys).toEqual([r.events[0].aggKey]);
  });

  it("treats a malformed sample hash as absent, sets hashUnavailable only when none validate", () => {
    const r = parseCapaResult(
      floss(
        { "accept command line arguments": cliRule() },
        { sample: { ...SAMPLE, md5: "not-a-hash", sha1: "not-a-hash", sha256: "not-a-hash" } },
      ),
    )!;
    const block = r.events[0].canonical!.capaMatch!;
    expect(block.sampleHash.hashUnavailable).toBe(true);
    expect(r.iocs.some((i) => i.type === "hash")).toBe(false);
  });
});

describe("parseCapaResult — report identity (learned directly from item 4/5's own lesson)", () => {
  it("gives two separate reports different aggKeys and different descriptions even with identical rule matches", () => {
    const r1 = parseCapaResult(floss({ "accept command line arguments": cliRule() }))!;
    const r2 = parseCapaResult(
      floss({ "accept command line arguments": cliRule() }, { argv: ["-j", "other.dll"] }),
    )!;
    expect(r1.events[0].aggKey).not.toBe(r2.events[0].aggKey);
    expect(r1.events[0].description).not.toBe(r2.events[0].description);
  });
});

describe("parseCapaResult — the composite inspection lead", () => {
  it("does NOT create a composite lead for a packer match alone (legitimate/commercial software also packs)", () => {
    const r = parseCapaResult(floss({ "packed with UPX": packerRule() }))!;
    expect(r.events).toHaveLength(1);
    expect(r.events.some((e) => e.canonical?.capaCompositeLead)).toBe(false);
    expect(r.events[0].severity).toBe("Info");
  });

  it("does NOT create a composite lead for a capability match alone (no anti-analysis signal)", () => {
    const r = parseCapaResult(floss({ "accept command line arguments": cliRule() }))!;
    expect(r.events.some((e) => e.canonical?.capaCompositeLead)).toBe(false);
  });

  it("creates exactly ONE Low-severity composite lead when a packer match co-occurs with a capability match, naming the contributing rules — never higher than Low", () => {
    const r = parseCapaResult(
      floss({ "packed with UPX": packerRule(), "accept command line arguments": cliRule() }),
    )!;
    const leads = r.events.filter((e) => e.canonical?.capaCompositeLead);
    expect(leads).toHaveLength(1);
    expect(leads[0].severity).toBe("Low");
    const block = leads[0].canonical!.capaCompositeLead!;
    expect(block.contributingFamilies.sort()).toEqual(["anti-analysis", "host-interaction"].sort());
    expect(block.contributingRules).toContain("packed with UPX");
    expect(block.contributingRules).toContain("accept command line arguments");
    // The per-rule Info rows are UNCHANGED — still present, still Info.
    expect(r.events.filter((e) => e.canonical?.capaMatch).every((e) => e.severity === "Info")).toBe(true);
  });

  it("the composite lead's own description states it is an inspection lead, not a verdict", () => {
    const r = parseCapaResult(
      floss({ "packed with UPX": packerRule(), "accept command line arguments": cliRule() }),
    )!;
    const lead = r.events.find((e) => e.canonical?.capaCompositeLead)!;
    expect(lead.description).toContain("not a verdict");
  });

  it("a rule literally named 'composite-lead' never collides with the report's own composite-lead aggKey (Codex code review finding)", () => {
    const collidingRule = cliRule();
    const r = parseCapaResult(
      floss({
        "packed with UPX": packerRule(),
        "composite-lead": collidingRule,
      }),
    )!;
    // The real rule (namespace host-interaction/cli) plus the packer rule (anti-analysis) still
    // triggers exactly one composite lead, and BOTH per-rule rows survive alongside it.
    expect(r.events).toHaveLength(3);
    expect(r.events.filter((e) => e.canonical?.capaCompositeLead)).toHaveLength(1);
    expect(r.events.filter((e) => e.canonical?.capaMatch)).toHaveLength(2);
    const aggKeys = r.events.map((e) => e.aggKey);
    expect(new Set(aggKeys).size).toBe(3); // no collision
  });
});

describe("parseCapaResult — address validation (static-only)", () => {
  it("rejects a process/thread/call address (dynamic-analysis-only) — the WHOLE tuple is malformed, never silently accepted with just the address dropped", () => {
    const badMatch: unknown[] = [
      { type: "process", value: [1, 2] },
      {
        success: true,
        node: { type: "feature", feature: { type: "os", os: "windows" } },
        children: [],
        locations: [{ type: "absolute", value: 1 }],
        captures: {},
      },
    ];
    const r = parseCapaResult(
      floss({ "accept command line arguments": cliRule([badMatch, cliMatch(100663300)]) }),
    )!;
    expect(r.events).toHaveLength(1);
    const block = r.events[0].canonical!.capaMatch!;
    expect(block.occurrences).toBe(1); // only the good tuple counted, the bad one is malformed
    expect(block.outerLocations).toEqual([{ type: "dn token", value: 100663300 }]);
  });

  it("rejects a match tuple whose root itself did not succeed, even with an otherwise-valid address", () => {
    const failedMatch: unknown[] = [
      { type: "absolute", value: 1 },
      {
        success: false,
        node: { type: "feature", feature: { type: "os", os: "windows" } },
        children: [],
        locations: [],
        captures: {},
      },
    ];
    const r = parseCapaResult(floss({ "accept command line arguments": cliRule([failedMatch]) }))!;
    expect(r.events).toHaveLength(0);
    expect(r.malformedMatches).toBe(1);
  });

  it("accepts a file-scope rule whose outer address is literally 'no address'", () => {
    const r = parseCapaResult(floss({ "packed with UPX": packerRule() }))!;
    const block = r.events[0].canonical!.capaMatch!;
    expect(block.outerLocations).toEqual([{ type: "no address", value: null }]);
  });

  it("never crashes on a malformed address object", () => {
    const matches = [
      [
        { type: "absolute", value: "not-a-number" },
        {
          success: true,
          node: { type: "feature", feature: { type: "number", number: 1 } },
          children: [],
          locations: [],
          captures: {},
        },
      ],
    ];
    expect(() => parseCapaResult(floss({ "accept command line arguments": cliRule(matches) }))).not.toThrow();
  });
});

describe("parseCapaResult — malformed rules and reports", () => {
  it("counts a rule entry missing 'source' as malformed, never crashes, disclosed via dropped/malformedRules", () => {
    const badEntry = { meta: cliRule().meta, matches: [] }; // no `source`
    const r = parseCapaResult(floss({ "bad rule": badEntry, "accept command line arguments": cliRule() }))!;
    expect(r.events).toHaveLength(1);
    expect(r.malformedRules).toBe(1);
    expect(r.dropped).toBe(1);
  });

  it("counts a rule whose matches produced zero valid occurrences as malformed too", () => {
    const emptyMatches = cliRule([]);
    const r = parseCapaResult(floss({ "accept command line arguments": emptyMatches }))!;
    expect(r.events).toHaveLength(0);
    expect(r.malformedRules).toBe(1);
  });

  it("never crashes on a deeply nested match tree, bounded by depth", () => {
    let node: unknown = {
      success: true,
      node: { type: "feature", feature: { type: "number", number: 1 } },
      children: [],
      locations: [],
      captures: {},
    };
    for (let i = 0; i < 100; i++) {
      node = {
        success: true,
        node: { type: "statement", statement: { type: "and" } },
        children: [node],
        locations: [],
        captures: {},
      };
    }
    const matches = [[{ type: "no address" }, node]];
    expect(() => parseCapaResult(floss({ "accept command line arguments": cliRule(matches) }))).not.toThrow();
  });

  it("returns null for text that isn't valid JSON", () => {
    expect(parseCapaResult("not json at all")).toBeNull();
  });

  it("returns null for valid JSON that isn't a capa document", () => {
    expect(parseCapaResult(JSON.stringify({ hello: "world" }))).toBeNull();
  });
});

describe("parseCapaResult — duplicate vs distinct occurrences", () => {
  it("counts two match tuples as two occurrences but dedupes byte-identical evidence into one citation", () => {
    const matches = [cliMatch(100663300), cliMatch(100663300)];
    const r = parseCapaResult(floss({ "accept command line arguments": cliRule(matches) }))!;
    const block = r.events[0].canonical!.capaMatch!;
    expect(block.occurrences).toBe(2);
    expect(block.evidence).toHaveLength(1);
  });

  it("keeps evidence from two match tuples at DIFFERENT locations as distinct citations", () => {
    const matches = [cliMatch(100663300), cliMatch(999)];
    const r = parseCapaResult(floss({ "accept command line arguments": cliRule(matches) }))!;
    const block = r.events[0].canonical!.capaMatch!;
    expect(block.occurrences).toBe(2);
    expect(block.evidence).toHaveLength(2);
    expect(block.notCitedEvidence).toBe(0);
  });
});
