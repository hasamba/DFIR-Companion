import { describe, expect, it } from "vitest";
import { createHash } from "node:crypto";
import {
  buildSigmaRuleSet,
  contentSha,
  matchSigmaRecord,
  normalizeRuleText,
  type SigmaRuleFile,
} from "../../src/analysis/sigmaRuleSet.js";
import { AWS_CLOUDTRAIL, type SigmaLogSourceDef } from "../../src/analysis/sigmaLogSources.js";

// Loading and indexing rules for the import-time engine (#2202), from in-memory rule texts so
// every outcome — loaded, filtered by status, disabled, refused, no log source — is pinned
// without the bundled release.

const META = { release: "r-test", commit: "abc123" };

function ruleText(o: {
  id: string;
  status?: string;
  level?: string;
  product?: string;
  service?: string;
  detection: string;
  condition?: string;
}): string {
  return [
    `title: Rule ${o.id}`,
    `id: ${o.id}`,
    `status: ${o.status ?? "test"}`,
    "author: Example Author",
    "logsource:",
    `  product: ${o.product ?? "aws"}`,
    `  service: ${o.service ?? "cloudtrail"}`,
    "detection:",
    o.detection,
    `  condition: ${o.condition ?? "sel"}`,
    `level: ${o.level ?? "high"}`,
    "tags:",
    "  - attack.defense-evasion",
    "  - attack.t1562.008",
    "",
  ].join("\n");
}

const file = (path: string, text: string): SigmaRuleFile => ({ path, text });

const STOP = file(
  "rules/cloud/aws/cloudtrail/stop.yml",
  ruleText({
    id: "stop",
    detection: "  sel:\n    eventSource: cloudtrail.amazonaws.com\n    eventName: StopLogging",
  }),
);

describe("buildSigmaRuleSet", () => {
  it("loads a rule whose fields the source maps, and records its metadata", () => {
    const set = buildSigmaRuleSet([STOP], META);
    expect(set.inventory.map((i) => [i.id, i.outcome])).toEqual([["stop", "loaded"]]);
    const m = matchSigmaRecord(set, "aws-cloudtrail", {
      eventSource: "cloudtrail.amazonaws.com",
      eventName: "StopLogging",
    });
    expect(m.matches.map((r) => r.ref)).toEqual([
      {
        id: "stop",
        title: "Rule stop",
        level: "high",
        status: "test",
        author: "Example Author",
        path: "rules/cloud/aws/cloudtrail/stop.yml",
        url: "https://github.com/SigmaHQ/sigma/blob/abc123/rules/cloud/aws/cloudtrail/stop.yml",
        release: "r-test",
        mitre: ["T1562.008"],
        huntingOnly: false,
        fields: ["eventsource", "eventname"],
      },
    ]);
  });

  it("filters out experimental rules by default", () => {
    const exp = file(
      "x.yml",
      ruleText({ id: "exp", status: "experimental", detection: "  sel:\n    eventName: X" }),
    );
    const set = buildSigmaRuleSet([exp], META);
    expect(set.inventory[0]).toMatchObject({ id: "exp", outcome: "status" });
    expect(matchSigmaRecord(set, "aws-cloudtrail", { eventName: "X" }).matches).toEqual([]);
  });

  it("honours the status list it is given", () => {
    const exp = file(
      "x.yml",
      ruleText({ id: "exp", status: "experimental", detection: "  sel:\n    eventName: X" }),
    );
    const set = buildSigmaRuleSet([exp], META, { statuses: ["experimental"] });
    expect(set.inventory[0].outcome).toBe("loaded");
  });

  it("skips a disabled rule and says why", () => {
    const set = buildSigmaRuleSet([STOP], META, { disabled: new Map([["stop", "noisy here"]]) });
    expect(set.inventory[0]).toMatchObject({ id: "stop", outcome: "disabled", reasons: ["noisy here"] });
  });

  it("refuses a rule that uses a field the source does not map, naming the field", () => {
    const bad = file(
      "bad.yml",
      ruleText({ id: "bad", detection: "  sel:\n    eventName: X\n    madeUpField: y" }),
    );
    const set = buildSigmaRuleSet([bad], META);
    expect(set.inventory[0]).toMatchObject({ id: "bad", outcome: "refused" });
    expect(set.inventory[0].reasons?.join(" ")).toMatch(/madeUpField.*AWS CloudTrail/);
  });

  it("refuses a rule the parser refuses, and one without a level", () => {
    const agg = file(
      "agg.yml",
      ruleText({ id: "agg", detection: "  sel:\n    eventName: X", condition: "sel | count() > 5" }),
    );
    const noLevel = file(
      "nolevel.yml",
      ruleText({ id: "nl", detection: "  sel:\n    eventName: X" }).replace(/^level: .*$/m, ""),
    );
    const set = buildSigmaRuleSet([agg, noLevel], META);
    expect(set.inventory.map((i) => i.outcome)).toEqual(["refused", "refused"]);
    expect(set.inventory[1].reasons?.join(" ")).toMatch(/level/);
  });

  it("reports a rule for a log source the Companion does not grade", () => {
    const gcp = file(
      "gcp.yml",
      ruleText({ id: "g", product: "gcp", service: "gcp.audit", detection: "  sel:\n    a: b" }),
    );
    expect(buildSigmaRuleSet([gcp], META).inventory[0].outcome).toBe("no-source");
  });

  it("grades a second log source with nothing but a registry entry", () => {
    const synthetic: SigmaLogSourceDef = {
      id: "test-src",
      label: "Test source",
      matches: (ls) => ls.product === "acme" && ls.service === "audit",
      fields: { exact: { action: ["act"] } },
      indexFields: ["action"],
      origins: ["Acme audit"],
    };
    const r = file(
      "acme.yml",
      ruleText({ id: "acme", product: "acme", service: "audit", detection: "  sel:\n    action: wipe" }),
    );
    const set = buildSigmaRuleSet([r], META, { sources: [AWS_CLOUDTRAIL, synthetic] });
    expect(matchSigmaRecord(set, "test-src", { act: "WIPE" }).matches.map((m) => m.ref.id)).toEqual(["acme"]);
  });
});

describe("matchSigmaRecord index", () => {
  const rules = [
    STOP,
    file("a.yml", ruleText({ id: "any-delete", detection: "  sel:\n    eventName|startswith: Delete" })),
    file(
      "b.yml",
      ruleText({ id: "either", detection: "  sel:\n    eventName:\n      - CreateUser\n      - DeleteUser" }),
    ),
    file("c.yml", ruleText({ id: "ua", detection: "  sel:\n    userAgent|contains: kali" })),
  ];
  const set = buildSigmaRuleSet(rules, META);

  it("finds the same matches the index-free evaluation would", () => {
    const records = [
      { eventName: "DeleteUser", userAgent: "aws-cli on kali" },
      { eventName: "CreateUser" },
      { eventSource: "cloudtrail.amazonaws.com", eventName: "stoplogging" },
      { eventName: "Other" },
    ];
    const got = records.map((r) =>
      matchSigmaRecord(set, "aws-cloudtrail", r)
        .matches.map((m) => m.ref.id)
        .sort(),
    );
    expect(got).toEqual([["any-delete", "either", "ua"], ["either"], ["stop"], []]);
  });

  it("returns nothing for an unknown source id", () => {
    expect(matchSigmaRecord(set, "nope", { eventName: "StopLogging" }).matches).toEqual([]);
  });

  it("counts an incomplete evaluation instead of matching it", () => {
    const filtered = buildSigmaRuleSet(
      [
        file(
          "n.yml",
          ruleText({
            id: "neg",
            detection: "  sel:\n    eventName: X\n  filter:\n    requestParameters.list: needle",
            condition: "sel and not filter",
          }),
        ),
      ],
      META,
    );
    const big = {
      eventName: "X",
      requestParameters: { list: Array.from({ length: 10_010 }, (_, i) => `v${i}`) },
    };
    const m = matchSigmaRecord(filtered, "aws-cloudtrail", big);
    expect(m.matches).toEqual([]);
    expect(m.incomplete).toBe(1);
  });
});

describe("threat-hunting rules and versioning (#2204)", () => {
  it("marks a rule under rules-threat-hunting/ hunting-only and records modified", () => {
    const text = ruleText({ id: "hunt", detection: "  sel:\n    eventName: X" }).replace(
      "author: Example Author",
      "author: Example Author\nmodified: 2025-02-03",
    );
    const set = buildSigmaRuleSet([file("rules-threat-hunting/cloud/aws/x.yml", text)], META);
    const ref = matchSigmaRecord(set, "aws-cloudtrail", { eventName: "X" }).matches[0].ref;
    expect(ref.huntingOnly).toBe(true);
    expect(ref.modified).toBe("2025-02-03");
  });
});

describe("duplicate rule ids (Codex review of #2204)", () => {
  it("refuses a later file with an id already loaded, naming the first file", () => {
    const first = file("rules/a.yml", ruleText({ id: "dup", detection: "  sel:\n    eventName: A" }));
    const second = file(
      "rules/b.yml",
      ruleText({ id: "dup", level: "critical", detection: "  sel:\n    eventName: B" }),
    );
    const set = buildSigmaRuleSet([first, second], META);
    expect(set.inventory.map((e) => e.outcome)).toEqual(["loaded", "refused"]);
    expect(set.inventory[1].reasons?.join(" ")).toMatch(/duplicate rule id.*rules\/a\.yml/);
    expect(matchSigmaRecord(set, "aws-cloudtrail", { eventName: "B" }).matches).toEqual([]);
  });
});

describe("contentSha line endings (#2215)", () => {
  const files = [
    file("rules/a.yml", ruleText({ id: "a", detection: "  sel:\n    eventName: A" })),
    file("rules/b.yml", ruleText({ id: "b", detection: "  sel:\n    eventName: B" })),
  ];
  const withEol = (eol: string) => files.map((f) => file(f.path, f.text.replace(/\n/g, eol)));
  // The pre-#2215 formula, over raw text. LF input must keep this exact value so the
  // provenance ids already in Linux/Docker reports stay valid.
  const legacySha = (list: readonly SigmaRuleFile[]) => {
    const hash = createHash("sha256");
    for (const f of [...list].sort((a, b) => (a.path < b.path ? -1 : 1)))
      hash.update(f.path).update("\0").update(f.text).update("\0");
    return hash.digest("hex").slice(0, 12);
  };

  it("gives CRLF, lone-CR and LF copies of the same rules one content id", () => {
    expect(contentSha(withEol("\r\n"))).toBe(contentSha(files));
    expect(contentSha(withEol("\r"))).toBe(contentSha(files));
  });

  it("keeps the previous value for LF input", () => {
    expect(contentSha(files)).toBe(legacySha(files));
  });

  it("still changes when the rule content changes", () => {
    const edited = [files[0], file("rules/b.yml", files[1].text.replace("eventName: B", "eventName: C"))];
    expect(contentSha(edited.map((f) => file(f.path, f.text.replace(/\n/g, "\r\n"))))).not.toBe(
      contentSha(files),
    );
  });

  it("normalizeRuleText converts CRLF and lone CR to LF and leaves LF text alone", () => {
    expect(normalizeRuleText("a\r\nb\rc\nd")).toBe("a\nb\nc\nd");
    expect(normalizeRuleText("a\nb\n")).toBe("a\nb\n");
  });
});
