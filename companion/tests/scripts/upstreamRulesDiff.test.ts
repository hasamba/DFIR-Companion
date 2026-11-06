import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  UPSTREAM_GROUPS,
  compareGroup,
  diffList,
  groupChanged,
  isEventFile,
  issueTitle,
  parseCsv,
  readRecordedCommit,
  renderReport,
  summariseEventFile,
  type FetchFile,
  type ListFiles,
} from "../../scripts/upstreamRulesDiff.mjs";

// The weekly upstream rule-list check (#2343). The diff logic is pure, so it is tested on fixture
// CSV pairs; the tags.yaml test proves the workflow can read the recorded port commit.

const FENCE = "`".repeat(3);

const BASE = [
  '"UserAgent","Category","Severity"',
  '"AADInternals","Offensive Tool","Red"',
  '"agentaxios","Password Spraying Attack,AiTM","Red"',
  '"python/","Offensive Tool","Yellow"',
  '"Python/","Offensive Tool","Yellow"',
].join("\n");

describe("parseCsv", () => {
  it("handles quotes, embedded commas, doubled quotes and newlines inside quotes", () => {
    const rows = parseCsv('a,b\n"x, y","say ""hi"""\n"multi\nline",z\n');
    expect(rows).toEqual([
      ["a", "b"],
      ["x, y", 'say "hi"'],
      ["multi\nline", "z"],
    ]);
  });

  it("strips a BOM, accepts CRLF and a missing final newline, skips blank lines", () => {
    const rows = parseCsv('\uFEFF"h1","h2"\r\n"a","1"\r\n\r\n"b","2"');
    expect(rows).toEqual([
      ["h1", "h2"],
      ["a", "1"],
      ["b", "2"],
    ]);
  });

  it("throws on an unclosed quote rather than guessing", () => {
    expect(() => parseCsv('"a,b\n')).toThrow(/unclosed/);
  });
});

describe("diffList", () => {
  it("reports nothing for identical lists, even when only line endings and the BOM differ", () => {
    const head = `\uFEFF${BASE.replace(/\n/g, "\r\n")}\r\n`;
    const diff = diffList(BASE, head);
    expect(diff.added).toEqual([]);
    expect(diff.removed).toEqual([]);
    expect(diff.changed).toEqual([]);
    expect(diff.headerChanged).toBe(false);
  });

  it("reports added and removed entries, keyed case-sensitively on the first column", () => {
    const head = BASE.replace('"Python/","Offensive Tool","Yellow"', '"undici","Node.js, AiTM","Red"');
    const diff = diffList(BASE, head);
    expect(diff.added).toEqual([{ key: "undici", cells: ["undici", "Node.js, AiTM", "Red"] }]);
    expect(diff.removed.map((e) => e.key)).toEqual(["Python/"]);
    expect(diff.changed).toEqual([]);
  });

  it("reports a severity edit as changed, not as remove + add", () => {
    const head = BASE.replace('"python/","Offensive Tool","Yellow"', '"python/","Offensive Tool","Red"');
    const diff = diffList(BASE, head);
    expect(diff.added).toEqual([]);
    expect(diff.removed).toEqual([]);
    expect(diff.changed).toEqual([
      {
        key: "python/",
        before: ["python/", "Offensive Tool", "Yellow"],
        after: ["python/", "Offensive Tool", "Red"],
      },
    ]);
  });

  it("flags a header change", () => {
    const head = BASE.replace('"Severity"', '"Level"');
    expect(diffList(BASE, head).headerChanged).toBe(true);
  });

  it("refuses an empty file instead of reporting every entry removed", () => {
    expect(() => diffList(BASE, "", "UserAgent-Blacklist.csv")).toThrow(/UserAgent-Blacklist\.csv/);
  });
});

describe("compareGroup", () => {
  const group = UPSTREAM_GROUPS[0];
  const sha = (c: string) => c.repeat(40);

  it("skips fetching when the recorded commit is already the newest", async () => {
    let calls = 0;
    const fetchFile: FetchFile = async () => {
      calls += 1;
      return BASE;
    };
    const result = await compareGroup(group, sha("a"), sha("a"), fetchFile);
    expect(calls).toBe(0);
    expect(groupChanged(result)).toBe(false);
  });

  it("fails loudly when an upstream file is missing or renamed", async () => {
    const fetchFile: FetchFile = async (_repo, path, ref) => {
      if (ref === sha("b") && path.endsWith("UserAgent-Blacklist.csv")) {
        throw new Error(`HTTP 404 for ${path}`);
      }
      return BASE;
    };
    await expect(compareGroup(group, sha("a"), sha("b"), fetchFile)).rejects.toThrow(/404/);
  });

  it("renders one report per change set with the range and no closing keyword", async () => {
    const fetchFile: FetchFile = async (_repo, path, ref) =>
      ref === sha("b") && path.endsWith("UserAgent-Blacklist.csv")
        ? `${BASE}\n"evil${FENCE}ua","x","Red"`
        : BASE;
    const result = await compareGroup(group, sha("a"), sha("b"), fetchFile);
    expect(groupChanged(result)).toBe(true);
    const body = renderReport([result]);
    expect(body).toContain(`compare/${sha("a")}...${sha("b")}`);
    expect(body).toContain("UserAgent-Blacklist.csv — 1 added, 0 removed, 0 changed");
    expect(body).not.toContain(`evil${FENCE}ua`);
    expect(body).not.toMatch(/\b(close[sd]?|fix(e[sd])?|resolve[sd]?)\b[^\n]{0,20}#\d+/i);
    expect(issueTitle([result])).toContain("[upstream-rules analyzer-suite@aaaaaaa]");
  });
});

describe("event-file groups — TrailDiscover (#2345)", () => {
  const group = UPSTREAM_GROUPS.find((g) => g.id === "traildiscover")!;
  const sha = (c: string) => c.repeat(40);
  const event = (o: Record<string, unknown>) =>
    JSON.stringify({
      eventName: "DeleteInvitations",
      eventSource: "guardduty.amazonaws.com",
      mitreAttackTechniques: ["T1562 - Impair Defenses"],
      mitreAttackSubTechniques: ["T1562.001 - Impair Defenses: Disable or Modify Tools"],
      usedInWild: true,
      incidents: [],
      ...o,
    });
  const GD = "events/GuardDuty/DeleteInvitations.json";
  const SES = "events/SES/PutAccountDetails.json";
  const OLD = "events/S3/GetBucketAcl.json";
  const NEW = "events/Bedrock/PutUseCaseForModelAccess.json";
  // Base and head trees (path → blob sha) and the file text at each blob.
  const trees: Record<string, Map<string, string>> = {
    [sha("a")]: new Map([
      [GD, "b1"],
      [SES, "s1"],
      [OLD, "o1"],
      [`${GD}.cloudtrail`, "c1"],
      ["events/README.md", "r1"],
    ]),
    [sha("b")]: new Map([
      [GD, "b2"],
      [SES, "s2"],
      [NEW, "n1"],
      [`${GD}.cloudtrail`, "c2"],
    ]),
  };
  const blobs: Record<string, string> = {
    b1: event({}),
    b2: event({ usedInWild: false }),
    s1: event({ eventName: "PutAccountDetails", eventSource: "ses.amazonaws.com", incidents: [] }),
    s2: event({
      eventName: "PutAccountDetails",
      eventSource: "ses.amazonaws.com",
      incidents: [{ description: "a new write-up", link: "https://example.com/x" }],
    }),
    o1: event({ eventName: "GetBucketAcl", eventSource: "s3.amazonaws.com" }),
    n1: event({ eventName: "PutUseCaseForModelAccess", eventSource: "bedrock.amazonaws.com" }),
  };
  const listFiles: ListFiles = async (_repo, _dir, ref) => trees[ref];
  const fetched: string[] = [];
  const fetchFile: FetchFile = async (_repo, path, ref) => {
    fetched.push(`${path}@${ref.slice(0, 1)}`);
    const blob = trees[ref].get(path);
    if (!blob) throw new Error(`HTTP 404 for ${path}`);
    return blobs[blob];
  };

  it("is watched on events/ with its own tags.yaml marker", () => {
    expect(group.kind).toBe("event-files");
    expect(group.watchPath).toBe("events");
    expect(group.marker).toBe("TrailDiscover upstream commit");
  });

  it("only counts <Service>/<Event>.json as an event file", () => {
    expect(isEventFile(GD, "events")).toBe(true);
    expect(isEventFile(`${GD}.cloudtrail`, "events")).toBe(false);
    expect(isEventFile("events/README.md", "events")).toBe(false);
    expect(isEventFile("events/a/b/c.json", "events")).toBe(false);
    expect(isEventFile("docs/events.json", "events")).toBe(false);
  });

  it("summarises the operation, usedInWild and the sorted ATT&CK ids — nothing else", () => {
    expect(summariseEventFile(event({}), GD)).toEqual([
      GD,
      "guardduty DeleteInvitations",
      "usedInWild=true",
      "mitre=T1562 T1562.001",
    ]);
    // A stray trailing colon upstream ("T1562.001:") still reads as the id.
    expect(summariseEventFile(event({ mitreAttackSubTechniques: ["T1562.001:"] }), GD)[3]).toBe(
      "mitre=T1562 T1562.001",
    );
    expect(() => summariseEventFile("{not json", GD)).toThrow(/not valid JSON/);
    expect(() => summariseEventFile("{}", GD)).toThrow(/no eventName/);
  });

  it("reports added, removed and flipped usedInWild files; ignores an incident-only edit", async () => {
    fetched.length = 0;
    const result = await compareGroup(group, sha("a"), sha("b"), fetchFile, listFiles);
    const diff = result.lists[0].diff;
    expect(diff.added.map((e) => e.key)).toEqual([NEW]);
    expect(diff.removed.map((e) => e.key)).toEqual([OLD]);
    expect(diff.changed.map((c) => [c.key, c.before[2], c.after[2]])).toEqual([
      [GD, "usedInWild=true", "usedInWild=false"],
    ]);
    expect(diff.headerChanged).toBe(false);
    expect(groupChanged(result)).toBe(true);
    // The .cloudtrail sample and README are never fetched.
    expect(fetched.some((f) => f.includes(".cloudtrail") || f.includes("README"))).toBe(false);
    const body = renderReport([result]);
    expect(body).toContain("#### events/ — 1 added, 1 removed, 1 changed");
    expect(body).toContain("bedrock PutUseCaseForModelAccess");
    expect(issueTitle([result])).toContain("[upstream-rules traildiscover@aaaaaaa]");
  });

  it("does not fetch an event file whose blob is unchanged", async () => {
    fetched.length = 0;
    const same: ListFiles = async () => new Map([[GD, "b1"]]);
    const result = await compareGroup(group, sha("a"), sha("b"), fetchFile, same);
    expect(fetched).toEqual([]);
    expect(groupChanged(result)).toBe(false);
  });

  it("fails loudly when the events folder is gone or listFiles is missing", async () => {
    const empty: ListFiles = async (_repo, _dir, ref) => (ref === sha("b") ? new Map() : trees[sha("a")]);
    await expect(compareGroup(group, sha("a"), sha("b"), fetchFile, empty)).rejects.toThrow(/no event files/);
    await expect(compareGroup(group, sha("a"), sha("b"), fetchFile)).rejects.toThrow(/needs listFiles/);
  });
});

describe("tags.yaml records the upstream commit each hand port came from", () => {
  const tagsYaml = readFileSync(new URL("../../data/tags.yaml", import.meta.url), "utf8");

  it.each(UPSTREAM_GROUPS.map((g) => [g.name, g] as const))(
    "%s: a 40-hex SHA and a valid date",
    (_name, group) => {
      const recorded = readRecordedCommit(tagsYaml, group.marker);
      expect(recorded.sha).toMatch(/^[0-9a-f]{40}$/);
      expect(Number.isNaN(Date.parse(recorded.date))).toBe(false);
    },
  );

  it("throws when the line is missing", () => {
    expect(() => readRecordedCommit("# nothing here", "Upstream commit")).toThrow(/no "# Upstream commit/);
  });
});
