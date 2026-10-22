import { describe, expect, it } from "vitest";
import { createZip } from "../../src/analysis/zipArchive.js";
import {
  diffSigmaReleases,
  readSigmaReleaseZip,
  SIGMA_RELEASE_MAX_ZIP_BYTES,
} from "../../src/analysis/sigmaReleaseArchive.js";

// Reading a SigmaHQ release zip (#2204): what is kept, what is refused, and the diff the analyst
// sees before installing. Archives are built in memory; nothing is downloaded.

const rule = (id: string, eventName = "StopLogging", product = "aws", service = "cloudtrail") =>
  `title: Rule ${id}\nid: ${id}\nstatus: test\nlogsource:\n  product: ${product}\n  service: ${service}\ndetection:\n  sel:\n    eventName: ${eventName}\n  condition: sel\nlevel: high\n`;

const zip = (entries: Record<string, string>) =>
  createZip(Object.entries(entries).map(([path, text]) => ({ path, data: Buffer.from(text) })));

const VERSION =
  "Release Date: 2026-07-09\nLabel: r2026-04-01-50-gabc\nCommit-Hash: 552f3fee420ef232a8e5790c4fae591847e32347\n";

describe("readSigmaReleaseZip", () => {
  it("keeps rule YAML under the three release folders, plus version.txt", () => {
    const r = readSigmaReleaseZip(
      zip({
        "version.txt": VERSION,
        "rules/cloud/aws/a.yml": rule("a"),
        "rules-emerging-threats/2024/b.yml": rule("b"),
        "rules-threat-hunting/c.yml": rule("c"),
        "README.md": "ignored",
        "other/d.yml": rule("d"),
      }),
    );
    expect(r.files.map((f) => f.path)).toEqual([
      "rules-emerging-threats/2024/b.yml",
      "rules-threat-hunting/c.yml",
      "rules/cloud/aws/a.yml",
    ]);
    expect(r.commit).toBe("552f3fee420ef232a8e5790c4fae591847e32347");
    expect(r.versionLabel).toBe("r2026-04-01-50-gabc");
  });

  it("strips a single wrapping folder", () => {
    const r = readSigmaReleaseZip(zip({ "sigma/rules/a.yml": rule("a"), "sigma/version.txt": VERSION }));
    expect(r.files.map((f) => f.path)).toEqual(["rules/a.yml"]);
  });

  it("refuses an archive with no rules folder", () => {
    expect(() => readSigmaReleaseZip(zip({ "x.txt": "hi" }))).toThrow(/no rules/i);
  });

  it("refuses unsafe and duplicate paths and file/folder collisions", () => {
    expect(() => readSigmaReleaseZip(zip({ "rules/../evil.yml": rule("a") }))).toThrow(/unsafe path/);
    expect(() => readSigmaReleaseZip(zip({ "rules/a.yml": rule("a"), "rules/A.yml": rule("b") }))).toThrow(
      /twice/,
    );
    expect(() => readSigmaReleaseZip(zip({ "rules/a": "x", "rules/a/b.yml": rule("b") }))).toThrow(
      /both a file and a folder/,
    );
  });

  it("skips explicit directory entries", () => {
    const r = readSigmaReleaseZip(zip({ "rules/": "", "rules/a.yml": rule("a") }));
    expect(r.files).toHaveLength(1);
  });

  it("refuses an archive larger than the cap before reading it", () => {
    expect(() => readSigmaReleaseZip(Buffer.alloc(SIGMA_RELEASE_MAX_ZIP_BYTES + 1))).toThrow(/larger than/);
  });

  it("refuses something that is not a zip", () => {
    expect(() => readSigmaReleaseZip(Buffer.from("not a zip at all"))).toThrow(/not a readable zip/);
  });
});

describe("diffSigmaReleases", () => {
  const f = (path: string, text: string) => ({ path, text });
  it("reports added, changed and removed rules for the graded log sources only", () => {
    const before = [f("rules/a.yml", rule("a")), f("rules/b.yml", rule("b")), f("rules/c.yml", rule("c"))];
    const after = [
      f("rules/a.yml", rule("a")),
      f("rules/b.yml", rule("b", "DeleteTrail")),
      f("rules/d.yml", rule("d")),
      f("rules/w.yml", rule("w", "x", "windows", "security")),
    ];
    const d = diffSigmaReleases(before, after);
    expect(d.added.map((r) => r.id)).toEqual(["d"]);
    expect(d.changed.map((r) => r.id)).toEqual(["b"]);
    expect(d.removed.map((r) => r.id)).toEqual(["c"]);
    expect(d.otherSources).toBe(1);
  });

  it("ignores line endings: a CRLF copy of the same rules is not a change (#2215)", () => {
    const crlf = (text: string) => text.replace(/\n/g, "\r\n");
    const before = [f("rules/a.yml", rule("a")), f("rules/b.yml", rule("b"))];
    const after = [f("rules/a.yml", crlf(rule("a"))), f("rules/b.yml", crlf(rule("b", "DeleteTrail")))];
    const d = diffSigmaReleases(before, after);
    expect(d.changed.map((r) => r.id)).toEqual(["b"]);
    expect(d.added).toEqual([]);
    expect(d.removed).toEqual([]);
    expect(
      diffSigmaReleases(
        before,
        before.map((x) => f(x.path, crlf(x.text))),
      ).changed,
    ).toEqual([]);
  });
});
