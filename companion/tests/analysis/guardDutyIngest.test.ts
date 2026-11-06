import { describe, expect, it } from "vitest";
import { writeFile } from "node:fs/promises";
import { gzipSync } from "node:zlib";
import { join } from "node:path";
import { tempCase } from "../helpers/cloudCollectFakes.js";
import { gdExport, gdFinding } from "../helpers/guardDutyFixtures.js";
import { isStreamKind } from "../../src/analysis/ingest/cloudStreamProviders.js";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { parseGuardDuty } from "../../src/analysis/guardDutyImport.js";
import { applyToForensicEvent, runTagger } from "../../src/analysis/tagger.js";
import { compileText } from "../../src/analysis/taggerStore.js";
import { createPreGrader } from "../../src/analysis/cloudStreamPreGrade.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

// #2361 — GuardDuty findings through the real pipeline: the whole-file path (a hand-dropped
// export) and the streaming path (a large or gzipped export, and every collected page).

const base = (n: number) => ({
  label: `gd-${n}.json`,
  idPrefix: `gd${n}`,
  importedAt: "2026-10-05T00:00:00Z",
});

const FINDINGS = () => [
  gdFinding(1, { Severity: 9.4, Type: "CryptoCurrency:EC2/BitcoinTool.B!DNS" }),
  gdFinding(2, { Severity: 2 }),
  gdFinding(3, { Severity: 8 }, { Archived: true }),
];

describe("GuardDuty whole-file import (#2361)", () => {
  it("lands each finding with GuardDuty's grade; the archived one is Info", async () => {
    const t = await tempCase();
    const state = await t.pipeline.importGuardDuty("c1", gdExport(FINDINGS()), base(1));
    const rows = state.forensicTimeline.filter((e) => /^GuardDuty finding/.test(e.description));
    const bySev = Object.fromEntries(rows.map((e) => [e.description.split(" ")[2], e.severity]));
    expect(bySev["CryptoCurrency:EC2/BitcoinTool.B!DNS:"]).toBe("Critical");
    expect(rows.find((e) => /, archived$/.test(e.description))?.severity ?? "Info").toBe("Info");
    const crit = rows.find((e) => e.severity === "Critical")!;
    expect(crit.mitreTechniques).toContain("T1496");
    expect(crit.sourceScreenshots).toContain("gd-1.json");
    expect(
      state.timeline.some((n) =>
        /AWS GuardDuty import: \d+ event\(s\) from 3 finding\(s\)/.test(n.description),
      ),
    ).toBe(true);
  });

  it("an identical re-import adds nothing; an updated finding lands as a new observation", async () => {
    const t = await tempCase();
    await t.pipeline.importGuardDuty("c1", gdExport([gdFinding(1, { Severity: 5 })]), base(1));
    const again = await t.pipeline.importGuardDuty("c1", gdExport([gdFinding(1, { Severity: 5 })]), base(2));
    const count = (s: typeof again) =>
      s.forensicTimeline.filter((e) => /^GuardDuty finding/.test(e.description)).length;
    expect(count(again)).toBe(1);
    const updated = gdFinding(1, { Severity: 5, UpdatedAt: "2026-10-03T00:00:00.000Z" }, { Count: 7 });
    const third = await t.pipeline.importGuardDuty("c1", gdExport([updated]), base(3));
    expect(count(third)).toBe(2);
    expect(third.forensicTimeline.some((e) => /record id conflict/.test(e.description))).toBe(false);
  });
});

describe("GuardDuty streaming import (#2361)", () => {
  it("is a stream kind", () => {
    expect(isStreamKind("guardduty")).toBe(true);
  });

  it("streams a gzipped {Findings:[...]} export record by record, graded the same", async () => {
    const t = await tempCase();
    const path = join(t.root, "gd.json.gz");
    await writeFile(path, gzipSync(Buffer.from(gdExport(FINDINGS()))));
    const { state, disclosure } = await t.pipeline.importCloudFile("c1", "guardduty", path, {
      ...base(1),
      batchRecords: 1,
    });
    expect(disclosure.records).toBe(3);
    const rows = state.forensicTimeline.filter((e) => /^GuardDuty finding/.test(e.description));
    expect(rows.find((e) => /BitcoinTool/.test(e.description))?.severity).toBe("Critical");
    expect(rows.find((e) => /i-0abc2/.test(e.description))?.severity).toBe("Low");
    // Info never reaches the forensic timeline: the archived finding goes to the super-timeline.
    expect(rows.some((e) => /, archived$/.test(e.description))).toBe(false);
    const sup = await t.superTimelineStore.query("c1", { limit: 50 });
    expect(JSON.stringify(sup)).toMatch(/archived/);
  });

  it("two versions of one finding across streamed batches stay two rows", async () => {
    const t = await tempCase();
    const path = join(t.root, "gd.json");
    const v2 = gdFinding(1, { UpdatedAt: "2026-10-01T05:00:00.000Z" }, { Count: 9 });
    await writeFile(path, gdExport([gdFinding(1), v2]));
    const { state } = await t.pipeline.importCloudFile("c1", "guardduty", path, {
      ...base(1),
      batchRecords: 1,
    });
    expect(state.forensicTimeline.filter((e) => /^GuardDuty finding/.test(e.description))).toHaveLength(2);
  });
});

// Codex review (#2361): a finding's resource names are adversary-reachable, so a shipped rule that
// matches them (a bucket named `ntds.dit` → the Windows NTDS rule) must not regrade the finding.
describe("GuardDuty keeps its own grade through the tagger (#2361 review)", () => {
  const rules = compileText(
    readFileSync(fileURLToPath(new URL("../../data/tags.yaml", import.meta.url)), "utf8"),
  );
  const bait = () =>
    gdFinding(
      7,
      {
        Type: "Discovery:S3/AnomalousBehavior",
        Severity: 2,
        Resource: { ResourceType: "S3Bucket", S3BucketDetails: [{ Name: "ntds.dit" }] },
        Description: "vssadmin create shadow /for=C: then copy ntds.dit from the shadow copy",
      },
      { Archived: true },
    );

  it("the bait really matches a graded shipped rule (so the guard is what holds the grade)", () => {
    const [row] = parseGuardDuty(gdExport([bait()]), { aggregate: false }).events;
    const event = {
      ...row,
      id: "e1",
      relatedFindingIds: [],
      sourceScreenshots: [],
    } as unknown as ForensicEvent;
    const hit = runTagger([event], rules).perEvent[0];
    expect(hit?.severity && hit.severity !== "Info").toBeTruthy();
    const applied = applyToForensicEvent(event, hit);
    expect(applied.severity).toBe("Info");
    expect(applied.mitreTechniques).toEqual(row.mitreTechniques);
    expect(createPreGrader(rules).grade([{ ...row, mitre: row.mitreTechniques, aggKey: "k" }]).raised).toBe(
      0,
    );
  });

  it("a streamed archived finding stays out of the forensic timeline even with tagger pre-grading on", async () => {
    const t = await tempCase();
    const path = join(t.root, "bait.json");
    await writeFile(path, gdExport([bait(), gdFinding(8, { Severity: 7.2 })]));
    const { state } = await t.pipeline.importCloudFile("c1", "guardduty", path, {
      ...base(1),
      preGradeRules: rules,
    });
    const rows = state.forensicTimeline.filter((e) => /^GuardDuty finding/.test(e.description));
    expect(rows.map((e) => e.severity)).toEqual(["High"]);
  });
});
