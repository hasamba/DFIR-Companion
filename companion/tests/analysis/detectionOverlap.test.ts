// Detection-overlap check (#2348). An imported cloud event can be graded by three paths — the
// importer's own grading, the bundled SigmaHQ rules (import-time, default settings: on, stable +
// test, raises at high and above) and the shipped tags.yaml tagger rules. Severity only ever rises,
// so a deliberate grade can be overridden by another path with no other test failing.
//
// SCOPE (v1): cloud sources only — AWS CloudTrail, Microsoft 365 / Entra (UAL, sign-in, directory
// audit) and GCP audit logs, through their real importers. Windows / web sources are not checked.
//
// WHAT FAILS: a REAL conflict — two or more paths that each assign a grade to the same row and
// disagree, unless data/detection-overlap-allow.yaml lists that pair. A path "assigns a grade" when:
//   importer — its grade is above the floor it gives an operation it does not recognise (Info for
//              M365 / Entra; for CloudTrail and GCP, the grade of the same record with the operation
//              renamed), or the operation is in its own grading table;
//   Sigma    — a matched rule at or above the minimum level, not hunting-only, not vetoed;
//   tagger   — a matched rule that sets a severity above Info.
// A rule raising a row the importer left at its floor is the normal job of a rule and passes.
// REPORTED, NOT FAILED: same-grade duplicates (same grade and same MITRE), Sigma rules with no
// buildable sample ("not checked", with a count), and graded cloud tagger rules no sample fires.
// An allowlist entry that matches no conflict fails (no stale entries).
//
// Samples: fixtures/detectionSamples/ — records copied from the cloud tagger/Sigma tests, plus one
// sample per loaded bundled cloud Sigma rule where one can be built from its selection.
import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { AWS_SAMPLES } from "./fixtures/detectionSamples/aws.js";
import { M365_SAMPLES } from "./fixtures/detectionSamples/m365.js";
import { GCP_SAMPLES } from "./fixtures/detectionSamples/gcp.js";
import { GWS_SAMPLES } from "./fixtures/detectionSamples/gws.js";
import { buildCloudSigmaSamples, CLOUD_SIGMA_SOURCES } from "./fixtures/detectionSamples/sigmaBuilt.js";
import { readAllowlist } from "./fixtures/detectionSamples/allowlist.js";
import {
  describeOverlap,
  findOverlaps,
  gradeSample,
  pairKey,
  SIGMA_SET,
  TAGGER_RULES,
  type GradeEntry,
  type RowResult,
} from "./fixtures/detectionSamples/overlap.js";

const ALLOW_TEXT = readFileSync(
  fileURLToPath(new URL("../../data/detection-overlap-allow.yaml", import.meta.url)),
  "utf8",
);

const builds = buildCloudSigmaSamples(SIGMA_SET);
const handSamples = [...AWS_SAMPLES, ...M365_SAMPLES, ...GCP_SAMPLES, ...GWS_SAMPLES];

// Grade every hand sample, and every built Sigma sample whose rule really fired through the importer.
const results = handSamples.map((s) => ({ s, ...gradeSample(s) }));
const builtResults = builds.flatMap((b) => {
  if (!b.sample) return [];
  const r = gradeSample(b.sample);
  return [{ b, fired: r.sigmaMatched.includes(b.ruleId), ...r }];
});
const checkedRows: RowResult[] = [
  ...results.flatMap((r) => r.rows),
  ...builtResults.filter((r) => r.fired).flatMap((r) => r.rows),
];
const { conflicts, duplicates } = findOverlaps(checkedRows);

// A loaded rule is checked when ANY sample (hand or built) made it match through the importer.
const sigmaChecked = new Set([
  ...results.flatMap((r) => r.sigmaMatched),
  ...builtResults.filter((r) => r.fired).flatMap((r) => r.sigmaMatched),
]);
const notChecked = builds
  .filter((b) => !sigmaChecked.has(b.ruleId))
  .map(
    (b) => `${b.source} ${b.title} — ${b.notBuilt ?? "the built sample did not fire through the importer"}`,
  );

const CLOUD_TAGGER = /^(?:ts_aws|ts_gcp|ts_m365|ts_entra|cloud_|mas_|td_aws_|gcp_)/;
const gradedCloudTagger = TAGGER_RULES.rules.filter(
  (r) => CLOUD_TAGGER.test(r.id) && r.severity && r.severity !== "Info",
);
const firedPaths = new Set(checkedRows.flatMap((r) => r.entries.map((e: GradeEntry) => e.path)));

describe("detection overlap — cloud importer vs bundled Sigma vs tagger (#2348)", () => {
  it("prints the coverage report", () => {
    const loaded = builds.length;
    const checked = builds.filter((b) => sigmaChecked.has(b.ruleId)).length;
    const builtUsed = builtResults.filter((r) => r.fired).length;
    const notLoaded = SIGMA_SET.inventory.filter(
      (e) => e.source && e.source in CLOUD_SIGMA_SOURCES && e.outcome !== "loaded",
    );
    const unfired = gradedCloudTagger.filter((r) => !firedPaths.has(`tagger:${r.id}`));
    const lines = [
      `samples: ${handSamples.length} hand + ${builtUsed} built from Sigma; rows checked: ${checkedRows.length}`,
      `bundled cloud Sigma rules loaded: ${loaded}; checked: ${checked}; NOT CHECKED: ${notChecked.length}`,
      ...notChecked.map((l) => `  not checked: ${l}`),
      `bundled cloud Sigma rules not loaded at default settings (status / refused / disabled): ${notLoaded.length}`,
      `graded cloud tagger rules: ${gradedCloudTagger.length}; fired by no sample: ${unfired.length}`,
      ...unfired.map((r) => `  no sample fires: tagger:${r.id}`),
      `conflicts: ${conflicts.length}; same-grade duplicates (reported, not failed): ${duplicates.length}`,
      ...duplicates.map((d) => `  duplicate: ${describeOverlap(d)}`),
    ];
    console.log(lines.join("\n"));
    expect(loaded).toBe(checked + notChecked.length);
    // Every rule a hand sample fires is in the loaded set (gradeSample throws otherwise).
    expect([...sigmaChecked].every((id) => builds.some((b) => b.ruleId === id))).toBe(true);
  });

  it("every hand sample produces at least one row through its importer", () => {
    expect(results.filter((r) => r.rows.length === 0).map((r) => r.s.id)).toEqual([]);
  });

  it("every sample id is unique", () => {
    const ids = [...handSamples, ...builds.flatMap((b) => (b.sample ? [b.sample] : []))].map((s) => s.id);
    expect(ids.length).toBe(new Set(ids).size);
  });

  it("has no real grade conflict outside the allowlist", () => {
    const allowed = new Set(readAllowlist(ALLOW_TEXT).map((e) => e.key));
    const open = conflicts.filter((c) => !allowed.has(pairKey(c.a.path, c.b.path)));
    const message = open
      .map((c) => `${describeOverlap(c)}\n    allowlist entry: rules: [${c.a.path}, ${c.b.path}]`)
      .join("\n");
    expect(open.length, `grade conflicts not in data/detection-overlap-allow.yaml:\n${message}`).toBe(0);
  });

  it("has no stale allowlist entry", () => {
    const live = new Set(conflicts.map((c) => pairKey(c.a.path, c.b.path)));
    const stale = readAllowlist(ALLOW_TEXT).filter((e) => !live.has(e.key));
    expect(
      stale.map((e) => e.key),
      "allowlist entries that match no conflict — remove them",
    ).toEqual([]);
  });
});

describe("detection overlap — the rules of the check (#2348)", () => {
  const entry = (path: string, grade: GradeEntry["grade"], mitre: string[] = []): GradeEntry => ({
    path,
    label: path,
    grade,
    mitre,
  });
  const row = (...entries: GradeEntry[]): RowResult => ({
    sampleId: "s",
    row: 0,
    description: "",
    entries,
    tagOnly: [],
  });

  it("a different grade from two paths is a conflict", () => {
    const r = findOverlaps([row(entry("importer:cloudtrail", "Medium"), entry("sigma:x", "High"))]);
    expect(r.conflicts).toHaveLength(1);
    expect(r.duplicates).toHaveLength(0);
  });

  it("the same grade and MITRE is a duplicate, the same grade with other MITRE is neither", () => {
    expect(
      findOverlaps([row(entry("tagger:a", "High", ["T1"]), entry("sigma:b", "High", ["T1"]))]).duplicates,
    ).toHaveLength(1);
    const other = findOverlaps([row(entry("tagger:a", "High", ["T1"]), entry("sigma:b", "High", ["T2"]))]);
    expect(other.duplicates).toHaveLength(0);
    expect(other.conflicts).toHaveLength(0);
  });

  it("one grading path alone is never an overlap", () => {
    const r = findOverlaps([row(entry("sigma:x", "High"))]);
    expect(r.conflicts.length + r.duplicates.length).toBe(0);
  });

  it("the allowlist refuses an entry without a reason or with one path", () => {
    expect(() => readAllowlist("entries:\n  - rules: [importer:cloudtrail, tagger:x]\n")).toThrow(/reason/);
    expect(() => readAllowlist("entries:\n  - rules: [tagger:x]\n    reason: r\n")).toThrow(
      /two different paths/,
    );
    expect(readAllowlist("entries:\n  - rules: [tagger:b, tagger:a]\n    reason: r\n")[0].key).toBe(
      "tagger:a + tagger:b",
    );
  });
});
