import { describe, it, expect, afterEach } from "vitest";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gzipSync } from "node:zlib";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore, INVESTIGATION_DB_FILENAME } from "../../src/analysis/stateStore.js";
import { SuperTimelineStore } from "../../src/analysis/superTimelineStore.js";
import { CloudRecordStore } from "../../src/analysis/cloudRecordStore.js";
import { AuthObservationStore } from "../../src/analysis/authObservationStore.js";
import { CloudCoverageStore } from "../../src/analysis/cloudCoverage.js";
import { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import { TaggerStore } from "../../src/analysis/taggerStore.js";
import { loadDatabaseSync } from "../../src/analysis/sqliteRuntime.js";

// #2362 — the streamed CloudTrail import is made faster WITHOUT changing what it produces. This test
// pins the result of a mid-size synthetic multi-object CloudTrail set, as computed by the code
// BEFORE the optimisation (master 8e7f1c5d): every forensic row, IOC, note, each import's
// disclosure, every persisted super-timeline / ledger / member row, and the cloud coverage —
// including a cancelled import and its retry (the crash/resume contract). One hash per section, so
// a regression names what changed. Volatile values are normalised: the random attempt suffix of a
// ledger batch (`<idPrefix>.<8 hex>`, distinct attempts keep distinct placeholders) and the two
// wall-clock stamps of a coverage record. Nothing else.
//
// Shape of the set: 3 gzip objects × 1,500 records, batches of 250, a 1,000-record summary window,
// and a 2,500-row super-timeline cap so Info overflows into aggregates (and the member relation)
// part-way through the second object. High/Medium operations, a Medium actor over its per-actor
// budget, Info reads, RunInstances/TerminateInstances (compute lifecycles), access keys reused
// across records (credential lineages), records repeated across objects (duplicates) and a changed
// payload under a known eventID (conflicts). The default tagger ruleset pre-grades every batch.

const ACCOUNT = "123456789012";
const OBJECTS = 3;
const PER_OBJECT = 1_500;

function rng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const BENIGN = [
  ["DescribeInstances", "ec2.amazonaws.com", true],
  ["DescribeVolumes", "ec2.amazonaws.com", true],
  ["ListBuckets", "s3.amazonaws.com", true],
  ["GetCallerIdentity", "sts.amazonaws.com", true],
  ["Decrypt", "kms.amazonaws.com", true],
  ["PutObject", "s3.amazonaws.com", false],
] as const;
const GRADED = [
  ["CreateAccessKey", "iam.amazonaws.com", false],
  ["AttachUserPolicy", "iam.amazonaws.com", false],
  ["StopLogging", "cloudtrail.amazonaws.com", false],
  ["GetSecretValue", "secretsmanager.amazonaws.com", true],
  ["AuthorizeSecurityGroupIngress", "ec2.amazonaws.com", false],
  ["DeleteTrail", "cloudtrail.amazonaws.com", false],
] as const;

type Rec = Record<string, unknown>;

function record(i: number, r: () => number): Rec {
  const minute = Math.floor(i / 7);
  const at = `2026-11-01T${String(Math.floor(minute / 60) % 24).padStart(2, "0")}:${String(minute % 60).padStart(2, "0")}:${String(i % 60).padStart(2, "0")}Z`;
  const roll = r();
  const u = Math.floor(r() * 12);
  const ip = `198.51.100.${1 + Math.floor(r() * 40)}`;
  let def: readonly [string, string, boolean];
  let user = `svc${u}`;
  if (roll < 0.04) def = GRADED[Math.floor(r() * GRADED.length)];
  else if (roll < 0.07) {
    def = ["GetSecretValue", "secretsmanager.amazonaws.com", true]; // one actor past its Medium budget
    user = "ops-bulk";
  } else def = BENIGN[Math.floor(r() * BENIGN.length)];
  const base: Rec = {
    eventVersion: "1.09",
    userIdentity: {
      type: "IAMUser",
      principalId: `AIDA${String(u).padStart(16, "0")}`,
      arn: `arn:aws:iam::${ACCOUNT}:user/${user}`,
      accountId: ACCOUNT,
      accessKeyId: `AKIAPAR${String(u).padStart(13, "0")}`,
      userName: user,
    },
    eventTime: at,
    eventSource: def[1],
    eventName: def[0],
    awsRegion: "us-east-1",
    sourceIPAddress: ip,
    userAgent: "aws-cli/2.15.0 Python/3.11.6 Linux/6.1 exe/x86_64",
    requestParameters: { maxResults: 100 },
    responseElements: null,
    requestID: `00000000-0000-4000-a000-${i.toString(16).padStart(12, "0")}`,
    eventID: `00000000-0000-4000-b000-${i.toString(16).padStart(12, "0")}`,
    readOnly: def[2],
    eventType: "AwsApiCall",
    managementEvent: true,
    recipientAccountId: ACCOUNT,
    eventCategory: "Management",
  };
  if (i % 97 === 5) {
    const id = `i-0${i.toString(16).padStart(16, "0")}`;
    return {
      ...base,
      eventSource: "ec2.amazonaws.com",
      eventName: "RunInstances",
      readOnly: false,
      requestParameters: { instanceType: "t3.micro", imageId: "ami-0abcdef1234567890" },
      responseElements: { instancesSet: { items: [{ instanceId: id, instanceType: "t3.micro" }] } },
    };
  }
  if (i % 97 === 50) {
    const id = `i-0${(i - 45).toString(16).padStart(16, "0")}`;
    return {
      ...base,
      eventSource: "ec2.amazonaws.com",
      eventName: "TerminateInstances",
      readOnly: false,
      requestParameters: { instancesSet: { items: [{ instanceId: id }] } },
    };
  }
  return base;
}

function objects(): Rec[][] {
  const r = rng(2362);
  const out: Rec[][] = [];
  for (let o = 0; o < OBJECTS; o++) {
    const recs: Rec[] = [];
    for (let k = 0; k < PER_OBJECT; k++) recs.push(record(o * PER_OBJECT + k, r));
    out.push(recs);
  }
  // The third object repeats 100 records of the first verbatim (duplicates) and 20 more under the
  // same eventID with a changed source address (conflicts).
  const dup = out[0].slice(200, 300);
  const conflict = out[0].slice(400, 420).map((rec) => ({ ...rec, sourceIPAddress: "203.0.113.99" }));
  out[2] = [...out[2].slice(0, 700), ...dup, ...conflict, ...out[2].slice(700)];
  return out;
}

/** Stable JSON: object keys sorted, so a change in construction order is not a result change. */
function stable(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(stable).join(",")}]`;
  if (v && typeof v === "object")
    return `{${Object.keys(v)
      .sort()
      .filter((k) => (v as Rec)[k] !== undefined)
      .map((k) => `${JSON.stringify(k)}:${stable((v as Rec)[k])}`)
      .join(",")}}`;
  return JSON.stringify(v);
}

function normaliser(): (s: string) => string {
  const seen = new Map<string, string>();
  return (s) =>
    s.replace(/\b(p\d)\.([0-9a-f]{8})\b/g, (_m, prefix: string, hex: string) => {
      if (!seen.has(hex)) seen.set(hex, `#${seen.size + 1}`);
      return `${prefix}.${seen.get(hex)}`;
    });
}

const sha = (s: string): string => createHash("sha256").update(s).digest("hex").slice(0, 16);

async function runSet() {
  const root = await mkdtemp(join(tmpdir(), "dfir-ctparity-"));
  const cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  const cloudCoverageStore = new CloudCoverageStore(cases);
  const stateStore = new StateStore(cases);
  const pipeline = new AnalysisPipeline({
    stateStore,
    superTimelineStore: new SuperTimelineStore(cases),
    cloudRecordStore: new CloudRecordStore(cases),
    cloudCoverageStore,
    authObservationStore: new AuthObservationStore(cases, 168),
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  const tagsYaml = fileURLToPath(new URL("../../data/tags.yaml", import.meta.url));
  const rules = await new TaggerStore(join(root, "no-user-rules.yaml"), [tagsYaml]).load();
  const files: string[] = [];
  for (const [o, recs] of objects().entries()) {
    const p = join(root, `${ACCOUNT}_CloudTrail_us-east-1_20261101T000${o}Z_PARITY.json.gz`);
    await writeFile(p, gzipSync(JSON.stringify({ Records: recs })));
    files.push(p);
  }
  const opts = (idPrefix: string, over: Rec = {}) => ({
    label: `${idPrefix}.json.gz`,
    idPrefix,
    importedAt: "2026-11-02T00:00:00Z",
    batchRecords: 250,
    summaryRecords: 1_000,
    preGradeRules: rules,
    ...over,
  });
  const disclosures: unknown[] = [];
  disclosures.push((await pipeline.importCloudFile("c1", "aws", files[0], opts("p1"))).disclosure);
  // The second object is cancelled after its third batch was written, then retried (same prefix).
  const ctrl = new AbortController();
  let calls = 0;
  await expect(
    pipeline.importCloudFile(
      "c1",
      "aws",
      files[1],
      opts("p2", {
        signal: ctrl.signal,
        onProgress: () => {
          if (++calls === 3) ctrl.abort();
        },
      }),
    ),
  ).rejects.toMatchObject({ name: "AbortError" });
  disclosures.push((await pipeline.importCloudFile("c1", "aws", files[1], opts("p2"))).disclosure);
  disclosures.push((await pipeline.importCloudFile("c1", "aws", files[2], opts("p3"))).disclosure);

  const state = await stateStore.load("c1");
  const DatabaseSync = loadDatabaseSync();
  const db = new DatabaseSync(join(cases.stateDir("c1"), INVESTIGATION_DB_FILENAME));
  const rows = db
    .prepare(
      "SELECT kind, entity_id, ordinal, version, timestamp, host, source, severity, content_key, payload " +
        "FROM entities ORDER BY kind, row_id",
    )
    .all() as Array<Record<string, unknown>>;
  db.close();
  const norm = normaliser();
  const byKind = new Map<string, string[]>();
  for (const row of rows) {
    const kind = String(row.kind);
    const { payload, ...cols } = row;
    const line = norm(stable({ ...cols, payload: JSON.parse(String(payload)) }));
    byKind.set(kind, [...(byKind.get(kind) ?? []), line]);
  }
  const notes = state.timeline;
  const sections: Record<string, unknown> = {
    forensicTimeline: state.forensicTimeline,
    iocs: state.iocs,
    notes,
    disclosures,
    // The two wall-clock stamps of a coverage record are when the test ran, not what it imported.
    coverage: (await cloudCoverageStore.load("c1")).map(
      ({ uploadFirstSeenAt: _f, importedAt: _i, ...rest }) => rest,
    ),
  };
  const hashes: Record<string, string> = {};
  for (const [k, v] of Object.entries(sections)) hashes[k] = sha(norm(stable(v)));
  for (const [kind, lines] of byKind) hashes[`db:${kind}`] = sha(lines.join("\n"));
  const counts = {
    forensic: state.forensicTimeline.length,
    graded: state.forensicTimeline.filter((e) => e.severity !== "Info" && e.severity !== "Low").length,
    iocs: state.iocs.length,
    lineages: state.forensicTimeline.filter((e) => e.description.startsWith("AWS credential lineage")).length,
    compute: state.forensicTimeline.filter((e) => e.description.startsWith("AWS compute lifecycle")).length,
    dbRows: Object.fromEntries([...byKind].map(([k, v]) => [k, v.length])),
  };
  return { hashes, counts };
}

const SUPER_MAX = process.env.DFIR_SUPERTIMELINE_MAX;
afterEach(() => {
  if (SUPER_MAX === undefined) delete process.env.DFIR_SUPERTIMELINE_MAX;
  else process.env.DFIR_SUPERTIMELINE_MAX = SUPER_MAX;
});

describe("streamed CloudTrail import parity (#2362)", () => {
  it("produces exactly the pinned rows, counts, grades, disclosures and ledger state", async () => {
    process.env.DFIR_SUPERTIMELINE_MAX = "2500";
    const got = await runSet();
    expect(got).toEqual(PINNED);
  }, 120_000);
});

// Computed by the pre-optimisation code (master 8e7f1c5d) and identical across runs. Re-pinned once
// for #2502, a deliberate output change: two in-budget Medium rows sharing one grouping key now merge
// into one counted detail row (forensic 2348 -> 2347, graded 300 -> 299; member rows unchanged at
// 2705, so no record is lost), and the disclosure gained mediumMerged plus the "kept in detail"
// wording (disclosures, notes, timeline, coverage). The #2502 time-span fix alone changes nothing here.
// Re-pinned for #2475 too: a one-row detailed group no longer carries the "[aggregated: 1 row(s) — …]"
// note, so those descriptions lose that suffix; no count changes.
// Re-pinned for #2481: only the disclosures hash moved. The set has no failed calls, so nothing folds;
// each disclosure gained three fields — mediumOverflow.failedReadBudget 0, failedReads {0, 0} and
// budgets.failedReadsPerActor 10. Stripping exactly those three reproduced the previous hash
// (b41790f4ea7b0e23); every other section, count and note is unchanged.
// Re-pinned for #2542 (user decision Q4): a credential-lineage row with an enumeration shape now
// states its burst (read calls, services, span, denied probes) in its description. Only the two
// forensic-timeline hashes moved; with the burst words suppressed they reproduce the previous
// hashes (47e419e317d56d07, 952a8006b6bd4d4a). No count, grade or other section changed.
// Re-pinned for #2543 part 1a: the High+ rows' IAM-user ARNs and long-term keys are now `other` IOCs
// with a context note (41 -> 65 IOCs; all 24 new ones carry a note). The timeline note states the
// IOC count, so notes and db:timeline moved with it. No forensic row, grade or coverage changed.
const PINNED = {
  counts: {
    compute: 30,
    dbRows: {
      cloudRecord: 5270,
      cloudRecordBatch: 4,
      cloudRecordMember: 2705,
      forensicTimeline: 2347,
      iocs: 65,
      superTimeline: 2500,
      timeline: 3,
    },
    forensic: 2347,
    graded: 299,
    iocs: 65,
    lineages: 36,
  },
  hashes: {
    coverage: "92a60725c7a87a3d",
    "db:cloudRecord": "55eeaad28f712d39",
    "db:cloudRecordBatch": "d7a32e76dfef0950",
    "db:cloudRecordMember": "2260533dd0f4bdd7",
    "db:forensicTimeline": "7eeeea4e62b61b44",
    "db:iocs": "4f512b1f74235cce",
    "db:superTimeline": "8beed3d432925a0d",
    "db:timeline": "92dddb73812ed1ad",
    disclosures: "9446777ef7052706",
    forensicTimeline: "f896c4c5af69ca2c",
    iocs: "313dfcbfb2c46ffb",
    notes: "0827783fdc6edf7b",
  },
};
