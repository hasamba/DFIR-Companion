import { describe, expect, it } from "vitest";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gzipSync } from "node:zlib";
import { parseCloudActivity } from "../../src/analysis/cloudActivityImport.js";
import { parseM365Audit } from "../../src/analysis/m365Import.js";
import { sourceArtifactHash } from "../../src/analysis/canonicalEvent.js";
import { openCloudRecordStream } from "../../src/analysis/cloudStreamReader.js";
import { loadBundledSigmaRuleSet } from "../../src/analysis/sigmaBundledRules.js";
import { createSigmaImportGrader } from "../../src/analysis/sigmaImportGrade.js";
import { sigmaRuleMitreIndex } from "../../src/analysis/sigmaRegradeSources.js";
import { GZIP_MAX_RATIO, GZIP_RATIO_SLACK_BYTES } from "../../src/analysis/cloudStreamLimits.js";
import { loadRegradePlan, storedImportBytes } from "../../src/routes/sigmaRegradePlan.js";
import { readStoredImportText } from "../../src/routes/storedImportText.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";
import type { SiemEvent } from "../../src/analysis/siemImport.js";

// #2353 (b): a Sigma re-grade reads a gzip stored file decompressed (bounded), and compares the
// rows' source hash with the decompressed text — the hash a streamed .gz import stamped.

const { set } = loadBundledSigmaRuleSet();
const snap = createSigmaImportGrader(set, { minLevel: () => "medium" }).snapshot()!;
const ruleMitre = sigmaRuleMitreIndex(set);

const rec = (i: number, methodName: string) => ({
  timestamp: `2026-03-01T10:00:0${i}Z`,
  insertId: `g-${i}`,
  logName: "projects/p1/logs/cloudaudit.googleapis.com%2Factivity",
  resource: { type: "service_account", labels: { project_id: "p1" } },
  protoPayload: {
    "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
    methodName,
    serviceName: "iam.googleapis.com",
    resourceName: "projects/-/serviceAccounts/123456789012345678901",
    authenticationInfo: { principalEmail: "alice@example.com" },
    requestMetadata: { callerIp: "198.51.100.7" },
  },
});
const GCP = JSON.stringify([
  rec(1, "google.iam.admin.v1.DisableServiceAccount"),
  rec(2, "google.iam.admin.v1.GetServiceAccount"),
]);
const ENTRA = JSON.stringify({
  value: [
    {
      id: "s-1",
      createdDateTime: "2026-03-01T10:00:00Z",
      userPrincipalName: "alice@example.test",
      appDisplayName: "Azure Portal",
      ipAddress: "198.51.100.7",
      clientAppUsed: "Browser",
      userAgent: "azurehound/v2.1.0",
      status: { errorCode: 0 },
    },
  ],
});

async function dirWith(file: string, body: Buffer): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "dfir-regrade-gz-"));
  await writeFile(join(dir, file), body);
  return dir;
}

function asStored(rows: SiemEvent[], file: string): ForensicEvent[] {
  return rows.map((e, i) => ({ ...e, id: `r${i + 1}`, relatedFindingIds: [], sourceScreenshots: [file] }));
}

function planOf(dir: string, rows: ForensicEvent[], maxTextBytes?: number) {
  return loadRegradePlan(
    {
      stateStore: {
        async *forensicTimelineBatches() {
          yield rows;
        },
      },
      importsDir: dir,
      snapshot: snap,
      gate: "Low",
      ruleMitre,
      ...(maxTextBytes ? { maxTextBytes } : {}),
    },
    "c1",
  );
}

describe("readStoredImportText (#2353)", () => {
  it("reads a plain file as the import decoded it", async () => {
    const dir = await dirWith("a.json", Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(GCP)]));
    expect(await readStoredImportText(join(dir, "a.json"))).toEqual({ text: GCP });
  });

  it("decompresses a gzip file, concatenated members included", async () => {
    const half = Math.floor(GCP.length / 2);
    const body = Buffer.concat([gzipSync(GCP.slice(0, half)), gzipSync(GCP.slice(half))]);
    const dir = await dirWith("a.json.gz", body);
    expect(await readStoredImportText(join(dir, "a.json.gz"))).toEqual({ text: GCP });
  });

  it("refuses a file past the cap, plain or decompressed, without reading it whole", async () => {
    const dir = await dirWith("big.json.gz", gzipSync("x".repeat(10_000)));
    await writeFile(join(dir, "big.json"), "x".repeat(10_000));
    expect(await readStoredImportText(join(dir, "big.json.gz"), 1_000)).toEqual({
      skipped: "file-too-large",
    });
    expect(await readStoredImportText(join(dir, "big.json"), 1_000)).toEqual({ skipped: "file-too-large" });
  });

  it("reports a corrupt or truncated gzip as unreadable, and a missing file as missing", async () => {
    const whole = gzipSync(GCP);
    const dir = await dirWith("cut.json.gz", whole.subarray(0, whole.length - 12));
    expect(await readStoredImportText(join(dir, "cut.json.gz"))).toEqual({ skipped: "file-unreadable" });
    expect(await readStoredImportText(join(dir, "nope.json"))).toEqual({ skipped: "file-missing" });
  });

  it("hashes to the streamed import's text hash (UTF-8, UTF-8 BOM, UTF-16LE BOM)", async () => {
    const bodies = [
      Buffer.from(GCP),
      Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(GCP)]),
      Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(GCP, "utf16le")]),
    ];
    for (const [i, body] of bodies.entries()) {
      const dir = await dirWith(`p${i}.json.gz`, gzipSync(body));
      const path = join(dir, `p${i}.json.gz`);
      const stream = await openCloudRecordStream(path, { chunkBytes: 7 }); // chunk edges mid-character
      for await (const _ of stream.records) void _;
      const read = await readStoredImportText(path);
      expect("text" in read && sourceArtifactHash(read.text)).toBe(stream.stats().textHash);
    }
  });
});

describe("loadRegradePlan reads gzip stored files (#2353)", () => {
  it("pairs and re-grades the rows of a gzip import", async () => {
    const file = "0001_gcp.json.gz";
    const rows = asStored(parseCloudActivity(GCP, { aggregate: false }).events, file);
    const p = await planOf(await dirWith(file, gzipSync(GCP)), rows);
    expect(p.files[0].status).not.toBe("skipped");
    expect(p.counts.unmatched).toBe(0);
    expect(p.rows.some((r) => r.kind === "changed")).toBe(true);
  });

  it("reports a gzip file whose decompressed text differs from the rows' hash as changed", async () => {
    const file = "0001_gcp.json.gz";
    const rows = asStored(parseCloudActivity(GCP, { aggregate: false }).events, file);
    const p = await planOf(await dirWith(file, gzipSync(`${GCP} `)), rows);
    expect(p.files[0]).toMatchObject({ status: "skipped", reason: "file-changed" });
  });

  it("skips a stored file past the re-grade cap as too large, and a corrupt one as unreadable", async () => {
    const file = "0001_gcp.json.gz";
    const rows = asStored(parseCloudActivity(GCP, { aggregate: false }).events, file);
    const big = await planOf(await dirWith(file, gzipSync(GCP)), rows, 100);
    expect(big.files[0]).toMatchObject({ status: "skipped", reason: "file-too-large" });
    const cut = await planOf(await dirWith(file, gzipSync(GCP).subarray(0, 20)), rows);
    expect(cut.files[0]).toMatchObject({ status: "skipped", reason: "file-unreadable" });
  });

  it("round-trips a whole-file M365 import, now hashed, without calling the file changed", async () => {
    const file = "0002_entra.json";
    const rows = asStored(parseM365Audit(ENTRA).events, file);
    expect(rows.every((e) => !e.canonical || e.canonical.evidence.sourceArtifactHash)).toBe(true);
    const p = await planOf(await dirWith(file, Buffer.from(ENTRA)), rows);
    expect(p.files[0].status).not.toBe("skipped");
    expect(p.counts.unmatched).toBe(0);
  });
});

describe("storedImportBytes sizes a gzip file by what the re-grade can read (#2353)", () => {
  it("counts a gzip file at the reader's upper bound, never its compressed size", async () => {
    const gz = gzipSync(GCP);
    const dir = await dirWith("a.json.gz", gz);
    await writeFile(join(dir, "b.json"), GCP);
    const expected = Math.max(GZIP_RATIO_SLACK_BYTES, gz.length * GZIP_MAX_RATIO) + Buffer.byteLength(GCP);
    expect(await storedImportBytes(dir)).toBe(expected);
  });
});
