/**
 * Synthetic large cloud exports for the import scale baseline (#2300). Writes:
 *
 *   ual-realistic-100k.{csv,jsonl}    ual-realistic-1m.{csv,jsonl}    ual-adversarial-1m.{csv,jsonl}
 *   cloudtrail-realistic/*.json.gz    manifest.json
 *
 * Usage (from companion/):
 *   npx tsx scripts/cloud-scale-gen.ts [--out=<dir>] [--only=ual-realistic-100k,cloudtrail-realistic]
 *
 * The output is hundreds of MB to GB. It never goes into the repo: pass --out (default: a
 * `dfir-cloud-scale` folder in the OS temp dir). Never point it at `cases/`.
 *
 * SHAPES. UAL rows use the Microsoft-Extractor-Suite `UAL-Combined.csv` columns (RecordType,
 * CreationDate, UserIds, Operations, AuditData, ResultIndex, ResultCount, Identity) with AuditData
 * as an embedded JSON string; the .jsonl carries the same rows, one JSON object per line.
 * CloudTrail objects are `{"Records":[...]}`, gzip-compressed, named like S3 CloudTrail objects.
 * Everything is synthetic: example.com users, RFC 5737 addresses, account 123456789012.
 *
 * DENSITIES. "realistic" plants 1.5% of rows with an operation the importer grades High or Medium
 * (m365Import.ts M365_OPS, awsImport.ts); the rest are Info-graded reads and sign-ins.
 * "adversarial" is 1M UAL `UserLoginFailed` rows (Medium, M365_OPS) — a password spray from a few
 * hundred addresses against 1M distinct accounts, so no two rows aggregate together.
 *
 * REFERENCE COUNTS (manifest.json). For each dataset: `rows`, `hmRows` (rows planted High/Medium)
 * and `hmGroups` — the number of distinct aggregation keys among them, computed with the importer's
 * own key shape (`m365|workload|operation|user|ip`, lowercased). The importer folds rows that share
 * a key into one counted event, so `hmGroups` is the most High/Medium events an import can keep,
 * and `hmRows` is the most their `count` fields can sum to. CloudTrail High/Medium rows each get a
 * distinct principal, so for CloudTrail hmGroups == hmRows.
 *
 * WHY "1 GB" MEANS UNCOMPRESSED for the CloudTrail set. The importer reads decompressed text — it
 * cannot read gzip at all today (see the compatibility matrix), so an analyst decompresses first —
 * and every limit that matters (DFIR_MAX_IMPORT_FILE_MB, V8's ~512 MB string ceiling, heap) is on
 * the decompressed bytes. 1 GB *compressed* CloudTrail is roughly 10-20 GB of JSON, which no
 * import path can hold and which measures generation time, not the importer. So the set is ~1 GiB
 * of JSON (default 30 objects of 40,000 records, ~37 MB each), gzip-compressed as S3 delivers it; the manifest
 * records both sizes. The objects are larger than typical 5-minute S3 objects to keep the file
 * count — one import each — manageable.
 */
import {
  createWriteStream,
  existsSync,
  mkdirSync,
  readFileSync,
  writeFileSync,
  type WriteStream,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gzipSync } from "node:zlib";

const arg = (name: string): string | undefined =>
  process.argv.find((v) => v.startsWith(`--${name}=`))?.slice(name.length + 3);

const OUT = arg("out") ?? join(tmpdir(), "dfir-cloud-scale");
const ONLY = arg("only")?.split(",");
const CT_OBJECTS = Number(arg("ct-objects") ?? 30);
const CT_RECORDS = Number(arg("ct-records") ?? 40_000);
const HM_RATE = 0.015;
const TENANT = "00000000-0000-4000-8000-000000000001";
const ACCOUNT = "123456789012";

// Deterministic PRNG (mulberry32) so a rerun produces byte-identical files.
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
const pick = <T>(r: () => number, xs: readonly T[]): T => xs[Math.floor(r() * xs.length)];

// RFC 5737 documentation ranges only: 762 usable addresses.
const DOC_NETS = ["192.0.2", "198.51.100", "203.0.113"];
const docIp = (n: number): string => `${DOC_NETS[n % 3]}.${(Math.floor(n / 3) % 254) + 1}`;

const BASE_MS = Date.UTC(2026, 9, 1);
const isoAt = (r: () => number): string =>
  new Date(BASE_MS + Math.floor(r() * 30 * 86_400_000)).toISOString().slice(0, 19);

interface UalOp {
  op: string;
  workload: string;
  recordType: number;
  typeName: string;
}
const BENIGN_UAL: readonly UalOp[] = [
  {
    op: "UserLoggedIn",
    workload: "AzureActiveDirectory",
    recordType: 15,
    typeName: "AzureActiveDirectoryStsLogon",
  },
  { op: "FileAccessed", workload: "SharePoint", recordType: 6, typeName: "SharePointFileOperation" },
  { op: "FilePreviewed", workload: "SharePoint", recordType: 6, typeName: "SharePointFileOperation" },
  { op: "MailboxLogin", workload: "Exchange", recordType: 2, typeName: "ExchangeItem" },
];
const HM_UAL: readonly UalOp[] = [
  {
    op: "Add member to role.",
    workload: "AzureActiveDirectory",
    recordType: 8,
    typeName: "AzureActiveDirectory",
  },
  {
    op: "Reset user password.",
    workload: "AzureActiveDirectory",
    recordType: 8,
    typeName: "AzureActiveDirectory",
  },
  { op: "New-InboxRule", workload: "Exchange", recordType: 1, typeName: "ExchangeAdmin" },
  { op: "Set-Mailbox", workload: "Exchange", recordType: 1, typeName: "ExchangeAdmin" },
  {
    op: "UserLoginFailed",
    workload: "AzureActiveDirectory",
    recordType: 15,
    typeName: "AzureActiveDirectoryStsLogon",
  },
];
const LOGIN_FAILED = HM_UAL[4];

interface UalRow {
  typeName: string;
  creation: string;
  user: string;
  op: string;
  auditData: string;
  identity: string;
}

function ualRow(i: number, def: UalOp, user: string, ip: string, at: string, r: () => number): UalRow {
  const id = `00000000-0000-4000-9000-${i.toString(16).padStart(12, "0")}`;
  const failed = def.op === "UserLoginFailed";
  const ad: Record<string, unknown> = {
    CreationTime: at,
    Id: id,
    Operation: def.op,
    OrganizationId: TENANT,
    RecordType: def.recordType,
    ResultStatus: failed ? "Failed" : "Succeeded",
    UserKey: `1003BFFD${(i % 1e8).toString().padStart(8, "0")}`,
    UserType: 0,
    Version: 1,
    Workload: def.workload,
    ClientIP: ip,
    ObjectId:
      def.workload === "SharePoint"
        ? `https://example.com/sites/team/doc${Math.floor(r() * 200)}.docx`
        : user,
    UserId: user,
    UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0",
    AzureActiveDirectoryEventType: 1,
    ExtendedProperties: [
      { Name: "ResultStatusDetail", Value: failed ? "UserError" : "Success" },
      { Name: "RequestType", Value: "OAuth2:Authorize" },
    ],
    ...(failed ? { LogonError: "InvalidUserNameOrPassword", ErrorNumber: "50126" } : {}),
  };
  return {
    typeName: def.typeName,
    creation: at,
    user,
    op: def.op,
    auditData: JSON.stringify(ad),
    identity: id,
  };
}

const csvCell = (v: string): string => `"${v.replace(/"/g, '""')}"`;
const UAL_HEADER = [
  "RecordType",
  "CreationDate",
  "UserIds",
  "Operations",
  "AuditData",
  "ResultIndex",
  "ResultCount",
  "Identity",
];

async function write(stream: WriteStream, chunk: string): Promise<void> {
  if (!stream.write(chunk)) await new Promise<void>((res) => stream.once("drain", () => res()));
}
const close = (s: WriteStream): Promise<void> =>
  new Promise((res, rej) => s.end((e?: Error | null) => (e ? rej(e) : res())));

interface DatasetRef {
  files: string[];
  rows: number;
  hmRows: number;
  hmGroups: number;
  bytes: number;
  compressedBytes?: number;
}

async function writeUal(name: string, rows: number, adversarial: boolean): Promise<DatasetRef> {
  const r = rng(adversarial ? 7 : 11 + rows);
  const csvPath = join(OUT, `${name}.csv`);
  const jsonlPath = join(OUT, `${name}.jsonl`);
  const csv = createWriteStream(csvPath);
  const jsonl = createWriteStream(jsonlPath);
  await write(csv, UAL_HEADER.map(csvCell).join(",") + "\r\n");
  const groups = new Set<string>();
  let hmRows = 0;
  let bytes = 0;
  for (let i = 0; i < rows; i++) {
    let def: UalOp, user: string, ip: string;
    if (adversarial) {
      def = LOGIN_FAILED;
      user = `spray${i}@example.com`; // one account per row: nothing folds
      ip = docIp(Math.floor(r() * 300));
    } else if (r() < HM_RATE) {
      def = pick(r, HM_UAL);
      user = `admin${Math.floor(r() * 2000)}@example.com`;
      ip = docIp(Math.floor(r() * 300));
    } else {
      def = pick(r, BENIGN_UAL);
      user = `user${Math.floor(r() * 5000)}@example.com`;
      ip = docIp(Math.floor(r() * 762));
    }
    const row = ualRow(i, def, user, ip, isoAt(r), r);
    if (HM_UAL.includes(def)) {
      hmRows++;
      if (!adversarial) groups.add(`m365|${def.workload}|${def.op}|${user}|${ip}`.toLowerCase());
    }
    const cells = [
      row.typeName,
      row.creation,
      row.user,
      row.op,
      row.auditData,
      String(i + 1),
      String(rows),
      row.identity,
    ];
    const line = cells.map(csvCell).join(",") + "\r\n";
    bytes += line.length;
    await write(csv, line);
    await write(
      jsonl,
      JSON.stringify({
        RecordType: row.typeName,
        CreationDate: row.creation,
        UserIds: row.user,
        Operations: row.op,
        AuditData: row.auditData,
        ResultIndex: i + 1,
        ResultCount: rows,
        Identity: row.identity,
      }) + "\n",
    );
  }
  await Promise.all([close(csv), close(jsonl)]);
  return { files: [csvPath, jsonlPath], rows, hmRows, hmGroups: adversarial ? hmRows : groups.size, bytes };
}

const BENIGN_CT = [
  ["DescribeInstances", "ec2.amazonaws.com", true],
  ["DescribeVolumes", "ec2.amazonaws.com", true],
  ["ListBuckets", "s3.amazonaws.com", true],
  ["GetCallerIdentity", "sts.amazonaws.com", true],
  ["Decrypt", "kms.amazonaws.com", true],
] as const;
const HM_CT = [
  ["CreateAccessKey", "iam.amazonaws.com", false],
  ["AttachUserPolicy", "iam.amazonaws.com", false],
  ["StopLogging", "cloudtrail.amazonaws.com", false],
  ["GetSecretValue", "secretsmanager.amazonaws.com", true],
  ["AuthorizeSecurityGroupIngress", "ec2.amazonaws.com", false],
] as const;

function ctRecord(
  i: number,
  def: readonly [string, string, boolean],
  user: string,
  key: string,
  ip: string,
  at: string,
) {
  return {
    eventVersion: "1.09",
    userIdentity: {
      type: "IAMUser",
      principalId: `AIDA${key.slice(4)}`,
      arn: `arn:aws:iam::${ACCOUNT}:user/${user}`,
      accountId: ACCOUNT,
      accessKeyId: key,
      userName: user,
    },
    eventTime: `${at}Z`,
    eventSource: def[1],
    eventName: def[0],
    awsRegion: "us-east-1",
    sourceIPAddress: ip,
    userAgent: "aws-cli/2.15.0 Python/3.11.6 Linux/6.1 exe/x86_64",
    requestParameters: { maxResults: 100, filterSet: { items: [{ name: "instance-state-name" }] } },
    responseElements: null,
    requestID: `00000000-0000-4000-a000-${i.toString(16).padStart(12, "0")}`,
    eventID: `00000000-0000-4000-b000-${i.toString(16).padStart(12, "0")}`,
    readOnly: def[2],
    eventType: "AwsApiCall",
    managementEvent: true,
    recipientAccountId: ACCOUNT,
    eventCategory: "Management",
    tlsDetails: {
      tlsVersion: "TLSv1.3",
      cipherSuite: "TLS_AES_128_GCM_SHA256",
      clientProvidedHostHeader: "ec2.us-east-1.amazonaws.com",
    },
  };
}

function writeCloudTrail(): DatasetRef {
  const dir = join(OUT, "cloudtrail-realistic");
  mkdirSync(dir, { recursive: true });
  const r = rng(23);
  const files: string[] = [];
  let i = 0;
  let hmRows = 0;
  let bytes = 0;
  let compressedBytes = 0;
  for (let o = 0; o < CT_OBJECTS; o++) {
    const records = [];
    for (let k = 0; k < CT_RECORDS; k++, i++) {
      if (r() < HM_RATE) {
        // One principal (and access key) per High/Medium row, so each is its own aggregation group.
        records.push(
          ctRecord(
            i,
            pick(r, HM_CT),
            `ops${hmRows}`,
            `AKIAHM${String(hmRows).padStart(14, "0")}`,
            docIp(Math.floor(r() * 300)),
            isoAt(r),
          ),
        );
        hmRows++;
      } else {
        const u = Math.floor(r() * 50);
        records.push(
          ctRecord(
            i,
            pick(r, BENIGN_CT),
            `svc${u}`,
            `AKIABN${String(u).padStart(14, "0")}`,
            docIp(Math.floor(r() * 200)),
            isoAt(r),
          ),
        );
      }
    }
    const json = JSON.stringify({ Records: records });
    const gz = gzipSync(json);
    const name = `${ACCOUNT}_CloudTrail_us-east-1_20261101T${String(o).padStart(4, "0")}Z_EXAMPLE${String(o).padStart(10, "0")}.json.gz`;
    const path = join(dir, name);
    writeFileSync(path, gz);
    files.push(path);
    bytes += Buffer.byteLength(json);
    compressedBytes += gz.length;
  }
  return { files, rows: i, hmRows, hmGroups: hmRows, bytes, compressedBytes };
}

async function main(): Promise<void> {
  if (/[\\/]cases([\\/]|$)/.test(OUT)) throw new Error(`refusing to write under a cases/ folder: ${OUT}`);
  mkdirSync(OUT, { recursive: true });
  const want = (n: string): boolean => !ONLY || ONLY.includes(n);
  const manifestPath = join(OUT, "manifest.json");
  // Merged, so a partial --only run keeps the reference counts of the datasets it did not rewrite.
  const manifest: Record<string, DatasetRef> = existsSync(manifestPath)
    ? (JSON.parse(readFileSync(manifestPath, "utf8")) as Record<string, DatasetRef>)
    : {};
  const plan: Array<[string, () => Promise<DatasetRef> | DatasetRef]> = [
    ["ual-realistic-100k", () => writeUal("ual-realistic-100k", 100_000, false)],
    ["ual-realistic-1m", () => writeUal("ual-realistic-1m", 1_000_000, false)],
    ["ual-adversarial-1m", () => writeUal("ual-adversarial-1m", 1_000_000, true)],
    ["cloudtrail-realistic", writeCloudTrail],
  ];
  for (const [name, fn] of plan) {
    if (!want(name)) continue;
    const t0 = Date.now();
    manifest[name] = await fn();
    console.log(
      `${name}: ${JSON.stringify({ ...manifest[name], files: manifest[name].files.length })} in ${((Date.now() - t0) / 1000).toFixed(1)} s`,
    );
  }
  writeFileSync(manifestPath, JSON.stringify(manifest, null, 2));
  console.log(`wrote ${OUT}`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
