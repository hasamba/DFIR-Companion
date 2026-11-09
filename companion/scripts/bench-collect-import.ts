/**
 * Import-stage benchmark for live cloud collections (#2478). bench-cloud-import.ts measures ONE
 * uploaded file; this measures the page-by-page import step a live AWS / Microsoft / GCP collection
 * runs after its download (#2311, shown as its own job step since #2470): every saved page, one at a
 * time, through the PRODUCTION page importer (routes/cloudCollectImporter.ts — import section,
 * "did this page land?", forget a dead attempt, baseline, the #2303 streaming importer, settle:
 * dual-write → content tagger → demote) and the engine's per-page checkpoint write.
 *
 * Usage (from companion/):
 *   npx tsx scripts/bench-collect-import.ts [--runs=aws-100k,gcp-100k] [--out=<dir>]
 *       [--heap-mb=4096] [--keep]
 *   npm run bench:collect-import -- --runs=aws-10k
 *
 * Runs: aws-<n>k = n×1000 CloudTrail records in 50-record pages (LookupEvents' page size), gcp-<n>k
 * = n×1000 GCP audit entries in 1,000-entry pages (entries.list's page size). Each run is its own
 * child process over a throwaway cases root under --out (default: a fresh temp folder; a path in or
 * named `cases` is refused, benchOutputGuard.ts). Nothing is read from or written to `cases/`.
 *
 * HOW THE CASE IS BUILT. The child wires the stores exactly as startServer does (createRuntimeStores
 * → buildBulkImportSink → buildAiRuntime → buildAppOptions) and then hands caseCollectImporter the
 * route-context fields it reads — the import lock (as createApp builds it), the state lock, the
 * server logger and the import demote — so a page crosses the same code a live collection's does.
 * The pages themselves come from a scripted provider session through the real engine
 * (createCollection → runCollection over nodeCollectFs), so the manifest, the page files, their
 * hashes and the per-page checkpoint are the production ones. No AI provider; default settings.
 *
 * WHAT IS REPORTED, per run: the import stage's wall time and pages/s, the child's peak RSS
 * (VmHWM), and the time spent per phase — lock (waiting for the import section), landed, forget,
 * importer (pipeline.importCloudFile), baselineSettle (the rest of the page's import call: the
 * baseline, the settle's scoped passes and the content tagger), and three parts of it measured on
 * their own — baseline (capture + disarm), dualWrite (super-timeline append), demote — and
 * checkpoint (the engine's checkpoint.json writes) — plus the mean page time over the first and last 10% of pages,
 * which shows whether the per-page cost grows with the pages already imported. Linux only (VmHWM).
 */
import { spawn } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { safeOutputDir } from "./benchOutputGuard.js";
import type { CollectPageImporter } from "../src/integrations/cloudCollect/collectImport.js";
import type { CollectFs } from "../src/integrations/cloudCollect/collectFs.js";
import type { CloudCollectSession, CollectPage } from "../src/integrations/cloudCollect/collectTypes.js";
import type { RouteContext } from "../src/routes/context.js";

const arg = (name: string): string | undefined =>
  process.argv.find((v) => v.startsWith(`--${name}=`))?.slice(name.length + 3);

const CASE_ID = "bench";
const COLLECTION_ID = "cc-bench-0001";
const AWS_PAGE_RECORDS = 50; // aws/awsLookupEvents.ts PAGE_SIZE
const GCP_PAGE_RECORDS = 1000; // cloudCollectGcp/gcpFilter.ts page size
const DEFAULT_RUNS = ["aws-100k", "gcp-100k"];
/** #2478's threshold: a 100k-record import step well over this needs a fix. */
const THRESHOLD_MIN = 30;

interface RunSpec {
  name: string;
  provider: "aws" | "gcp";
  pages: number;
  perPage: number;
}

export function parseRun(name: string): RunSpec {
  const m = /^(aws|gcp)-(\d+)k$/.exec(name);
  if (!m) throw new Error(`unknown run "${name}" (expected aws-<n>k or gcp-<n>k)`);
  const provider = m[1] as "aws" | "gcp";
  const perPage = provider === "aws" ? AWS_PAGE_RECORDS : GCP_PAGE_RECORDS;
  const records = Number(m[2]) * 1000;
  return { name, provider, perPage, pages: Math.max(1, Math.ceil(records / perPage)) };
}

// ───────────────────────────── synthetic records ─────────────────────────────
// Documentation account id, TEST-NET addresses, example.com principals. Mostly read-only noise
// (graded Info, demoted), with a High/Medium operation every 25th record — the realistic mix.

const AWS_OPS = [
  ["DescribeInstances", "ec2.amazonaws.com"],
  ["GetObject", "s3.amazonaws.com"],
  ["ListBuckets", "s3.amazonaws.com"],
  ["AssumeRole", "sts.amazonaws.com"],
] as const;
const AWS_HM = [
  ["CreateAccessKey", "iam.amazonaws.com"],
  ["StopLogging", "cloudtrail.amazonaws.com"],
  ["AttachUserPolicy", "iam.amazonaws.com"],
] as const;

const at = (i: number): string =>
  new Date(Date.UTC(2026, 9, 1) + (i % 86_400) * 1000).toISOString().replace(".000", "");

function awsRecord(i: number) {
  const [name, source] = i % 25 === 0 ? AWS_HM[(i / 25) % AWS_HM.length] : AWS_OPS[i % AWS_OPS.length];
  const user = `ops${i % 40}`;
  return {
    eventVersion: "1.09",
    eventID: `00000000-0000-4000-b000-${i.toString(16).padStart(12, "0")}`,
    eventTime: at(i),
    eventSource: source,
    eventName: name,
    awsRegion: "us-east-1",
    sourceIPAddress: `198.51.100.${i % 200}`,
    userAgent: "aws-cli/2.15.0",
    readOnly: i % 25 !== 0,
    userIdentity: {
      type: "IAMUser",
      arn: `arn:aws:iam::123456789012:user/${user}`,
      accountId: "123456789012",
      userName: user,
    },
  };
}

const GCP_OPS = ["storage.objects.get", "storage.objects.list", "compute.instances.get"];
const GCP_HM = ["SetIamPolicy", "google.iam.admin.v1.CreateServiceAccountKey"];

function gcpRecord(i: number) {
  const method = i % 25 === 0 ? GCP_HM[(i / 25) % GCP_HM.length] : GCP_OPS[i % GCP_OPS.length];
  const log = i % 25 === 0 ? "activity" : "data_access";
  const ts = at(i).replace("Z", ".000000Z");
  return {
    protoPayload: {
      "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
      status: {},
      authenticationInfo: { principalEmail: `admin${i % 40}@example.com` },
      requestMetadata: { callerIp: `203.0.113.${i % 200}`, callerSuppliedUserAgent: "google-cloud-sdk" },
      serviceName: method.startsWith("storage") ? "storage.googleapis.com" : "iam.googleapis.com",
      methodName: method,
      resourceName: `projects/bench-project/serviceAccounts/sa${i % 40}@bench-project.iam.gserviceaccount.com`,
    },
    insertId: `insert${String(i).padStart(9, "0")}`,
    resource: { type: "service_account", labels: { project_id: "bench-project" } },
    timestamp: ts,
    severity: "NOTICE",
    logName: `projects/bench-project/logs/cloudaudit.googleapis.com%2F${log}`,
    receiveTimestamp: ts,
  };
}

/** A provider session that serves `spec.pages` pages, tokens "p1", "p2", … */
function scriptedSession(spec: RunSpec): CloudCollectSession {
  return {
    identity: async () => ({
      accountRef: "123456789012",
      caller: "arn:aws:iam::123456789012:role/bench",
      sdkVersions: { bench: "1.0.0" },
    }),
    fetchPage: async (req): Promise<CollectPage> => {
      const index = req.pageToken ? Number(req.pageToken.slice(1)) : 0;
      const first = index * spec.perPage + 1;
      const ids = Array.from({ length: spec.perPage }, (_, k) => first + k);
      const body =
        spec.provider === "aws" ? { Records: ids.map(awsRecord) } : { entries: ids.map(gcpRecord) };
      const next = index + 1 < spec.pages ? `p${index + 1}` : undefined;
      return {
        body: Buffer.from(JSON.stringify(body)),
        extension: "json",
        recordCount: ids.length,
        ...(next ? { nextPageToken: next } : {}),
        requestId: `req-${index}`,
        requestParams: { page: String(index), source: req.source },
      };
    },
  };
}

// ───────────────────────────── child: one run ─────────────────────────────

type Phase =
  | "lock"
  | "landed"
  | "forget"
  | "importer"
  | "baselineSettle"
  | "baseline"
  | "dualWrite"
  | "demote"
  | "checkpoint";

class Timers {
  readonly ms: Record<Phase, number> = {
    lock: 0,
    landed: 0,
    forget: 0,
    importer: 0,
    baselineSettle: 0,
    baseline: 0,
    dualWrite: 0,
    demote: 0,
    checkpoint: 0,
  };
  readonly pageMs: number[] = [];
  add(phase: Phase, ms: number): void {
    this.ms[phase] += ms;
  }
  async time<T>(phase: Phase, fn: () => Promise<T>): Promise<T> {
    const t0 = performance.now();
    try {
      return await fn();
    } finally {
      this.add(phase, performance.now() - t0);
    }
  }
}

/** The engine's checkpoint.json writes, timed; every other fs call passes through untouched. */
function timedFs(fs: CollectFs, timers: Timers): CollectFs {
  const isCheckpoint = (p: unknown): boolean => /checkpoint\.json/.test(String(p));
  const wrap =
    <A extends unknown[], R>(fn: (...args: A) => Promise<R>) =>
    (...args: A): Promise<R> =>
      isCheckpoint(args[0]) || isCheckpoint(args[1])
        ? timers.time("checkpoint", () => fn(...args))
        : fn(...args);
  return {
    ...fs,
    writeFileSync: wrap(fs.writeFileSync),
    rename: wrap(fs.rename),
    // The checkpoint's directory fsync: the collection folder itself (collectCheckpoint.ts).
    fsyncDir: (dir) =>
      /pages$/.test(dir) ? fs.fsyncDir(dir) : timers.time("checkpoint", () => fs.fsyncDir(dir)),
  };
}

/** The production importer, each phase timed. `importer` time is part of `baselineSettle`'s call. */
function timedImporter(inner: CollectPageImporter, timers: Timers): CollectPageImporter {
  return {
    withImportSection: (caseId, fn) => {
      const asked = performance.now();
      return inner.withImportSection(caseId, () => {
        timers.add("lock", performance.now() - asked);
        return fn();
      });
    },
    landed: (c, l) => timers.time("landed", () => inner.landed(c, l)),
    forgetAttempt: (c, l) => timers.time("forget", () => inner.forgetAttempt(c, l)),
    settleLanded: (c, l) => inner.settleLanded(c, l),
    // #2482's once-per-collection summary step: passed through, timed as part of the settle.
    summarizesPerCollection: (kind) => inner.summarizesPerCollection(kind),
    importSummary: (c, req, signal) =>
      timers.time("baselineSettle", () => inner.importSummary(c, req, signal)),
    importPage: async (c, page, signal) => {
      const t0 = performance.now();
      const before = timers.ms.importer;
      await inner.importPage(c, page, signal);
      const total = performance.now() - t0;
      timers.pageMs.push(total);
      timers.add("baselineSettle", total - (timers.ms.importer - before));
    },
  };
}

/** `target` with the named async methods timed under `phase`; every other member passes through. */
function timedMethods<T extends object>(
  target: T,
  methods: readonly string[],
  phase: Phase,
  timers: Timers,
): T {
  return new Proxy(target, {
    get(obj, prop, receiver) {
      const value = Reflect.get(obj, prop, receiver);
      if (typeof value !== "function") return value;
      if (!methods.includes(String(prop))) return value.bind(obj);
      return (...args: unknown[]) => timers.time(phase, () => value.apply(obj, args));
    },
  });
}

function vmHwmMiB(): number {
  const m = /VmHWM:\s+(\d+)\s+kB/.exec(readFileSync("/proc/self/status", "utf8"));
  return m ? Math.round(Number(m[1]) / 1024) : 0;
}

async function buildContext(root: string, timers: Timers) {
  const { createRuntimeStores } = await import("../src/composition/runtimeStores.js");
  const { buildBulkImportSink } = await import("../src/composition/bulkImportSink.js");
  const { buildAiRuntime } = await import("../src/composition/aiRuntime.js");
  const { buildAppOptions } = await import("../src/composition/appWiring.js");
  const { startMaintenanceTasks } = await import("../src/composition/maintenanceTasks.js");
  const { createImportDemote } = await import("../src/composition/importDemote.js");
  const { ImportLock } = await import("../src/analysis/importLock.js");
  const { createImportMemoryGuard } = await import("../src/analysis/importMemoryGuard.js");
  const { getServerLogger } = await import("../src/logging/serverLogger.js");

  const rt = createRuntimeStores({
    casesRoot: root,
    host: "127.0.0.1",
    port: 0,
    logDir: join(root, "..", "logs"),
  });
  const { store, stateStore } = rt;
  const maintenance = startMaintenanceTasks({
    store,
    custodyStore: rt.custodyStore,
    notifier: rt.notifier,
    dashboardBaseUrl: rt.dashboardBaseUrl,
  });
  const bulkImportSink = buildBulkImportSink({
    stateStore,
    superTimelineStore: rt.superTimelineStore,
    taggerStore: rt.taggerStore,
    tagsStore: rt.tagsStore,
    forensicGateControlStore: rt.forensicGateControlStore,
    analysisRunStore: rt.analysisRunStore,
    log: () => {},
  });
  const ai = buildAiRuntime({
    store,
    stateStore,
    bulkImportSink,
    stateLock: rt.stateLock,
    logger: rt.logger,
    kevStore: rt.kevStore,
    clockSkewStore: rt.clockSkewStore,
    incidentTypeStore: rt.incidentTypeStore,
    analysisRunStore: rt.analysisRunStore,
    operationalMetrics: rt.operationalMetrics,
    secondOpinionStore: rt.secondOpinionStore,
    velociraptorClientStore: rt.velociraptorClientStore,
    notifier: rt.notifier,
    dashboardBaseUrl: rt.dashboardBaseUrl,
    onState: () => {},
  });
  const pipeline = timedMethods(ai.wiredPipeline, ["importCloudFile"], "importer", timers);
  const options = buildAppOptions(rt, {
    pipeline,
    provider: ai.provider,
    secondOpinionProvider: ai.secondOpinionProvider,
    ocrRunner: ai.ocrRunner,
    bulkImportSink,
    ...maintenance,
    onPreflightReady: () => {},
  });
  // createApp's own definitions of the four route-context fields caseCollectImporter reads.
  const runStateExclusive = <T>(caseId: string, fn: () => Promise<T>): Promise<T> =>
    options.stateLock ? options.stateLock.runExclusive(caseId, fn) : fn();
  const importLock =
    options.importLock ??
    new ImportLock(
      createImportMemoryGuard({
        countEvents: async (caseId) =>
          (await stateStore.queryForensicTimeline(caseId, { limit: 1, includeTotal: true })).total,
      }),
    );
  const { demoteForensic } = createImportDemote({ options, runStateExclusive });
  // The page importer's view of the stores: the same objects, with the baseline capture/release
  // and the super-timeline dual-write timed (both run inside importPage, outside the importer).
  const timedOptions = {
    ...options,
    stateStore: timedMethods(
      stateStore,
      ["captureImportBaseline", "disarmImportJournal"],
      "baseline",
      timers,
    ),
    superTimelineStore: timedMethods(
      rt.superTimelineStore,
      ["append", "appendReporting"],
      "dualWrite",
      timers,
    ),
  };
  const ctx = {
    store,
    options: timedOptions,
    importLock,
    runStateExclusive,
    serverLogger: getServerLogger(),
    demoteForensic: (caseId: string) => timers.time("demote", () => demoteForensic(caseId)),
  } as unknown as RouteContext;
  await store.createCase({ caseId: CASE_ID, name: "bench", investigator: "bench", aiProvider: null });
  return { ctx, stateStore, superTimelineStore: rt.superTimelineStore };
}

async function child(): Promise<void> {
  const spec = parseRun(arg("run")!);
  const root = arg("cases-root")!;
  const timers = new Timers();
  const { ctx, stateStore, superTimelineStore } = await buildContext(root, timers);
  const { createCollection, runCollection } =
    await import("../src/integrations/cloudCollect/collectEngine.js");
  const { nodeCollectFs } = await import("../src/integrations/cloudCollect/collectFs.js");
  const { caseCollectImporter } = await import("../src/routes/cloudCollectImporter.js");
  const { collectionDir } = await import("../src/routes/cloudCollectJob.js");

  const dir = collectionDir(ctx, CASE_ID, COLLECTION_ID);
  const session = scriptedSession(spec);
  const now = () => new Date().toISOString();
  const source = {
    id: "bench-src",
    label: "bench",
    streamKind: spec.provider === "aws" ? "aws" : "cloud",
  } as const;
  const window = { start: "2026-10-01T00:00:00Z", end: "2026-10-02T00:00:00Z" };
  await createCollection(
    nodeCollectFs,
    session,
    {
      dir,
      collectionId: COLLECTION_ID,
      caseId: CASE_ID,
      accountId: "bench",
      accountName: "bench",
      provider: spec.provider,
      sources: [source.id],
      window,
      filters: {},
      companionVersion: "0.0.0-bench",
    },
    now,
  );
  const started = performance.now();
  let importStarted = 0;
  const fs = timedFs(nodeCollectFs, timers);
  await runCollection(
    {
      fs,
      session,
      importer: timedImporter(caseCollectImporter(ctx), timers),
      sources: [source],
      now,
      onProgress: (p) => {
        if (p.stage !== "import" || importStarted) return;
        importStarted = performance.now();
        timers.ms.checkpoint = 0; // count the import stage's checkpoint writes only
      },
    },
    dir,
    { resume: false },
  );
  const ended = performance.now();
  const state = await stateStore.load(CASE_ID);
  const superMeta = await superTimelineStore.meta(CASE_ID);
  const importS = (ended - importStarted) / 1000;
  const tenth = Math.max(1, Math.floor(timers.pageMs.length / 10));
  const mean = (xs: number[]) => xs.reduce((a, b) => a + b, 0) / Math.max(1, xs.length);
  const phasesS = Object.fromEntries(
    Object.entries(timers.ms).map(([k, v]) => [k, Number((v / 1000).toFixed(2))]),
  );
  const result = {
    run: spec.name,
    pages: spec.pages,
    recordsPerPage: spec.perPage,
    records: spec.pages * spec.perPage,
    downloadS: Number(((importStarted - started) / 1000).toFixed(1)),
    importS: Number(importS.toFixed(1)),
    pagesPerS: Number((spec.pages / importS).toFixed(2)),
    projected100kMin: Number((((importS / (spec.pages * spec.perPage)) * 100_000) / 60).toFixed(1)),
    peakRssMiB: vmHwmMiB(),
    phasesS,
    firstTenthPageMs: Math.round(mean(timers.pageMs.slice(0, tenth))),
    lastTenthPageMs: Math.round(mean(timers.pageMs.slice(-tenth))),
    forensicEvents: state.forensicTimeline.length,
    superRows: superMeta.rows,
  };
  process.stdout.write(`RESULT ${JSON.stringify(result)}\n`);
  process.exit(0);
}

// ───────────────────────────── parent ─────────────────────────────

function runChild(run: string, out: string, heapMb: number): Promise<Record<string, unknown>> {
  const root = join(out, run, "bench-root");
  rmSync(join(out, run), { recursive: true, force: true });
  const self = fileURLToPath(import.meta.url);
  const nodeArgs = [`--max-old-space-size=${heapMb}`, "--import", "tsx/esm", self, "--child", `--run=${run}`];
  const proc = spawn(process.execPath, [...nodeArgs, `--cases-root=${root}`], {
    env: { ...process.env, DFIR_CASES_ROOT: root },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let stdout = "";
  let stderr = "";
  proc.stdout.on("data", (d) => (stdout += d));
  proc.stderr.on("data", (d) => (stderr = (stderr + d).slice(-20_000)));
  if (process.env.BENCH_DEBUG) proc.stderr.pipe(process.stderr);
  return new Promise((resolve) =>
    proc.on("exit", (code, sig) => {
      const line = stdout.split("\n").find((l) => l.startsWith("RESULT "));
      resolve(
        line ? JSON.parse(line.slice(7)) : { run, error: `exit ${sig ?? code}`, stderr: stderr.slice(-2000) },
      );
    }),
  );
}

async function parent(): Promise<void> {
  const out = safeOutputDir(arg("out") ?? mkdtempSync(join(tmpdir(), "dfir-bench-collect-")));
  const runs = (arg("runs") ?? DEFAULT_RUNS.join(",")).split(",").filter(Boolean);
  const heapMb = Number(arg("heap-mb") ?? 4096);
  runs.forEach(parseRun); // refuse a bad name before any run starts
  process.stdout.write(
    `bench-collect-import: ${runs.join(", ")} → ${out} (threshold ${THRESHOLD_MIN} min / 100k)\n`,
  );
  for (const run of runs) {
    const result = await runChild(run, out, heapMb);
    process.stdout.write(`${JSON.stringify(result)}\n`);
    if (!process.argv.includes("--keep")) rmSync(join(out, run), { recursive: true, force: true });
  }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  (process.argv.includes("--child") ? child() : parent()).catch((err) => {
    process.stderr.write(`${(err as Error).stack ?? err}\n`);
    process.exit(1);
  });
}
