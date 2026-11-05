/**
 * Scale baseline for large cloud exports (#2300): sends the files cloud-scale-gen.ts wrote to a
 * real companion server over HTTP, one run per server process, and reports per run: peak RSS, CPU
 * time, wall time, events written to the super-timeline, and High/Medium events kept in the
 * forensic timeline against the generator's reference counts (manifest.json).
 *
 * Usage (from companion/; generate first):
 *   npx tsx scripts/cloud-scale-gen.ts --out=<dir>
 *   npx tsx scripts/bench-cloud-import.ts --dir=<dir> [--heap-mb=4096] [--timeout-min=30]
 *       [--runs=ual-realistic-100k.csv,ual-realistic-100k.jsonl,...,cloudtrail-realistic]
 *       [--max-import-mb=<n>]
 *
 * WHAT "THE REAL IMPORT PATH" MEANS HERE. The child process builds the app exactly as startServer
 * does (createRuntimeStores → buildAiRuntime → buildAppOptions → createApp) over a throwaway cases
 * root inside --dir, and listens on 127.0.0.1. The parent uploads the way the dashboard's Import
 * button does (public/js/dashboard-unified-import.js): a file up to 200 MB is streamed as the JSON
 * body of POST /cases/:id/import; a larger one is handed to POST /cases/:id/import-file by path.
 * The child reports each finished import job. So a run covers sniff, the importer, aggregation and
 * its cap, the super-timeline dual-write, the content tagger and the demote, and the server
 * process's memory is not inflated by the client's copy of the file. No AI provider is configured;
 * every kind measured is deterministic. Settings are the defaults (DFIR_MAX_EVENTS 2000,
 * DFIR_MAX_BODY_MB 256, DFIR_MAX_IMPORT_FILE_MB 256) unless --max-import-mb raises the last one.
 *
 * Each run is a separate `node --max-old-space-size=<heap-mb>` server, one at a time. The parent
 * samples /proc/<pid>/status (VmHWM) and /proc/<pid>/stat (utime+stime) every 250 ms, so a server
 * that dies of OOM still gets its peak RSS and CPU recorded. Linux only.
 */
import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import {
  createReadStream,
  createWriteStream,
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { request as httpRequest } from "node:http";
import { createInterface } from "node:readline";
import { basename, join } from "node:path";
import { gunzipSync } from "node:zlib";
import { fileURLToPath } from "node:url";

const arg = (name: string): string | undefined =>
  process.argv.find((v) => v.startsWith(`--${name}=`))?.slice(name.length + 3);

const DEFAULT_RUNS = [
  "idle",
  "ual-realistic-100k.csv",
  "ual-realistic-100k.jsonl",
  "ual-realistic-1m.csv",
  "ual-realistic-1m.jsonl",
  "ual-adversarial-1m.csv",
  "ual-adversarial-1m.jsonl",
  "cloudtrail-realistic",
];
/** public/js/dashboard-unified-import.js LARGE_FILE_MB: above it the dashboard asks for a server path. */
const LARGE_FILE_BYTES = 200 * 1024 * 1024;
const CASE_ID = "bench";

interface ServerResult {
  forensicEvents: number;
  hmEvents: number;
  hmCountSum: number;
  hmLineageEvents: number;
  maxRssKiB: number;
  cpuUserMs: number;
  cpuSystemMs: number;
}

// ───────────────────────────── child: a real server ─────────────────────────────

async function server(): Promise<void> {
  const root = arg("cases-root")!;
  const { createRuntimeStores } = await import("../src/composition/runtimeStores.js");
  const { startMaintenanceTasks } = await import("../src/composition/maintenanceTasks.js");
  const { buildBulkImportSink } = await import("../src/composition/bulkImportSink.js");
  const { buildAiRuntime } = await import("../src/composition/aiRuntime.js");
  const { buildAppOptions } = await import("../src/composition/appWiring.js");
  const { createApp } = await import("../src/server.js");

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
  const sinkStores = {
    superTimelineStore: rt.superTimelineStore,
    taggerStore: rt.taggerStore,
    tagsStore: rt.tagsStore,
  };
  const bulkImportSink = buildBulkImportSink({
    stateStore,
    ...sinkStores,
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
  const options = buildAppOptions(rt, {
    pipeline: ai.wiredPipeline,
    provider: ai.provider,
    secondOpinionProvider: ai.secondOpinionProvider,
    ocrRunner: ai.ocrRunner,
    bulkImportSink,
    ...maintenance,
    onPreflightReady: () => {},
  });
  const app = createApp(store, options);
  await store.createCase({ caseId: CASE_ID, name: "bench", investigator: "bench", aiProvider: null });

  // Report every import job that reaches a terminal state, with the import-meta it left behind.
  const reported = new Set<string>();
  const poll = setInterval(() => {
    for (const job of options.jobManager?.list(CASE_ID) ?? []) {
      if (job.status === "queued" || job.status === "running" || reported.has(job.id)) continue;
      reported.add(job.id);
      void options.importMetaStore!.load(CASE_ID).then((meta) => {
        const done = {
          status: job.status,
          error: job.error,
          file: meta.lastImportFile,
          superTimelineAdded: meta.superTimelineAddedCount,
        };
        process.stdout.write(`DONE ${JSON.stringify(done)}\n`);
      });
    }
  }, 200);

  const listener = app.listen(0, "127.0.0.1", () => {
    const addr = listener.address();
    process.stdout.write(`READY ${typeof addr === "object" && addr ? addr.port : 0}\n`);
  });
  process.stdin.on("data", async (d) => {
    if (!String(d).includes("END")) return;
    clearInterval(poll);
    const state = await stateStore.load(CASE_ID);
    const hm = state.forensicTimeline.filter((e) => e.severity === "High" || e.severity === "Medium");
    const isLineage = (e: (typeof hm)[number]) => e.description.startsWith("AWS credential lineage");
    const usage = process.resourceUsage();
    const result: ServerResult = {
      forensicEvents: state.forensicTimeline.length,
      hmEvents: hm.filter((e) => !isLineage(e)).length,
      hmCountSum: hm.filter((e) => !isLineage(e)).reduce((n, e) => n + (e.count ?? 1), 0),
      hmLineageEvents: hm.filter(isLineage).length,
      maxRssKiB: usage.maxRSS,
      cpuUserMs: Math.round(usage.userCPUTime / 1000),
      cpuSystemMs: Math.round(usage.systemCPUTime / 1000),
    };
    process.stdout.write(`RESULT ${JSON.stringify(result)}\n`);
    process.exit(0);
  });
}

// ───────────────────────────── parent: the dashboard's side of the upload ─────────────────────────────

interface Sample {
  hwmKiB: number;
  cpuMs: number;
}
const CLK_TCK = 100; // USER_HZ on Linux

function sample(pid: number, prev: Sample): Sample {
  try {
    const status = readFileSync(`/proc/${pid}/status`, "utf8");
    const hwm = Number(/VmHWM:\s+(\d+)/.exec(status)?.[1] ?? 0);
    const stat = readFileSync(`/proc/${pid}/stat`, "utf8");
    const fields = stat.slice(stat.lastIndexOf(")") + 2).split(" ");
    const cpuMs = ((Number(fields[11]) + Number(fields[12])) * 1000) / CLK_TCK;
    return { hwmKiB: Math.max(prev.hwmKiB, hwm), cpuMs: Math.max(prev.cpuMs, cpuMs) };
  } catch {
    return prev; // the process is gone; keep the last reading
  }
}

/** POST a JSON body; the `text` of an upload is streamed from disk, never held whole here. */
function post(
  port: number,
  path: string,
  head: string,
  file?: string,
): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      { host: "127.0.0.1", port, path, method: "POST", headers: { "content-type": "application/json" } },
      (res) => {
        let body = "";
        res.on("data", (d) => (body += d));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, body }));
      },
    );
    req.on("error", reject);
    if (!file) return req.end(head);
    req.write(`${head.slice(0, -1)},"text":"`);
    const rs = createReadStream(file, { encoding: "utf8", highWaterMark: 1 << 20 });
    rs.on("data", (chunk) => {
      if (!req.write(JSON.stringify(chunk).slice(1, -1))) {
        rs.pause();
        req.once("drain", () => rs.resume());
      }
    });
    rs.on("end", () => req.end(`"}`));
    rs.on("error", reject);
  });
}

/** The files one run imports. A CloudTrail set is decompressed first: the companion cannot read gzip. */
async function runFiles(dir: string, run: string, work: string): Promise<{ files: string[]; note: string }> {
  if (run === "idle") return { files: [], note: "server start, no import: the floor every run sits on" };
  const split = /^(.+)@(\d+)$/.exec(run);
  if (split) return splitFile(join(dir, split[1]), Number(split[2]), work);
  if (run !== "cloudtrail-realistic") return { files: [join(dir, run)], note: "" };
  const src = join(dir, run);
  const out = join(work, "gunzipped");
  mkdirSync(out, { recursive: true });
  const gz = readdirSync(src)
    .filter((f) => f.endsWith(".json.gz"))
    .sort();
  const files = [join(src, gz[0])]; // the first object is also offered as downloaded, to record the refusal
  for (const f of gz) {
    const target = join(out, f.replace(/\.gz$/, ""));
    writeFileSync(target, gunzipSync(readFileSync(join(src, f))));
    files.push(target);
  }
  return { files, note: `${gz.length} objects, gunzipped before import; the first also offered as .gz` };
}

/**
 * `<file>@<n>`: the file cut into n consecutive parts by line, the CSV header repeated in each — what
 * an analyst does with an export over the 256 MB ceiling. The generator writes no multi-line cells.
 */
async function splitFile(
  src: string,
  parts: number,
  work: string,
): Promise<{ files: string[]; note: string }> {
  const csv = src.endsWith(".csv");
  const lines = createInterface({ input: createReadStream(src, { encoding: "utf8" }), crlfDelay: Infinity });
  const size = /(\d+)(k|m)\./.exec(basename(src)); // the generator names the row count: -100k. / -1m.
  const total = size ? Number(size[1]) * (size[2] === "k" ? 1e3 : 1e6) : NaN;
  const per = Math.ceil(total / parts);
  const files: string[] = [];
  let header = "";
  let out: ReturnType<typeof createWriteStream> | null = null;
  let n = 0;
  for await (const line of lines) {
    if (csv && !header) {
      header = line;
      continue;
    }
    if (n % per === 0) {
      if (out) await new Promise((r) => out!.end(r));
      const name = basename(src).replace(/(\.\w+)$/, `-part${files.length + 1}of${parts}$1`);
      files.push(join(work, name));
      out = createWriteStream(files[files.length - 1]);
      if (csv) out.write(header + "\r\n");
    }
    if (!out!.write(line + (csv ? "\r\n" : "\n")))
      await new Promise<void>((r) => out!.once("drain", () => r()));
    n++;
  }
  if (out) await new Promise((r) => out.end(r));
  return { files, note: `${n} rows split into ${files.length} files of ${per} rows` };
}

/** Lines from the server's stdout, awaited one prefix at a time. */
function lineReader(proc: ChildProcessWithoutNullStreams) {
  const lines: string[] = [];
  let buf = "";
  let wake: (() => void) | null = null;
  proc.stdout.on("data", (d) => {
    buf += d;
    const parts = buf.split("\n");
    buf = parts.pop() ?? "";
    lines.push(...parts);
    wake?.();
  });
  const exited = new Promise<void>((r) => proc.on("exit", () => r()));
  return async (prefix: string): Promise<string | null> => {
    for (;;) {
      const i = lines.findIndex((l) => l.startsWith(prefix));
      if (i >= 0) return lines.splice(i, 1)[0].slice(prefix.length + 1);
      if (proc.exitCode !== null || proc.signalCode !== null) return null;
      await Promise.race([new Promise<void>((r) => (wake = r)), exited]);
    }
  };
}

async function oneRun(
  dir: string,
  run: string,
  heapMb: number,
  timeoutMin: number,
): Promise<Record<string, unknown>> {
  const work = join(dir, "work", run.replace(/[^\w.-]/g, "_"));
  rmSync(work, { recursive: true, force: true });
  mkdirSync(join(work, "cases"), { recursive: true });
  const { files, note } = await runFiles(dir, run, work);
  const maxImportMb = arg("max-import-mb");
  const env = { ...process.env, ...(maxImportMb ? { DFIR_MAX_IMPORT_FILE_MB: maxImportMb } : {}) };
  const self = fileURLToPath(import.meta.url);
  const nodeArgs = [
    `--max-old-space-size=${heapMb}`,
    "--import",
    "tsx/esm",
    self,
    "--server",
    `--cases-root=${join(work, "cases")}`,
  ];
  const started = Date.now();
  const proc = spawn(process.execPath, nodeArgs, { env, stdio: ["pipe", "pipe", "pipe"] });
  // Captured now: a server killed by a signal (V8 aborts on heap exhaustion) has exitCode null.
  const exit = new Promise<string>((res) => proc.on("exit", (c, sig) => res(sig ?? String(c))));
  let s: Sample = { hwmKiB: 0, cpuMs: 0 };
  const timer = setInterval(() => (s = sample(proc.pid!, s)), 250);
  let stderr = "";
  proc.stderr.on("data", (d) => (stderr = (stderr + d).slice(-100_000)));
  if (process.env.BENCH_DEBUG) proc.stderr.pipe(process.stderr);
  const killer = setTimeout(() => proc.kill("SIGKILL"), timeoutMin * 60_000);
  const next = lineReader(proc);
  const imports: Array<Record<string, unknown>> = [];
  let superTimelineAdded = 0;
  let result: ServerResult | null = null;
  const port = Number(await next("READY"));
  try {
    for (const file of files) {
      const large = statSync(file).size > LARGE_FILE_BYTES;
      const res = large
        ? await post(port, `/cases/${CASE_ID}/import-file`, JSON.stringify({ path: file }))
        : await post(port, `/cases/${CASE_ID}/import`, JSON.stringify({ filename: basename(file) }), file);
      const body = JSON.parse(res.body || "{}") as { kind?: string; error?: string };
      const entry: Record<string, unknown> = {
        file: basename(file),
        route: large ? "import-file" : "import",
        status: res.status,
        kind: body.kind,
      };
      if (res.status !== 202) entry.error = String(body.error ?? "").slice(0, 240);
      else {
        const done = await next("DONE");
        if (done === null) throw new Error("server exited during the import");
        const d = JSON.parse(done) as { status: string; error?: string; superTimelineAdded?: number };
        Object.assign(entry, { job: d.status, ...(d.error ? { jobError: d.error.slice(0, 240) } : {}) });
        superTimelineAdded += d.superTimelineAdded ?? 0;
      }
      imports.push(entry);
      console.error(`  ${JSON.stringify(entry)}`);
    }
    proc.stdin.write("END\n");
    const r = await next("RESULT");
    result = r ? (JSON.parse(r) as ServerResult) : null;
  } catch (err) {
    imports.push({ fatal: (err as Error).message });
  }
  const code = await exit;
  clearInterval(timer);
  clearTimeout(killer);
  rmSync(work, { recursive: true, force: true }); // the evidence copy and case database are as large as the input
  return {
    run,
    heapMb,
    exit: code,
    wallS: Math.round((Date.now() - started) / 100) / 10,
    peakRssMiB: Math.round(Math.max(s.hwmKiB, result?.maxRssKiB ?? 0) / 1024),
    cpuS: Math.round((result ? result.cpuUserMs + result.cpuSystemMs : s.cpuMs) / 100) / 10,
    note,
    imports,
    superTimelineAdded,
    ...(result ?? {
      died: stderr
        .split("\n")
        .filter((l) => /heap|memory|Invalid string|FATAL|Error/i.test(l))
        .slice(-6),
    }),
  };
}

async function parent(): Promise<void> {
  const dir = arg("dir");
  if (!dir || !existsSync(join(dir, "manifest.json")))
    throw new Error("--dir=<generator output with manifest.json> is required");
  const heapMb = Number(arg("heap-mb") ?? 4096);
  const timeoutMin = Number(arg("timeout-min") ?? 30);
  const runs = arg("runs")?.split(",") ?? DEFAULT_RUNS;
  const manifest = JSON.parse(readFileSync(join(dir, "manifest.json"), "utf8")) as Record<
    string,
    { files?: unknown }
  >;
  const results: Array<Record<string, unknown>> = [];
  for (const run of runs) {
    const { files: _files, ...reference } = manifest[run.replace(/\.(csv|jsonl)(@\d+)?$/, "")] ?? {};
    const row = { ...(await oneRun(dir, run, heapMb, timeoutMin)), reference };
    results.push(row);
    console.log(JSON.stringify(row));
  }
  writeFileSync(join(dir, `results-${Date.now()}.json`), JSON.stringify(results, null, 2));
}

(process.argv.includes("--server") ? server() : parent()).catch((err) => {
  console.error(err);
  process.exit(1);
});
