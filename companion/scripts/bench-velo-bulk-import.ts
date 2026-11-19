/**
 * Memory benchmark for a large Velociraptor JSON Lines file dropped into a case (#2713).
 *
 * Usage (from companion/):
 *   npx tsx scripts/bench-velo-bulk-import.ts [--rows=20000] [--graded=0.9] [--heap-mb=1024]
 *       [--out=<dir>] [--timeout-min=60] [--server-dir=<companion dir>] [--keep]
 *   npm run bench:velo-bulk -- --rows=1000000 --graded=0.02 --heap-mb=2048
 *
 * WHAT IT RUNS. A real server child (`src/server.ts`, no AI provider, default settings) over a
 * throwaway cases root under --out (default: a fresh temp folder; a path in or named `cases` is
 * refused, benchOutputGuard.ts — nothing is read from or written to `cases/`). It creates one case,
 * drops a synthetic file into that case's drop/ folder, and waits for the drop sweep to import it the
 * way it imports an analyst's file: the disk-streamed bulk path (batches), the importer's full-state
 * merge, then the settle (dual-write → tagger → caps → demote). The drop cap is lowered so the file
 * always streams from disk.
 *
 * THE DATA. Synthetic Velociraptor notebook rows: a `--graded` share are DetectRaptor-style detection
 * rows (graded Medium, kept in the forensic timeline), the rest plain process-creation telemetry
 * (Info, super-timeline only). Field-rich and varied — host, user, image, parent, command line and
 * hashes change from row to row — with documentation-only names and TEST-NET addresses.
 *
 * WHAT IT REPORTS. Wall time, peak RSS (VmHWM) and, from `--trace-gc`, the main thread's heap per
 * phase — the largest size before a collection (an upper bound: it includes garbage) and the largest
 * size after a full mark-compact (what was really alive). The phases are delimited by the import's own
 * log lines. PASS means the import finished end to end under `--heap-mb`; the run also reports whether
 * the settle's live peak stayed within the batches' live peak plus a margin — the settle no longer
 * holds a copy of every row the file added (#2713). The full-state merge still loads the case's whole
 * forensic timeline once, so a file whose rows are nearly all graded costs that; the table shows it.
 * Linux only (VmHWM).
 */
import { spawn, type ChildProcess } from "node:child_process";
import { createWriteStream, mkdtempSync, readFileSync, readdirSync, rmSync, existsSync } from "node:fs";
import { copyFile, mkdir } from "node:fs/promises";
import { once } from "node:events";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { safeOutputDir } from "./benchOutputGuard.js";

const arg = (name: string): string | undefined =>
  process.argv.find((v) => v.startsWith(`--${name}=`))?.slice(name.length + 3);

/** The companion/ whose server runs — this checkout's, or `--server-dir` (e.g. a master export). */
const COMPANION_DIR = resolve(arg("server-dir") ?? resolve(dirname(fileURLToPath(import.meta.url)), ".."));
const CASE_ID = "bench";
const FILE_NAME = "Windows.Hayabusa.Notebook.json";
/** How far the settle's live heap may sit above the batches' before the run reports it as growing. */
const SETTLE_MARGIN_MB = 64;

// ───────────────────────────── synthetic rows ─────────────────────────────

const IMAGES = [
  "powershell.exe",
  "cmd.exe",
  "rundll32.exe",
  "wmic.exe",
  "certutil.exe",
  "mshta.exe",
  "regsvr32.exe",
];
const BENIGN = ["notepad.exe", "conhost.exe", "taskhostw.exe", "dllhost.exe", "searchprotocolhost.exe"];
const PARENTS = ["explorer.exe", "svchost.exe", "services.exe", "winword.exe", "wmiprvse.exe"];
const RULES = [
  "T1059.001-Suspicious PowerShell Invocation",
  "T1218.011-Rundll32 Without Arguments",
  "T1105-Certutil Download",
  "T1047-WMIC Process Call Create",
];

const hex = (i: number, len: number): string =>
  Array.from({ length: Math.ceil(len / 8) }, (_, k) =>
    ((i * 2654435761 + k * 40503) >>> 0).toString(16).padStart(8, "0"),
  )
    .join("")
    .slice(0, len);

export function syntheticRow(i: number, graded: boolean): Record<string, unknown> {
  const host = `WKS-${String(i % 37).padStart(3, "0")}.lab.example`;
  // Telemetry rows run benign images with plain arguments, so they grade Info and stay super-only.
  const image = graded ? IMAGES[i % IMAGES.length] : BENIGN[i % BENIGN.length];
  const user = `user${i % 211}`;
  const args = Array.from({ length: 6 + (i % 9) }, (_, k) => `/p${k}:${hex(i + k, 12)}`).join(" ");
  const tail = graded ? ` http://198.51.100.${i % 250}/p${i % 97}` : "";
  const row: Record<string, unknown> = {
    EventTime: new Date(Date.UTC(2026, 7, 13) + i * 1000).toISOString(),
    Computer: host,
    Channel: "Security",
    EventID: 4688,
    EventData: {
      SubjectUserName: user,
      SubjectDomainName: "LAB",
      NewProcessId: `0x${(4096 + i).toString(16)}`,
      NewProcessName: `C:\\Windows\\System32\\${image}`,
      ParentProcessName: `C:\\Windows\\System32\\${PARENTS[i % PARENTS.length]}`,
      CommandLine: `"C:\\Windows\\System32\\${image}" ${args}${tail}`,
      TokenElevationType: "%%1936",
      Hashes: `SHA256=${hex(i, 64)},MD5=${hex(i * 7, 32)}`,
    },
    Message: "A new process has been created.",
    OSPath: "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx",
    FlowId: `F.BENCH${(i % 5).toString(16).toUpperCase()}`,
    ClientId: "C.0123456789abcdef",
    Fqdn: host,
  };
  if (graded)
    row.Detection = { Name: RULES[i % RULES.length], EventId: "^(4688)$", Regex: image, Ignore: "" };
  return row;
}

async function writeRows(path: string, rows: number, graded: number): Promise<void> {
  const out = createWriteStream(path);
  for (let i = 0; i < rows; i++) {
    const isGraded = (i * 7919) % 1000 < graded * 1000;
    if (!out.write(JSON.stringify(syntheticRow(i, isGraded)) + "\n")) await once(out, "drain");
  }
  out.end();
  await once(out, "finish");
}

// ───────────────────────────── the server child ─────────────────────────────

async function freePort(): Promise<number> {
  const srv = createServer();
  srv.listen(0, "127.0.0.1");
  await once(srv, "listening");
  const port = (srv.address() as { port: number }).port;
  srv.close();
  return port;
}

function vmHwmMiB(pid: number): number {
  try {
    const m = /VmHWM:\s+(\d+)\s+kB/.exec(readFileSync(`/proc/${pid}/status`, "utf8"));
    return m ? Math.round(Number(m[1]) / 1024) : 0;
  } catch {
    return 0;
  }
}

async function until(
  cond: () => boolean | Promise<boolean>,
  ms: number,
  child: ChildProcess,
): Promise<boolean> {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    if (await cond()) return true;
    if (child.exitCode !== null || child.signalCode !== null) return false;
    await new Promise((r) => setTimeout(r, 1000));
  }
  return false;
}

// ───────────────────────────── the GC trace ─────────────────────────────

const PHASES: Array<[string, RegExp]> = [
  ["batches", /: bulk path \(forensic\)/],
  ["full merge", /\[merge\] (full-state merge|incremental)/],
  ["settle: stamp", /: parsed and merged in/],
  ["settle: dual-write + tag", /settle start forensicBefore=/],
  ["settle: caps + demote", /settle dual-write /],
  ["settle: names + diff", /settle demote /],
  ["after", /: done — forensic/],
];

export interface PhasePeak {
  phase: string;
  beforeGcMb: number;
  liveMb: number;
}

/** Per phase, the main isolate's largest pre-GC heap and largest post-mark-compact heap. */
export function phasePeaks(log: string): PhasePeak[] {
  let main: string | undefined;
  let phase = "startup";
  const peaks = new Map<string, PhasePeak>();
  for (const line of log.split("\n")) {
    const next = PHASES.find(([, re]) => re.test(line));
    if (next) phase = next[0];
    const g =
      /^\[\d+:(0x[0-9a-f]+)\]\s+\d+ ms: (Scavenge|Mark-Compact|Mark-sweep)[^\d]*([\d.]+) \([\d.]+\) -> ([\d.]+)/.exec(
        line,
      );
    if (!g) continue;
    main ??= g[1]; // the main isolate collects first
    if (g[1] !== main) continue;
    const p = peaks.get(phase) ?? { phase, beforeGcMb: 0, liveMb: 0 };
    p.beforeGcMb = Math.max(p.beforeGcMb, Number(g[3]));
    if (g[2] !== "Scavenge") p.liveMb = Math.max(p.liveMb, Number(g[4]));
    peaks.set(phase, p);
  }
  return [...peaks.values()];
}

// ───────────────────────────── main ─────────────────────────────

async function main(): Promise<void> {
  if (process.platform !== "linux") throw new Error("this benchmark reads /proc and runs on Linux only");
  const rows = Number(arg("rows") ?? 20_000);
  const graded = Number(arg("graded") ?? 0.9);
  const heapMb = Number(arg("heap-mb") ?? 1024);
  const timeoutMs = Number(arg("timeout-min") ?? 60) * 60_000;
  if (!(rows > 0) || !(graded >= 0 && graded <= 1) || !(heapMb > 0))
    throw new Error("bad --rows/--graded/--heap-mb");
  const base = safeOutputDir(arg("out") ?? mkdtempSync(join(tmpdir(), "dfir-bench-velo-")));
  const root = join(base, "data");
  const logs = join(base, "logs");
  const source = join(base, FILE_NAME);
  await mkdir(root, { recursive: true });
  await writeRows(source, rows, graded);
  const port = await freePort();
  const out = createWriteStream(join(base, "server.log"));
  const child = spawn(
    process.execPath,
    [`--max-old-space-size=${heapMb}`, "--trace-gc", "--import", "tsx/esm", "src/server.ts"],
    {
      cwd: COMPANION_DIR,
      env: {
        ...process.env,
        DFIR_CASES_ROOT: root,
        DFIR_LOG_DIR: logs,
        DFIR_PORT: String(port),
        DFIR_LOG_LEVEL: "debug",
        DFIR_DROP_POLL_S: "2",
        DFIR_DROP_MAX_BYTES: String(1024 * 1024), // always the streamed branch
      },
      stdio: ["ignore", "pipe", "pipe"],
    },
  );
  let log = "";
  const take = (b: Buffer): void => {
    log += b.toString();
    out.write(b);
  };
  child.stdout.on("data", take);
  child.stderr.on("data", take);
  let hwm = 0;
  const sampler = setInterval(() => (hwm = Math.max(hwm, vmHwmMiB(child.pid!))), 500);
  const t0 = Date.now();
  try {
    const url = `http://127.0.0.1:${port}`;
    const up = await until(
      () =>
        fetch(`${url}/health`).then(
          (r) => r.ok,
          () => false,
        ),
      60_000,
      child,
    );
    if (!up) throw new Error("the server did not start");
    const created = await fetch(`${url}/cases`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ caseId: CASE_ID, name: "bench", investigator: "bench", aiProvider: null }),
    });
    if (!created.ok) throw new Error(`could not create the case (${created.status})`);
    const drop = join(root, CASE_ID, "drop");
    await mkdir(drop, { recursive: true });
    await copyFile(source, join(drop, FILE_NAME));
    const processed = join(drop, "_processed");
    const finished = await until(
      () =>
        /: done — forensic/.test(log) && existsSync(processed) && readdirSync(processed).includes(FILE_NAME),
      timeoutMs,
      child,
    );
    report({
      rows,
      graded,
      heapMb,
      finished,
      seconds: (Date.now() - t0) / 1000,
      hwm,
      log,
      exit: child.exitCode,
    });
  } finally {
    clearInterval(sampler);
    child.kill("SIGINT");
    out.end();
    if (!process.argv.includes("--keep")) rmSync(base, { recursive: true, force: true });
    else console.log(`kept: ${base}`);
  }
}

function report(r: {
  rows: number;
  graded: number;
  heapMb: number;
  finished: boolean;
  seconds: number;
  hwm: number;
  log: string;
  exit: number | null;
}): void {
  const peaks = phasePeaks(r.log);
  console.log(`rows ${r.rows}, graded ${Math.round(r.graded * 100)}%, heap limit ${r.heapMb} MB`);
  console.log(`wall ${r.seconds.toFixed(0)} s, peak RSS ${r.hwm} MB`);
  console.log(
    "phase".padEnd(26),
    "heap before GC (MB)".padStart(20),
    "live after mark-compact (MB)".padStart(30),
  );
  for (const p of peaks)
    console.log(
      p.phase.padEnd(26),
      String(Math.round(p.beforeGcMb)).padStart(20),
      String(Math.round(p.liveMb)).padStart(30),
    );
  const live = (prefix: string): number =>
    Math.max(0, ...peaks.filter((p) => p.phase.startsWith(prefix)).map((p) => p.liveMb));
  const settle = live("settle");
  const batches = live("batches");
  if (settle && batches)
    console.log(
      `settle live peak ${Math.round(settle)} MB vs batches ${Math.round(batches)} MB: ` +
        (settle <= batches + SETTLE_MARGIN_MB ? "bounded" : "GROWS with the file"),
    );
  console.log(
    r.finished ? "PASS — imported end to end under the heap limit" : `FAIL — not finished (exit ${r.exit})`,
  );
  if (!r.finished) process.exitCode = 1;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((err: unknown) => {
    console.error(err instanceof Error ? err.message : err);
    process.exitCode = 1;
  });
}
