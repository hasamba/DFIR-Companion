/**
 * Memory benchmark for a Velociraptor hunt zip with many result files, dropped into a case (#2746).
 *
 * Usage (from companion/):
 *   npx tsx scripts/bench-velo-many-files.ts [--clients=40] [--artifacts=3] [--rows=2000]
 *       [--graded=0.05] [--heap-mb=4096] [--out=<dir>] [--timeout-min=60] [--keep]
 *   npm run bench:velo-many -- --clients=40
 *
 * A real server child (`src/server.ts`, no AI provider) over a throwaway cases root (never `cases/`,
 * benchOutputGuard.ts). It builds one synthetic hunt zip — `clients` per-client folders, each with
 * `artifacts` result files of `rows` rows — drops it into a fresh case and waits for every result
 * file to import. After each file's "done" line it records the server's RSS and the main heap's live
 * size after the last full mark-compact, then prints the series and the growth per file over the
 * second half (the first files warm caches). Synthetic data only: documentation names, TEST-NET IPs.
 * Linux only (/proc).
 */
import { spawn } from "node:child_process";
import { createWriteStream, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { mkdir, writeFile } from "node:fs/promises";
import { once } from "node:events";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { ZipFile } from "yazl";
import { safeOutputDir } from "./benchOutputGuard.js";
import { syntheticRow } from "./bench-velo-bulk-import.js";

const arg = (name: string): string | undefined =>
  process.argv.find((v) => v.startsWith(`--${name}=`))?.slice(name.length + 3);
const COMPANION_DIR = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const CASE_ID = "bench";
const ARTIFACTS = [
  "Windows.EventLogs.Hayabusa",
  "Windows.Detection.Evtx",
  "Windows.System.Pslist",
  "Windows.Network.Netstat",
  "Windows.Detection.Amcache",
  "Windows.Sys.Users",
];

export interface FileSample {
  file: number;
  rssMb: number;
  liveMb: number;
}

/** Bytes per file of growth over the second half of the series (least squares on RSS). */
export function growthPerFileMb(samples: readonly FileSample[], key: "rssMb" | "liveMb"): number {
  const tail = samples.slice(Math.floor(samples.length / 2));
  if (tail.length < 2) return 0;
  const n = tail.length;
  const mx = tail.reduce((s, p) => s + p.file, 0) / n;
  const my = tail.reduce((s, p) => s + p[key], 0) / n;
  const num = tail.reduce((s, p) => s + (p.file - mx) * (p[key] - my), 0);
  const den = tail.reduce((s, p) => s + (p.file - mx) ** 2, 0);
  return den ? num / den : 0;
}

async function buildHuntZip(path: string, clients: number, artifacts: number, rows: number, graded: number) {
  const zip = new ZipFile();
  const out = createWriteStream(path);
  zip.outputStream.pipe(out);
  zip.addBuffer(Buffer.from(JSON.stringify({ hunt_id: "H.BENCH0001" })), "hunt_info.json");
  let row = 0;
  for (let c = 0; c < clients; c++) {
    const id = `C.${(0x1000 + c).toString(16).padStart(16, "0")}`;
    const dir = `WKS-${String(c).padStart(3, "0")}-${id}`;
    zip.addBuffer(
      Buffer.from(JSON.stringify({ client_id: id, hostname: `WKS-${c}` })),
      `${dir}/client_info.json`,
    );
    for (let a = 0; a < artifacts; a++) {
      const lines: string[] = [];
      for (let r = 0; r < rows; r++, row++) {
        const isGraded = (row * 7919) % 1000 < graded * 1000;
        lines.push(JSON.stringify(syntheticRow(row, isGraded)));
      }
      zip.addBuffer(
        Buffer.from(lines.join("\n") + "\n"),
        `${dir}/results/${ARTIFACTS[a % ARTIFACTS.length]}.json`,
      );
    }
  }
  zip.end();
  await once(out, "finish");
}

async function freePort(): Promise<number> {
  const srv = createServer();
  srv.listen(0, "127.0.0.1");
  await once(srv, "listening");
  const port = (srv.address() as { port: number }).port;
  srv.close();
  return port;
}

function rssMb(pid: number): number {
  try {
    const m = /VmRSS:\s+(\d+)\s+kB/.exec(readFileSync(`/proc/${pid}/status`, "utf8"));
    return m ? Math.round(Number(m[1]) / 1024) : 0;
  } catch {
    return 0;
  }
}

async function main(): Promise<void> {
  if (process.platform !== "linux") throw new Error("this benchmark reads /proc and runs on Linux only");
  const clients = Number(arg("clients") ?? 40);
  const artifacts = Number(arg("artifacts") ?? 3);
  const rows = Number(arg("rows") ?? 2000);
  const graded = Number(arg("graded") ?? 0.05);
  const heapMb = Number(arg("heap-mb") ?? 4096);
  const timeoutMs = Number(arg("timeout-min") ?? 60) * 60_000;
  const total = clients * artifacts;
  const base = safeOutputDir(arg("out") ?? mkdtempSync(join(tmpdir(), "dfir-bench-many-")));
  const root = join(base, "data");
  await mkdir(root, { recursive: true });
  const zipPath = join(base, "hunt.zip");
  await buildHuntZip(zipPath, clients, artifacts, rows, graded);
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
        DFIR_LOG_DIR: join(base, "logs"),
        DFIR_PORT: String(port),
        DFIR_DROP_POLL_S: "2",
      },
      stdio: ["ignore", "pipe", "pipe"],
    },
  );
  const samples: FileSample[] = [];
  // Live heap after the last full GC, per isolate: the main thread and each SQLite worker (#2746).
  const live = new Map<string, number>();
  let pending = "";
  const onLine = (line: string): void => {
    const g =
      /^\[\d+:(0x[0-9a-f]+)\]\s+\d+ ms: (Mark-Compact|Mark-sweep)[^\d]*[\d.]+ \([\d.]+\) -> ([\d.]+)/.exec(
        line,
      );
    if (g) live.set(g[1], Number(g[3]));
    if (/\[import\] .*: done — forensic/.test(line)) {
      samples.push({
        file: samples.length + 1,
        rssMb: rssMb(child.pid!),
        liveMb: Math.round([...live.values()].reduce((a, b) => a + b, 0)),
      });
      const s = samples[samples.length - 1];
      if (s.file % 10 === 0 || s.file === 1)
        console.log(`file ${s.file}/${total}: rss ${s.rssMb} MB, live ${s.liveMb} MB`);
    }
  };
  const take = (b: Buffer): void => {
    out.write(b);
    pending += b.toString();
    const lines = pending.split("\n");
    pending = lines.pop() ?? "";
    for (const l of lines) onLine(l);
  };
  child.stdout.on("data", take);
  child.stderr.on("data", take);
  const t0 = Date.now();
  try {
    const url = `http://127.0.0.1:${port}`;
    for (let i = 0; i < 60; i++) {
      if (
        await fetch(`${url}/health`).then(
          (r) => r.ok,
          () => false,
        )
      )
        break;
      await new Promise((r) => setTimeout(r, 1000));
    }
    const created = await fetch(`${url}/cases`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ caseId: CASE_ID, name: "bench", investigator: "bench", aiProvider: null }),
    });
    if (!created.ok) throw new Error(`could not create the case (${created.status})`);
    const drop = join(root, CASE_ID, "drop");
    await mkdir(drop, { recursive: true });
    await writeFile(join(drop, "hunt.zip"), readFileSync(zipPath));
    while (samples.length < total && Date.now() - t0 < timeoutMs && child.exitCode === null)
      await new Promise((r) => setTimeout(r, 1000));
    console.log(`${samples.length}/${total} files in ${((Date.now() - t0) / 1000).toFixed(0)} s`);
    console.log(
      `growth per file (second half): rss ${growthPerFileMb(samples, "rssMb").toFixed(1)} MB, live heap ${growthPerFileMb(samples, "liveMb").toFixed(1)} MB`,
    );
    await writeFile(join(base, "samples.json"), JSON.stringify(samples));
  } finally {
    child.kill("SIGINT");
    out.end();
    if (!process.argv.includes("--keep")) rmSync(base, { recursive: true, force: true });
    else console.log(`kept: ${base}`);
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((err: unknown) => {
    console.error(err instanceof Error ? err.message : err);
    process.exitCode = 1;
  });
}
