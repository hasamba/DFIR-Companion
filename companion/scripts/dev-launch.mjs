// `npm run dev` launcher (#2855). It sizes the server's V8 heap from the machine instead of the old
// fixed --max-old-space-size=8192. That flag applies to every isolate (the main thread and each
// SQLite worker), so on a small or container-capped machine the kernel killed the server before V8
// ever collected. Half of the memory, clamped to 2048..8192 MB: a 16 GB+ host keeps 8192 exactly as
// before; smaller or capped machines get less. A heap flag already set in NODE_OPTIONS or passed to
// this launcher is respected. Plain ESM with no deps so it runs under bare `node`; the sizing is
// pure and exported for tests/scripts/devLaunch.test.ts, and the spawn only runs as the main module.

import { spawn } from "node:child_process";
import { constants, totalmem } from "node:os";
import { dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

export const HEAP_FLOOR_MB = 2048;
export const HEAP_CEILING_MB = 8192;
const HEAP_SHARE = 0.5;
const MB = 1024 * 1024;
const HEAP_FLAG_RE = /^--max[-_]old[-_]space[-_]size(=|$)/;

/** Heap size from machine memory; a positive cgroup/container cap below the total wins. */
export function computeHeapMb({ totalMemBytes, constrainedMemBytes }) {
  const capped =
    typeof constrainedMemBytes === "number" &&
    Number.isFinite(constrainedMemBytes) &&
    constrainedMemBytes > 0 &&
    constrainedMemBytes < totalMemBytes;
  const memMb = Math.floor((capped ? constrainedMemBytes : totalMemBytes) / MB);
  const heapMb = Math.min(HEAP_CEILING_MB, Math.max(HEAP_FLOOR_MB, Math.floor(HEAP_SHARE * memMb)));
  return { heapMb, memMb, source: capped ? "container" : "machine" };
}

/** A heap flag the user already set. NODE_OPTIONS is inherited by the child, so nothing is
 * forwarded; flags on the launcher's own node or after `npm run dev --` are forwarded. */
export function existingHeapFlag({ nodeOptions = "", execArgv = [], args = [] }) {
  const forwarded = [...execArgv, ...args].filter((a) => HEAP_FLAG_RE.test(a));
  if (forwarded.length > 0) return { where: "launcher arguments", flags: forwarded };
  if (nodeOptions.split(/\s+/).some((a) => HEAP_FLAG_RE.test(a))) return { where: "NODE_OPTIONS", flags: [] };
  return null;
}

export function heapLogLine(sizing, existing = null) {
  if (existing) return `[DFIR] dev launch: keeping the --max-old-space-size set in ${existing.where}.`;
  const why = sizing.source === "container" ? "container memory cap" : "machine memory";
  return `[DFIR] dev launch: V8 heap ${sizing.heapMb} MB (half of ${sizing.memMb} MB ${why}, clamped ${HEAP_FLOOR_MB}-${HEAP_CEILING_MB} MB).`;
}

export const FORWARDED_SIGNALS = ["SIGINT", "SIGTERM"];
/** Longer than the server's 5 s drain deadline (SHUTDOWN_DEADLINE_MS in gracefulShutdown.ts). */
export const FORWARD_GRACE_MS = 6000;

/**
 * Forward a stop signal to the server only if it has not stopped on its own. The server shares the
 * launcher's process group, so a terminal Ctrl+C (or `timeout`) already reaches it; an eager forward
 * lands mid-drain as a "second SIGINT — exiting now" and cuts the graceful shutdown short. The first
 * signal arms one timer; later copies do nothing (a real second Ctrl+C still reaches the server
 * through the group). A signal sent to the launcher alone still stops the server after the grace.
 */
export function createSignalForwarder(
  child,
  { graceMs = FORWARD_GRACE_MS, setTimer = setTimeout, clearTimer = clearTimeout } = {},
) {
  let timer = null;
  return {
    onSignal(signal) {
      if (timer !== null) return;
      timer = setTimer(() => {
        if (child.exitCode === null && child.signalCode === null) child.kill(signal);
      }, graceMs);
    },
    cancel() {
      if (timer !== null) clearTimer(timer);
    },
  };
}

function main() {
  const companion = resolve(dirname(fileURLToPath(import.meta.url)), "..");
  const args = process.argv.slice(2);
  const existing = existingHeapFlag({
    nodeOptions: process.env.NODE_OPTIONS,
    execArgv: process.execArgv,
    args,
  });
  const sizing = existing
    ? null
    : computeHeapMb({ totalMemBytes: totalmem(), constrainedMemBytes: process.constrainedMemory?.() });
  console.log(heapLogLine(sizing, existing));
  const heapFlags = existing ? existing.flags : [`--max-old-space-size=${sizing.heapMb}`];
  const otherArgs = args.filter((a) => !HEAP_FLAG_RE.test(a));
  const child = spawn(
    process.execPath,
    [...heapFlags, "--import", "tsx/esm", "src/server.ts", ...otherArgs],
    {
      cwd: companion,
      stdio: "inherit",
    },
  );
  const forwarder = createSignalForwarder(child);
  for (const signal of FORWARDED_SIGNALS) process.on(signal, () => forwarder.onSignal(signal));
  child.on("error", (err) => {
    console.error(`[DFIR] dev launch: could not start the server: ${err.message}`);
    process.exit(1);
  });
  child.on("exit", (code, signal) => {
    forwarder.cancel();
    process.exit(code ?? (signal ? 128 + (constants.signals[signal] ?? 0) : 1));
  });
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) main();
