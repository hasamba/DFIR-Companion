import { spawn } from "node:child_process";
import { openSync, closeSync } from "node:fs";
import { dirname, isAbsolute } from "node:path";
import { retryTransientSpawn } from "../velociraptor/velociraptorApi.js";

// Generic runner for the analyst-configured external forensic tools (Hayabusa, Velociraptor CLI,
// Suricata, Snort, YARA). It shells out to a LOCAL binary the analyst installed — the Companion never
// bundles or downloads it — and feeds the tool's OUTPUT into an existing importer. Modelled 1:1 on the
// Velociraptor API runner (`velociraptorApi.ts`): `spawn`, `windowsHide`, NO shell (each arg is a
// discrete argv element — no command injection), a per-run timeout + output-size cap that kills the
// child, and the shared transient-spawn retry (`retryTransientSpawn`, reused) for the AV/sync-client
// EPERM/EBUSY lock. INJECTABLE so tests never spawn a real process.

export interface ToolRunResult {
  stdout: string;
  stderr: string;
  code: number;   // process exit code (0 on success; some tools exit non-zero yet still produce output)
}

// A runner spawns `binary` with the given argv and returns the captured output. The binary is a
// parameter (not bound at construction) because the run path uses the tool binary while the
// "update rules" path may invoke a SIBLING binary (e.g. `suricata-update`). Real impl spawns; tests
// inject a mock.
export type ToolRunner = (
  binary: string,
  args: string[],
  // When `stdoutFile` is set, the child's stdout is written DIRECTLY to that file (a native equivalent
  // of the shell `> file` redirect) instead of being buffered in memory — so a huge output (e.g. a big
  // Velociraptor collection) isn't capped/killed. res.stdout is then empty; the caller reads the file.
  opts: { timeoutMs: number; maxOutputBytes: number; stdoutFile?: string },
) => Promise<ToolRunResult>;

// An Error tagged with the OS code of a spawn-LAUNCH failure, so retryTransientSpawn can retry a
// transient one (EPERM/EBUSY/…). Mirrors the private type in velociraptorApi.ts.
interface SpawnLaunchError extends Error { spawnCode?: string }

// Build the message for a spawn-launch failure. EPERM/EACCES on a binary that otherwise runs is almost
// always the OS security stack (AV/EDR) denying CreateProcess — retrying can't clear a policy block, so
// point the analyst at the real remedy. Pure + exported for unit testing (the tool analogue of
// velociraptorApi's spawnErrorMessage).
export function toolSpawnErrorMessage(binary: string, err: { message?: string; code?: string }): string {
  const base = `Failed to run tool binary "${binary}": ${err?.message ?? "spawn failed"}`;
  if (err?.code === "ENOENT") {
    return base + " — the binary was not found. Check the path in Settings → Tools (and that the tool is installed).";
  }
  if (err?.code === "EPERM" || err?.code === "EACCES") {
    return base +
      " — the OS denied launching it. Your antivirus/EDR may be blocking the process; add an exclusion" +
      " for the tool binary, or run it manually and import its output.";
  }
  return base;
}

// Strip ANSI escape sequences (SGR colours, cursor moves, OSC) from tool output. Many CLIs (e.g.
// Hayabusa's `update-rules`) FORCE colour even when stdout isn't a TTY, so their text arrives full of
// `ESC[…m` codes that render as garbage in the dashboard. We never feed ANSI to an importer or show it
// in a toast. Anchored on the ESC (0x1B) / CSI (0x9B) byte so it only removes real escape sequences and
// never touches plain brackets in the text (the canonical `ansi-regex` pattern). The regex is built via
// fromCharCode so no raw control byte lives in this source file. Pure + exported for testing.
const ANSI_RE = new RegExp(
  "[" + String.fromCharCode(0x1b, 0x9b) + "][[\\]()#;?]*(?:(?:(?:[a-zA-Z\\d]*(?:;[a-zA-Z\\d]*)*)?" +
    String.fromCharCode(0x07) + ")|(?:(?:\\d{1,4}(?:;\\d{0,4})*)?[\\dA-PR-TZcf-ntqry=><~]))",
  "g",
);
export function stripAnsi(s: string): string {
  return String(s ?? "").replace(ANSI_RE, "");
}

// Clean tool output for DISPLAY (a UI toast / error detail): strip ANSI, turn carriage-return progress
// redraws into lines, drop now-empty lines, and keep the tail (the meaningful summary). Pure.
export function cleanToolOutput(s: string, maxLines = 12): string {
  const lines = stripAnsi(s)
    .replace(/\r\n?/g, "\n")
    .split("\n")
    .map((l) => l.trimEnd())
    .filter((l) => l.trim().length > 0);
  return lines.slice(-maxLines).join("\n").trim();
}

// Quote-aware split of an args/command TEMPLATE into discrete argv tokens. Respects single and double
// quotes (so a path with spaces can be one token); collapses unquoted whitespace. Does NOT interpret
// any shell metacharacters — the result is passed straight to spawn() argv, never a shell string.
export function tokenizeArgs(template: string): string[] {
  const tokens: string[] = [];
  const re = /"([^"]*)"|'([^']*)'|(\S+)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(String(template || ""))) !== null) {
    tokens.push(m[1] ?? m[2] ?? m[3] ?? "");
  }
  return tokens;
}

export interface ArgVars {
  target?: string;       // the input file
  targetdir?: string;    // a folder CONTAINING the input file under its original name (Velociraptor --ROOT)
  output?: string;       // server-owned output file/dir
  rules?: string;        // analyst's rules path (Snort/YARA)
  definitions?: string;  // extra artifact-definitions path (Velociraptor --definitions, for non-built-in artifacts)
}

// Substitute the placeholders (`<target>`/`<targetdir>`/`<output>`/`<rules>`/`<definitions>`) into the
// already-tokenized argv. Each placeholder is replaced IN PLACE within its token and the token is NEVER
// re-split — so a substituted path with spaces stays a single argv element (a token equal to `<target>`
// becomes the path; a token like `EvtxGlob=<target>` becomes `EvtxGlob=<path>`, still one element). An
// unset placeholder is left verbatim so the caller can detect/reject it. `<targetdir>` is matched before
// `<target>` in the alternation so it isn't shadowed.
export function substituteArgs(argv: readonly string[], vars: ArgVars): string[] {
  const map: Record<string, string | undefined> = {
    "<targetdir>": vars.targetdir,
    "<target>": vars.target,
    "<output>": vars.output,
    "<rules>": vars.rules,
    "<definitions>": vars.definitions,
  };
  return argv.map((tok) =>
    tok.replace(/<targetdir>|<target>|<output>|<rules>|<definitions>/g, (ph) => {
      const v = map[ph];
      return v !== undefined ? v : ph;
    }),
  );
}

// One spawn attempt. A LAUNCH failure (sync throw — Windows does this for EPERM — or the async 'error'
// event) rejects with `spawnCode` set so retryTransientSpawn can retry a transient one. A timeout /
// output-cap kill rejects WITHOUT spawnCode. A clean OR non-zero exit RESOLVES with the code — some
// tools (YARA, Snort) exit non-zero yet still emit useful output, so the caller decides what counts as
// empty/failed.
function spawnToolOnce(
  binary: string,
  args: string[],
  opts: { timeoutMs: number; maxOutputBytes: number; stdoutFile?: string },
): Promise<ToolRunResult> {
  return new Promise<ToolRunResult>((resolve, reject) => {
    // Optional native `> file` redirect: send the child's stdout straight to a file descriptor.
    let outFd: number | null = null;
    if (opts.stdoutFile) {
      try { outFd = openSync(opts.stdoutFile, "w"); }
      catch (e) { reject(new Error(`cannot open output file "${opts.stdoutFile}": ${(e as Error).message}`)); return; }
    }
    const closeFd = (): void => { if (outFd !== null) { try { closeSync(outFd); } catch { /* ignore */ } outFd = null; } };
    const launchFailed = (e: unknown): void => {
      closeFd();
      const code = (e as NodeJS.ErrnoException).code || "ESPAWN";
      const err = new Error(toolSpawnErrorMessage(binary, { message: (e as Error).message, code })) as SpawnLaunchError;
      err.spawnCode = code;
      reject(err);
    };
    let child;
    try {
      // Run FROM the binary's own directory when it's an absolute path, so tools that resolve their
      // bundled data relative to the working dir find it — e.g. Hayabusa looks for `rules/` + `config/`
      // in the CWD, and a release ships them next to the exe. Target/output/rules are absolute paths, so
      // this cwd never affects their resolution. stdout → the redirect fd when requested, else a pipe.
      const cwd = isAbsolute(binary) ? dirname(binary) : undefined;
      const stdio: ["ignore", number | "pipe", "pipe"] = ["ignore", outFd !== null ? outFd : "pipe", "pipe"];
      child = spawn(binary, args, { windowsHide: true, stdio, ...(cwd ? { cwd } : {}) });
    } catch (e) {
      launchFailed(e);   // Windows throws EPERM synchronously — not via the 'error' event
      return;
    }
    let out = "";
    let err = "";
    let killed = false;
    const timer = setTimeout(() => {
      killed = true;
      child.kill();
      closeFd();
      reject(new Error(`Tool "${binary}" timed out after ${opts.timeoutMs}ms`));
    }, opts.timeoutMs);
    // When redirecting to a file, child.stdout is null (goes to the fd) — no in-memory buffer/cap.
    child.stdout?.on("data", (d: Buffer) => {
      out += d.toString();
      if (out.length > opts.maxOutputBytes) {
        killed = true;
        child.kill();
        clearTimeout(timer);
        closeFd();
        reject(new Error(`Tool "${binary}" output exceeded ${opts.maxOutputBytes} bytes — raise the tool's MAX_OUTPUT, or narrow the run`));
      }
    });
    child.stderr?.on("data", (d: Buffer) => { err += d.toString(); });
    child.on("error", (e) => {
      if (killed) return;
      clearTimeout(timer);
      launchFailed(e);   // async spawn failure (e.g. ENOENT) — tagged so a transient one is retried
    });
    child.on("close", (code) => {
      if (killed) return;
      clearTimeout(timer);
      closeFd();
      resolve({ stdout: out, stderr: err, code: code ?? 0 });
    });
  });
}

// The real runner: spawn the given binary with the argv, no shell, killing the child on timeout or when
// output blows the cap, and retrying a transient spawn-launch lock (AV/sync client). Mirrors
// spawnVqlRunner but binary-parameterized so run vs update can target different executables.
export function spawnToolRunner(): ToolRunner {
  const retries = Number(process.env.DFIR_TOOL_SPAWN_RETRIES);
  return (binary, args, opts) => {
    if (!binary) return Promise.reject(new Error("no tool binary configured"));
    return retryTransientSpawn(() => spawnToolOnce(binary, args, opts), {
      retries: Number.isFinite(retries) && retries >= 0 ? retries : undefined,
    });
  };
}
