import { spawn } from "node:child_process";

// Run VQL against a Velociraptor server through its API, so the analyst can execute the hunt-pivot
// queries the Companion generates without leaving the dashboard. Velociraptor's API is gRPC + mTLS
// driven by an `api_client` config (`velociraptor config api_client …`); rather than reimplement
// gRPC/mTLS in Node, we shell out to the `velociraptor` binary with `--api_config`, which connects
// to the server's API and runs the query server-side. The query runner is INJECTABLE so tests never
// spawn a process or touch the network (mirrors the EnrichmentProvider/AIProvider fetchFn pattern).
//
// This is a powerful capability (arbitrary VQL against your Velociraptor estate), so it is OFF by
// default and only enabled when DFIR_VELOCIRAPTOR_API_CONFIG is set. Localhost + analyst-driven.

export interface VelociraptorApiConfig {
  apiConfigPath: string;   // path to the api_client config yaml (velociraptor config api_client …)
  binary: string;          // velociraptor executable (PATH name or absolute path)
  timeoutMs: number;       // per-query timeout
  maxRows: number;         // cap rows returned to the caller
  maxOutputBytes: number;  // hard cap on captured stdout (kill the child if exceeded)
}

export interface VqlRunResult {
  rows: unknown[];
  raw: string;
}

// A runner executes one VQL program and returns its rows. Real impl spawns the binary; tests inject.
export type VqlRunner = (vql: string, opts: { timeoutMs: number; maxOutputBytes: number }) => Promise<VqlRunResult>;

// Parse `velociraptor query --format json` output. Primary form is a single JSON array of row
// objects; we also accept JSONL (one row per line) and tolerate trailing noise. Non-JSON → [].
export function parseVqlOutput(stdout: string): unknown[] {
  const text = String(stdout || "").trim();
  if (!text) return [];
  try {
    const parsed = JSON.parse(text);
    if (Array.isArray(parsed)) return parsed;
    if (parsed && typeof parsed === "object") return [parsed];
  } catch {
    // fall through to JSONL
  }
  const rows: unknown[] = [];
  for (const line of text.split(/\r?\n/)) {
    const t = line.trim();
    if (!t) continue;
    try {
      const v = JSON.parse(t);
      if (Array.isArray(v)) rows.push(...v);
      else rows.push(v);
    } catch {
      // skip non-JSON lines (e.g. a stray log line)
    }
  }
  return rows;
}

// Split a VQL blob (e.g. the notebook pivots, separated by blank lines) into individual statements
// and STRIP comment lines. Critical for the CLI: a query passed to `velociraptor query` that begins
// with a `-- comment` is parsed by the flag lexer as an unknown long flag ("--"), so each statement
// must start with real VQL. Comment-only chunks are dropped. Each statement becomes its own
// positional `query` arg (the command is variadic), so multiple pivots run in one invocation.
export function splitVqlStatements(vql: string): string[] {
  return String(vql || "")
    .split(/\n\s*\n/)
    .map((chunk) =>
      chunk
        .split(/\r?\n/)
        .filter((line) => line.trim() && !line.trim().startsWith("--"))   // drop pure-comment lines
        .join("\n")
        .trim(),
    )
    .filter(Boolean);
}

// The real runner: spawn the velociraptor binary with the api config, no shell (each statement is a
// single argv element — no command injection). Uses jsonl output so multiple queries parse robustly.
// Kills the child on timeout or if output blows the cap.
export function spawnVqlRunner(config: VelociraptorApiConfig): VqlRunner {
  return (vql, opts) =>
    new Promise<VqlRunResult>((resolve, reject) => {
      const statements = splitVqlStatements(vql);
      if (statements.length === 0) {
        reject(new Error("No runnable VQL found (the query is empty or only comments)"));
        return;
      }
      const args = ["--api_config", config.apiConfigPath, "query", "--format", "jsonl", ...statements];
      const child = spawn(config.binary, args, { windowsHide: true });
      let out = "";
      let err = "";
      let killed = false;
      const timer = setTimeout(() => {
        killed = true;
        child.kill();
        reject(new Error(`Velociraptor query timed out after ${opts.timeoutMs}ms`));
      }, opts.timeoutMs);
      child.stdout.on("data", (d: Buffer) => {
        out += d.toString();
        if (out.length > opts.maxOutputBytes) {
          killed = true;
          child.kill();
          clearTimeout(timer);
          reject(new Error(`Velociraptor query output exceeded ${opts.maxOutputBytes} bytes — narrow the query`));
        }
      });
      child.stderr.on("data", (d: Buffer) => { err += d.toString(); });
      child.on("error", (e) => {
        clearTimeout(timer);
        reject(new Error(`Failed to run velociraptor binary "${config.binary}": ${(e as Error).message}`));
      });
      child.on("close", (code) => {
        if (killed) return;
        clearTimeout(timer);
        if (code !== 0) {
          reject(new Error(err.trim() || `velociraptor exited with code ${code}`));
          return;
        }
        resolve({ rows: parseVqlOutput(out), raw: out });
      });
    });
}

export interface VelociraptorRunResult {
  rows: unknown[];
  total: number;      // total rows the query returned
  truncated: boolean; // true when total > maxRows and rows was capped
}

export class VelociraptorClient {
  constructor(
    private readonly config: VelociraptorApiConfig,
    private readonly runner: VqlRunner = spawnVqlRunner(config),
  ) {}

  // Run a VQL program and return (capped) rows. Throws on empty VQL or runner failure.
  async run(vql: string): Promise<VelociraptorRunResult> {
    const trimmed = String(vql || "").trim();
    if (!trimmed) throw new Error("VQL is required");
    const { rows } = await this.runner(trimmed, {
      timeoutMs: this.config.timeoutMs,
      maxOutputBytes: this.config.maxOutputBytes,
    });
    return {
      rows: rows.slice(0, this.config.maxRows),
      total: rows.length,
      truncated: rows.length > this.config.maxRows,
    };
  }
}

// Build a config from env, or null when not configured (DFIR_VELOCIRAPTOR_API_CONFIG unset).
export function loadVelociraptorConfig(env: NodeJS.ProcessEnv = process.env): VelociraptorApiConfig | null {
  const apiConfigPath = env.DFIR_VELOCIRAPTOR_API_CONFIG?.trim();
  if (!apiConfigPath) return null;
  return {
    apiConfigPath,
    binary: env.DFIR_VELOCIRAPTOR_BINARY?.trim() || "velociraptor",
    timeoutMs: Number(env.DFIR_VELOCIRAPTOR_TIMEOUT_MS) || 60_000,
    maxRows: Number(env.DFIR_VELOCIRAPTOR_MAX_ROWS) || 1000,
    maxOutputBytes: Number(env.DFIR_VELOCIRAPTOR_MAX_OUTPUT) || 50 * 1024 * 1024,
  };
}

// Construct a client when configured, else undefined (mirrors buildIrisClient()).
export function buildVelociraptorClient(env: NodeJS.ProcessEnv = process.env): VelociraptorClient | undefined {
  const config = loadVelociraptorConfig(env);
  return config ? new VelociraptorClient(config) : undefined;
}
