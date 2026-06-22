import { spawn } from "node:child_process";

// Run the hunt-pivot queries the Companion generates against a Velociraptor server through its API.
// The hunt-pivot is run as a HUNT across ALL enrolled endpoints (not server-side): the pivot VQL is
// packaged as a CLIENT artifact (`artifact_set`), a hunt is launched (`hunt`), and results are read
// back per client (`hunt_results`) — so "find this file" searches every connected endpoint.
//
// Velociraptor's API is gRPC + mTLS driven by an `api_client` config (`velociraptor config
// api_client …`); rather than reimplement gRPC/mTLS in Node we shell out to the `velociraptor`
// binary with `--api_config`. The query runner is INJECTABLE so tests never spawn a process or touch
// the network (mirrors the EnrichmentProvider/AIProvider fetchFn pattern).
//
// Powerful capability (creates artifacts + hunts on your estate), so it is OFF by default and only
// enabled when DFIR_VELOCIRAPTOR_API_CONFIG is set. Localhost + analyst-driven.

export interface VelociraptorApiConfig {
  apiConfigPath: string;   // path to the api_client config yaml (velociraptor config api_client …)
  binary: string;          // velociraptor executable (PATH name or absolute path)
  timeoutMs: number;       // per-query timeout
  maxRows: number;         // cap rows returned to the caller
  maxOutputBytes: number;  // hard cap on captured stdout for interactive queries (kill the child if exceeded)
  collectMaxOutputBytes?: number;  // larger cap for bundle-hunt collection (rows + uploaded JSON); forensic data is big
  guiUrl?: string;         // optional Velociraptor GUI base URL, for deep-linking to a launched hunt
  guiOrg?: string;         // Velociraptor org for the deep link (?org_id=…); default "root" (the GUI requires it)
  uploadVql?: string;      // optional override for the hunt-uploads VQL (DFIR_VELOCIRAPTOR_UPLOAD_VQL); __HUNT_ID__ placeholder
  monitorVql?: string;     // optional override for the per-client client-event read VQL (DFIR_VELOCIRAPTOR_MONITOR_VQL); see DEFAULT_MONITOR_VQL
  monitorAllVql?: string;  // optional override for the ALL-clients client-event read VQL (DFIR_VELOCIRAPTOR_MONITOR_ALL_VQL); see DEFAULT_MONITOR_ALL_VQL
  monitoredVql?: string;   // optional override for the "configured client-event artifacts" VQL (DFIR_VELOCIRAPTOR_MONITORED_VQL); see DEFAULT_MONITORED_VQL
}

export interface VqlRunResult {
  rows: unknown[];
  raw: string;
}

// A runner executes one or more VQL statements (each becomes a positional `query` arg) and returns
// the combined rows. Real impl spawns the binary; tests inject a mock.
export type VqlRunner = (statements: string[], opts: { timeoutMs: number; maxOutputBytes: number }) => Promise<VqlRunResult>;

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

// Velociraptor VQL has no duration-suffix literals (30d, 7h, 2w, etc.). AI models sometimes
// generate them by analogy with other query languages. Rewrite any that appear in arithmetic
// context (after + or -) to seconds so artifact_set does not reject the query at parse time.
// Only operates in operator context to avoid touching unrelated "d"/"h" inside string literals
// such as file paths (e.g. "C:/logs/30day_archive/").
export function sanitizeVqlDurations(vql: string): string {
  return String(vql || "")
    .replace(/([-+])\s*(\d+)w\b/g, "$1 $2 * 604800")
    .replace(/([-+])\s*(\d+)d\b/g, "$1 $2 * 86400")
    .replace(/([-+])\s*(\d+)h\b/g, "$1 $2 * 3600")
    .replace(/([-+])\s*(\d+)m\b/g, "$1 $2 * 60");
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

// Transient process-spawn failures: the velociraptor binary is briefly locked when we try to launch it
// — antivirus real-time scan, a syncing client (Dropbox/OneDrive), or a concurrent spawn of the same
// exe — so spawn() throws EPERM/EBUSY/EACCES/ETXTBSY even though the binary is fine. (Same class
// atomicWrite retries for file renames; here the symptom is "error: spawn EPERM" deploying a 2nd hunt.)
const TRANSIENT_SPAWN = new Set(["EPERM", "EBUSY", "EACCES", "ETXTBSY"]);

// An Error tagged with the OS code of a spawn-LAUNCH failure (binary couldn't start). Only these are
// retried; a query/exit failure (the binary ran, then errored) carries no spawnCode and is never retried.
interface SpawnLaunchError extends Error { spawnCode?: string }

// Build the message for a spawn-launch failure. EPERM/EACCES on a binary that otherwise runs fine is
// almost always the OS security stack denying CreateProcess — and when it's PERSISTENT for only SPECIFIC
// hunts (works for others, survives the retries below), it's antivirus/EDR blocking the velociraptor
// process because that hunt's VQL command line carries credential-dump indicators (e.g. `lsass.dmp`),
// which trips command-line heuristics. Retrying can't clear a policy block, so point the analyst at the
// real remedy. Pure + exported for unit testing. (A genuinely transient lock — sync client / AV file
// scan — is retried automatically by retryTransientSpawn before this surfaces.)
export function spawnErrorMessage(binary: string, err: { message?: string; code?: string }): string {
  const base = `Failed to run velociraptor binary "${binary}": ${err?.message ?? "spawn failed"}`;
  if (err?.code === "EPERM" || err?.code === "EACCES") {
    return base +
      " — the OS denied launching it. If this happens only for SPECIFIC hunts (others deploy fine), your" +
      " antivirus/EDR is most likely blocking the velociraptor process because that hunt's VQL command line" +
      " contains credential-dump indicators (e.g. lsass.dmp). Fix: add an exclusion for the velociraptor" +
      " binary in your AV/EDR, or copy the VQL and run that hunt from the Velociraptor GUI.";
  }
  return base;
}

// Retry an attempt while it fails with a TRANSIENT spawn-launch error; rethrow anything else (a real
// ENOENT/bad-config or a query failure) immediately. Exported + injectable sleep so the backoff logic
// is unit-tested without spawning a process. Mirrors atomicWrite's linear backoff (capped 500ms).
export async function retryTransientSpawn<T>(
  attempt: () => Promise<T>,
  opts: { retries?: number; sleep?: (ms: number) => Promise<void> } = {},
): Promise<T> {
  const retries = opts.retries ?? 6;
  const sleep = opts.sleep ?? ((ms) => new Promise<void>((r) => setTimeout(r, ms)));
  for (let i = 0; ; i++) {
    try {
      return await attempt();
    } catch (e) {
      const code = (e as SpawnLaunchError).spawnCode;
      if (i >= retries || !code || !TRANSIENT_SPAWN.has(code)) throw e;
      await sleep(Math.min(500, 40 * (i + 1)));
    }
  }
}

// One spawn attempt. A LAUNCH failure (spawn threw synchronously — which Windows does for EPERM, so the
// 'error' event never fires — OR the async 'error' event) rejects with `spawnCode` set so the caller can
// retry a transient one. A timeout / output-cap / non-zero exit rejects WITHOUT spawnCode (the binary
// ran; retrying would just repeat the failure).
function spawnVqlOnce(config: VelociraptorApiConfig, statements: string[], opts: { timeoutMs: number; maxOutputBytes: number }): Promise<VqlRunResult> {
  return new Promise<VqlRunResult>((resolve, reject) => {
    const args = ["--api_config", config.apiConfigPath, "query", "--format", "jsonl", ...statements];
    const launchFailed = (e: unknown): void => {
      const code = (e as NodeJS.ErrnoException).code || "ESPAWN";
      const err = new Error(spawnErrorMessage(config.binary, { message: (e as Error).message, code })) as SpawnLaunchError;
      err.spawnCode = code;
      reject(err);
    };
    let child;
    try {
      child = spawn(config.binary, args, { windowsHide: true });
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
      reject(new Error(`Velociraptor query timed out after ${opts.timeoutMs}ms`));
    }, opts.timeoutMs);
    child.stdout.on("data", (d: Buffer) => {
      out += d.toString();
      if (out.length > opts.maxOutputBytes) {
        killed = true;
        child.kill();
        clearTimeout(timer);
        reject(new Error(`Velociraptor query output exceeded ${opts.maxOutputBytes} bytes — raise DFIR_VELOCIRAPTOR_COLLECT_MAX_OUTPUT (collection) / DFIR_VELOCIRAPTOR_MAX_OUTPUT, or narrow the query`));
      }
    });
    child.stderr.on("data", (d: Buffer) => { err += d.toString(); });
    child.on("error", (e) => {
      if (killed) return;
      clearTimeout(timer);
      launchFailed(e);   // async spawn failure (e.g. ENOENT) — tagged so a transient one is retried
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

// The real runner: spawn the velociraptor binary with the api config, no shell (each statement is a
// single argv element — no command injection). Uses jsonl output so multiple queries parse robustly.
// Kills the child on timeout or if output blows the cap, and retries a transient spawn-launch lock.
export function spawnVqlRunner(config: VelociraptorApiConfig): VqlRunner {
  const retries = Number(process.env.DFIR_VELOCIRAPTOR_SPAWN_RETRIES);
  return (statements, opts) => {
    if (statements.length === 0) return Promise.reject(new Error("No runnable VQL found (the query is empty or only comments)"));
    return retryTransientSpawn(() => spawnVqlOnce(config, statements, opts), { retries: Number.isFinite(retries) && retries >= 0 ? retries : undefined });
  };
}

export interface VelociraptorRunResult {
  rows: unknown[];
  total: number;      // total rows the query returned
  truncated: boolean; // true when total > maxRows and rows was capped
}

export interface HuntLaunchResult {
  huntId: string;
  artifact: string;     // the Custom.* artifact the hunt collects
  sources: string[];    // its source names (one per pivot statement)
  state: string;        // RUNNING / PAUSED / …
  guiUrl?: string;      // deep link to the hunt in the Velociraptor GUI (when DFIR_VELOCIRAPTOR_GUI_URL set)
}

// One collectable CLIENT artifact definition on the server (for the bundle builder's picker).
export interface VeloArtifactInfo {
  name: string;         // e.g. "Windows.System.Pslist"
  description: string;  // one-line summary
}

// Optional scoping for a bundle hunt — mirrors Velociraptor's hunt include/exclude conditions.
// Default (all empty) = every enrolled client. Labels are AND-of-include / NOT-exclude; os pins
// the client OS. Restricting keeps heavy triage off the whole fleet.
export interface HuntTarget {
  includeLabels?: string[];
  excludeLabels?: string[];
  os?: "windows" | "linux" | "darwin";
}

// Result of launching a hunt over a chosen SET of existing artifacts (the bundle flow). Distinct
// from HuntLaunchResult (the pivot flow, which builds one Custom.* artifact with named sources).
export interface ArtifactHuntLaunchResult {
  huntId: string;
  artifacts: string[];  // the artifacts the hunt collects (echoed back, validated)
  state: string;        // RUNNING / PAUSED / …
  guiUrl?: string;
}

// Result of launching a single-endpoint COLLECTION (issue #70 — collect_client on ONE host).
// Distinct from a hunt (which fans out across the fleet): the VQL runs only on the resolved client.
export interface CollectLaunchResult {
  clientId: string;     // the Velociraptor client the collection runs on
  flowId: string;       // the launched flow id (F.…)
  hostname: string;     // the host the analyst asked for (echoed back)
  artifact: string;     // the Custom.* artifact built from the VQL
  sources: string[];    // its source names (one per pivot statement) — to read results back via collectionResults
  guiUrl?: string;      // deep link to the flow in the Velociraptor GUI (when DFIR_VELOCIRAPTOR_GUI_URL set)
}

// A file UPLOADED by a hunt's collections (not a result row). Some artifacts (offline collectors,
// THOR/Hayabusa wrappers like Generic.Scanner.ThorZIP) put their real triage data in an uploaded
// JSON file rather than result rows — that JSON is what we ingest.
export interface HuntUpload {
  name: string;      // file name (basename of the upload path)
  clientId: string;  // the endpoint it came from
  content: string;   // the file's text content (read server-side)
}

// Default VQL to enumerate a hunt's uploaded JSON files and read their content server-side. Walks the
// hunt's flows → each flow's uploads → reads `.json` ones from the filestore (`fs` accessor + the
// upload's filestore components). __HUNT_ID__ is replaced with the validated hunt id. Override per
// Velociraptor version with DFIR_VELOCIRAPTOR_UPLOAD_VQL (keep the __HUNT_ID__ placeholder + a
// Name/ClientId/Content column shape).
const DEFAULT_UPLOAD_VQL =
  "LET flows = SELECT Flow.client_id AS ClientId, Flow.session_id AS FlowId FROM hunt_flows(hunt_id='__HUNT_ID__')\n" +
  "LET ups = SELECT * FROM foreach(row=flows, query={ SELECT ClientId, vfs_path AS Path, file_size AS Size, _Components AS Components FROM uploads(client_id=ClientId, flow_id=FlowId) })\n" +
  "SELECT ClientId, Path, basename(path=Path) AS Name, read_file(accessor='fs', filename=Components) AS Content FROM ups WHERE Path =~ '(?i)\\.json$' AND Size < __MAX_BYTES__ AND Content";

// Default VQL to read a CLIENT_EVENT (monitoring) artifact's rows for one client over a time window
// (#84). Velociraptor's `source()` plugin reads a client's monitoring result set when given an event
// artifact + client_id + start_time/end_time (epoch seconds). __CLIENT_ID__/__ARTIFACT__ are validated
// before substitution; __START__/__END__ are integers; __LIMIT__ bounds the rows. Override per
// Velociraptor version with DFIR_VELOCIRAPTOR_MONITOR_VQL (keep the placeholders + a row-per-event shape).
const DEFAULT_MONITOR_VQL =
  "SELECT * FROM source(client_id='__CLIENT_ID__', artifact='__ARTIFACT__', start_time=__START__, end_time=__END__) LIMIT __LIMIT__";

// Default VQL to read a CLIENT_EVENT artifact's rows across ALL enrolled clients in one monitor (#84
// follow-up). `source()` reads ONE client's monitoring set, so we iterate the fleet with `clients()`
// and read each client's set, stamping the client id onto every row. No __CLIENT_ID__ to inject — the
// client id comes from the `clients()` rows, so there's nothing analyst-controlled in the literal.
// Override per Velociraptor version with DFIR_VELOCIRAPTOR_MONITOR_ALL_VQL (keep the placeholders).
const DEFAULT_MONITOR_ALL_VQL =
  "SELECT * FROM foreach(row={ SELECT client_id FROM clients() }, " +
  "query={ SELECT *, client_id AS ClientId FROM source(client_id=client_id, artifact='__ARTIFACT__', start_time=__START__, end_time=__END__) }) LIMIT __LIMIT__";

// Default VQL to read Velociraptor's client-event monitoring table (#84 follow-up — "listen to
// whatever is already configured"). The VQL function is `get_client_monitoring()` — NOT
// `GetClientMonitoringState()`, which is the Go method / gRPC name and returns null as a VQL call. We
// return the WHOLE `ClientEventTable` proto as one row and walk it in TypeScript
// (`extractMonitoredArtifacts`) — far more robust than proto-path-walking in VQL, which is brittle
// across versions (the proto nests `artifacts.artifacts` + `artifacts.specs` + per-label
// `label_events`, casing varies). Override with DFIR_VELOCIRAPTOR_MONITORED_VQL to return either the
// raw state (one `State` column) or simple `{ artifact }` rows — both are handled.
const DEFAULT_MONITORED_VQL =
  "SELECT get_client_monitoring() AS State FROM scope()";

// Pure: pull the configured client-event artifact NAMES out of whatever `listMonitoredArtifacts`' VQL
// returned. Handles (a) the raw `GetClientMonitoringState()` proto (wrapped in `State`/`state`, or bare)
// — walking `artifacts.artifacts` (repeated name) + `artifacts.specs[].artifact` + each
// `label_events[].artifacts.…`, tolerant of PascalCase/camelCase — and (b) a custom override returning
// bare strings or `{ artifact | Name | name }` rows. De-duplicated, validated, order-preserving.
export function extractMonitoredArtifacts(rows: readonly unknown[]): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  const add = (v: unknown): void => {
    const name = String(v ?? "").trim();
    if (name && ARTIFACT_RE.test(name) && !seen.has(name)) { seen.add(name); out.push(name); }
  };
  const ci = (o: Record<string, unknown>, ...keys: string[]): unknown => {
    for (const k of keys) if (o[k] != null) return o[k];
    return undefined;
  };
  const walkTable = (tbl: unknown): void => {
    if (!tbl || typeof tbl !== "object") return;
    const t = tbl as Record<string, unknown>;
    const arts = ci(t, "artifacts", "Artifacts");
    if (arts && typeof arts === "object") {
      const a = arts as Record<string, unknown>;
      const names = ci(a, "artifacts", "Artifacts");
      if (Array.isArray(names)) names.forEach(add);
      const specs = ci(a, "specs", "Specs");
      if (Array.isArray(specs)) for (const s of specs) if (s && typeof s === "object") add(ci(s as Record<string, unknown>, "artifact", "Artifact"));
    }
    const labels = ci(t, "label_events", "labelEvents", "LabelEvents");
    if (Array.isArray(labels)) labels.forEach(walkTable);
  };
  for (const row of rows) {
    if (typeof row === "string") { add(row); continue; }
    if (!row || typeof row !== "object") continue;
    const r = row as Record<string, unknown>;
    const simple = ci(r, "artifact", "Name", "name");           // override `{ artifact }` shape
    if (typeof simple === "string") add(simple);
    walkTable(ci(r, "State", "state") ?? r);                    // raw GetClientMonitoringState() proto
  }
  return out;
}

export const ALL_CLIENTS = "*";             // sentinel client id meaning "every enrolled client"
const ARTIFACT_RE = /^[A-Za-z0-9._]+$/;     // valid Velociraptor artifact / source name
const HUNT_RE = /^H\.[A-Za-z0-9]+$/;        // valid hunt id
const FLOW_RE = /^F\.[A-Za-z0-9]+$/;        // valid collection flow id (collect_client)
const CLIENT_RE = /^C\.[A-Za-z0-9]+$/;      // valid Velociraptor client id

// One enrolled endpoint as the Companion records it in the persisted client INVENTORY (issue #70).
export interface VeloClientRecord {
  clientId: string;
  hostname: string;
  fqdn: string;
  lastSeen?: string;
}

// Normalize one `clients()` row → a record (or null if it has no usable client id). Casing-tolerant:
// `client_id`/`ClientId`, and `os_info.hostname`/`os_info.Hostname` (+ `fqdn`/`Fqdn`) differ across
// Velociraptor versions and depending on whether the VQL aliases the columns.
export function normalizeClientRow(row: unknown): VeloClientRecord | null {
  const r = (row ?? {}) as { client_id?: unknown; ClientId?: unknown; os_info?: Record<string, unknown>; OsInfo?: Record<string, unknown>; last_seen_at?: unknown; LastSeen?: unknown };
  const clientId = String(r.client_id ?? r.ClientId ?? "");
  if (!CLIENT_RE.test(clientId)) return null;
  const os = (r.os_info ?? r.OsInfo ?? {}) as Record<string, unknown>;
  const hostname = String(os.hostname ?? os.Hostname ?? "").trim();
  const fqdn = String(os.fqdn ?? os.Fqdn ?? "").trim();
  const last = r.last_seen_at ?? r.LastSeen;
  return { clientId, hostname, fqdn, ...(last != null && last !== "" ? { lastSeen: String(last) } : {}) };
}

// Pure: the best client record for a target host, from the inventory. Robust to the two real-world
// mismatches that make a naive `clients(search='host:<fqdn>')` miss: the client enrolled with its
// SHORT name while the case asset is an FQDN (or vice-versa). Exact full match (hostname or FQDN) wins
// over a first-label match; case-insensitive. Returns undefined when nothing matches.
export function matchClient(records: readonly VeloClientRecord[], host: string): VeloClientRecord | undefined {
  const target = String(host || "").trim().toLowerCase();
  if (!target) return undefined;
  const targetShort = target.split(".")[0];
  const valid = (records ?? []).filter((r) => r && CLIENT_RE.test(r.clientId));
  // Pass 1: exact full match on hostname or FQDN (the safest disambiguation).
  for (const r of valid) if (r.hostname.toLowerCase() === target || r.fqdn.toLowerCase() === target) return r;
  // Pass 2: first-label match either way ("WIN11" ↔ "WIN11.windomain.local").
  for (const r of valid) {
    const hn = r.hostname.toLowerCase(), fq = r.fqdn.toLowerCase();
    if (hn && (hn === targetShort || hn.split(".")[0] === targetShort)) return r;
    if (fq && (fq === targetShort || fq.split(".")[0] === targetShort)) return r;
  }
  return undefined;
}

// Slug for a generated artifact name: alphanumerics from the description, capped.
function slugify(s: string): string {
  return String(s || "").replace(/[^A-Za-z0-9]+/g, "_").replace(/^_+|_+$/g, "").slice(0, 48) || "Pivot";
}
// Sanitize free text (e.g. an event label with a `\\.\C:\…` path) for embedding in BOTH a YAML
// double-quoted scalar and a VQL single-quoted string: collapse to one ASCII line and strip
// backslashes and quotes (YAML treats `\` as an escape and a stray quote terminates the literal).
function oneLine(s: string): string {
  return String(s || "")
    .replace(/[\r\n]+/g, " ")
    .replace(/[^\x20-\x7E]/g, "")
    .replace(/[\\'"]/g, "")
    .slice(0, 200);
}

// Sanitize Velociraptor client labels for embedding in a single-quoted VQL string list: keep only a
// safe charset (so no quote/backslash can break out of the literal), drop empties, cap the count.
function sanitizeLabels(labels?: string[]): string[] {
  if (!Array.isArray(labels)) return [];
  return labels
    .map((l) => String(l ?? "").replace(/[^A-Za-z0-9._\- ]/g, "").trim())
    .filter(Boolean)
    .slice(0, 50);
}

// Constrain a free-text OS to the three Velociraptor client OS values, else undefined (no filter).
function normalizeOs(os?: string): "windows" | "linux" | "darwin" | undefined {
  const v = String(os ?? "").trim().toLowerCase();
  return v === "windows" || v === "linux" || v === "darwin" ? v : undefined;
}

// Normalize an analyst-authored VQL WHERE expression for inlining into a hunt_results query: one line,
// no trailing ';', length-capped. Localhost/trusted analyst (same as the pivot-hunt VQL); it's wrapped
// in parentheses at the call site so it stays a contained boolean expression.
function sanitizeWhere(where?: string): string {
  if (!where) return "";
  return String(where).replace(/[\r\n]+/g, " ").replace(/;+\s*$/, "").trim().slice(0, 1000);
}

const PARAM_RE = /^[A-Za-z_][A-Za-z0-9_]*$/;   // valid Velociraptor parameter name

// Build the hunt's `spec` clause from per-artifact parameter overrides so a heavy artifact runs with
// fewer/narrower outputs at the source (e.g. `Windows.Hayabusa.Rules`=dict(RuleLevel='Critical, High, and Medium')). Only
// artifacts actually in this hunt are included; param names are validated and values are sanitized into
// single-quoted strings (Velociraptor coerces). Returns undefined when there's nothing to set.
function buildHuntSpec(names: string[], params?: Record<string, Record<string, string>>): string | undefined {
  if (!params || typeof params !== "object") return undefined;
  const inHunt = new Set(names);
  const entries: string[] = [];
  for (const [artifact, kv] of Object.entries(params)) {
    if (!ARTIFACT_RE.test(artifact) || !inHunt.has(artifact) || !kv || typeof kv !== "object") continue;
    const pairs = Object.entries(kv)
      .filter(([k]) => PARAM_RE.test(k))
      .map(([k, v]) => `${k}='${oneLine(String(v))}'`);
    if (pairs.length) entries.push(`\`${artifact}\`=dict(${pairs.join(", ")})`);
  }
  return entries.length ? `spec=dict(${entries.join(", ")})` : undefined;
}

// A CLIENT artifact (YAML) with one source per pivot statement — collected by the hunt on every endpoint.
function buildHuntArtifact(name: string, statements: string[], sources: string[], description: string): string {
  const blocks = statements
    .map((q, i) => `  - name: ${sources[i]}\n    query: |\n${q.split(/\r?\n/).map((l) => "      " + l).join("\n")}`)
    .join("\n");
  return `name: ${name}\ndescription: "${oneLine(description)}"\ntype: CLIENT\nsources:\n${blocks}\n`;
}

export class VelociraptorClient {
  constructor(
    private readonly config: VelociraptorApiConfig,
    private readonly runner: VqlRunner = spawnVqlRunner(config),
  ) {}

  private cap(rows: unknown[]): VelociraptorRunResult {
    return { rows: rows.slice(0, this.config.maxRows), total: rows.length, truncated: rows.length > this.config.maxRows };
  }

  // Deep link to a hunt in the Velociraptor GUI. The `?org_id=…` MUST come before the `#` fragment
  // (the SPA router reads the org from the query, the hunt from the hash) — without it the GUI opens
  // the wrong/empty org. Defaults to the `root` org; override with DFIR_VELOCIRAPTOR_ORG.
  private huntGuiUrl(huntId: string): string | undefined {
    if (!this.config.guiUrl) return undefined;
    const base = this.config.guiUrl.replace(/\/+$/, "");
    const org = encodeURIComponent(this.config.guiOrg?.trim() || "root");
    return `${base}/app/index.html?org_id=${org}#/hunts/${huntId}`;
  }

  // Deep link to a single client's COLLECTION (flow) in the GUI. Same `?org_id=` before `#` invariant
  // as huntGuiUrl — the SPA reads the org from the query and the flow from the hash route.
  private collectGuiUrl(clientId: string, flowId: string): string | undefined {
    if (!this.config.guiUrl) return undefined;
    const base = this.config.guiUrl.replace(/\/+$/, "");
    const org = encodeURIComponent(this.config.guiOrg?.trim() || "root");
    return `${base}/app/index.html?org_id=${org}#/collected/${clientId}/${flowId}`;
  }

  // Run a single VQL program verbatim (no statement-splitting) — for internal orchestration VQL.
  // maxOutputBytes can be raised for bulk collection reads (forensic data is large).
  private async runRaw(program: string, maxOutputBytes: number = this.config.maxOutputBytes): Promise<unknown[]> {
    const { rows } = await this.runner([program], { timeoutMs: this.config.timeoutMs, maxOutputBytes });
    return rows;
  }

  // The larger stdout cap to use for bundle-hunt collection (rows + uploaded JSON), falling back to the
  // interactive cap when unset.
  private collectCap(): number {
    return this.config.collectMaxOutputBytes || this.config.maxOutputBytes;
  }

  // Run analyst pivot VQL server-side (split into statements). Kept for ad-hoc/server-scoped queries;
  // the dashboard hunt flow uses launchHunt() instead so queries run on the endpoints.
  async run(vql: string): Promise<VelociraptorRunResult> {
    const statements = splitVqlStatements(vql);
    if (statements.length === 0) throw new Error("No runnable VQL found (the query is empty or only comments)");
    const { rows } = await this.runner(statements, {
      timeoutMs: this.config.timeoutMs,
      maxOutputBytes: this.config.maxOutputBytes,
    });
    return this.cap(rows);
  }

  // Launch a HUNT that runs the pivot VQL on ALL enrolled clients: package the (comment-stripped)
  // pivots as a CLIENT artifact, then create the hunt. Returns the hunt id; results arrive
  // asynchronously as endpoints check in (read them with huntResults()).
  async launchHunt(vql: string, description: string): Promise<HuntLaunchResult> {
    const statements = splitVqlStatements(sanitizeVqlDurations(vql));
    if (statements.length === 0) throw new Error("No runnable VQL found (the query is empty or only comments)");
    const name = "Custom.Hunt.Companion." + slugify(description);
    const sources = statements.map((_, i) => `Pivot${i}`);
    const yaml = buildHuntArtifact(name, statements, sources, description);
    const program =
      `LET def = '''${yaml}'''\n` +
      `LET _set <= artifact_set(definition=def)\n` +
      `SELECT hunt(description='${oneLine("DFIR Companion: " + description)}', artifacts='${name}') AS Hunt FROM scope()`;
    const rows = await this.runRaw(program);
    const hunt = (rows[0] as { Hunt?: Record<string, unknown> })?.Hunt ?? {};
    const huntId = String(hunt.HuntId ?? hunt.hunt_id ?? "");
    if (!HUNT_RE.test(huntId)) throw new Error("Velociraptor did not launch the hunt (no hunt id). The VQL likely references a non-existent artifact/plugin or has a syntax error so it can't compile — edit the VQL and retry. (Less commonly: the api_client role lacks COLLECT_CLIENT/ARTIFACT_WRITER.)");
    return {
      huntId,
      artifact: name,
      sources,
      state: String(hunt.state ?? hunt.State ?? "RUNNING"),
      guiUrl: this.huntGuiUrl(huntId),
    };
  }

  // Snapshot the whole enrolled fleet — client_id + hostname + fqdn per client — so the Companion can
  // persist an INVENTORY and resolve a host → client_id from that file (robust + fast) instead of a
  // brittle live `clients(search=...)` lookup whose index tokenizes the hostname on dots. Metadata
  // only, so the per-query row cap is NOT applied (use the larger collect cap; a server can have many).
  async listClients(): Promise<VeloClientRecord[]> {
    const rows = await this.runRaw("SELECT client_id, os_info, last_seen_at FROM clients() LIMIT 100000", this.collectCap());
    const out: VeloClientRecord[] = [];
    for (const row of rows) {
      const rec = normalizeClientRow(row);
      if (rec) out.push(rec);
    }
    return out;
  }

  // Launch the VQL as a COLLECTION on a known client_id (issue #70) — the inventory already resolved
  // the host → client_id, so this just packages the pivot(s) as a CLIENT artifact and `collect_client`
  // on that one client. clientId is CLIENT_RE-validated, so it's safe inside the VQL literal. The
  // resulting flow is reviewed in the Velociraptor GUI via the returned deep link.
  async collectOnClient(clientId: string, vql: string, description: string, hostname = ""): Promise<CollectLaunchResult> {
    if (!CLIENT_RE.test(clientId)) throw new Error(`invalid Velociraptor client id "${clientId}"`);
    const statements = splitVqlStatements(sanitizeVqlDurations(vql));
    if (statements.length === 0) throw new Error("No runnable VQL found (the query is empty or only comments)");
    const name = "Custom.Collect.Companion." + slugify(description);
    const sources = statements.map((_, i) => `Pivot${i}`);
    const yaml = buildHuntArtifact(name, statements, sources, description);
    const program =
      `LET def = '''${yaml}'''\n` +
      `LET _set <= artifact_set(definition=def)\n` +
      `SELECT collect_client(client_id='${clientId}', artifacts=['${name}']) AS Flow FROM scope()`;
    const rows = await this.runRaw(program);
    const flow = (rows[0] as { Flow?: Record<string, unknown> })?.Flow ?? {};
    const flowId = String(flow.flow_id ?? flow.FlowId ?? flow.session_id ?? "");
    // collect_client returns a null flow when the custom artifact can't COMPILE — almost always the VQL
    // references a non-existent Artifact.<Name>/plugin or has a syntax error (the simple cases launch
    // fine, so it's rarely a permissions issue). Point the analyst at the VQL first.
    if (!FLOW_RE.test(flowId)) throw new Error("Velociraptor did not launch the collection (no flow id). The VQL likely references a non-existent artifact/plugin or has a syntax error so it can't compile — edit the VQL and retry. (Less commonly: the api_client role lacks COLLECT_CLIENT/ARTIFACT_WRITER.)");
    return { clientId, flowId, hostname: hostname || clientId, artifact: name, sources, guiUrl: this.collectGuiUrl(clientId, flowId) };
  }

  // Read a single COLLECTION flow's result rows (issue #70) — the per-flow analog of huntResults(),
  // so the dashboard can show a collection's results inline (and auto-poll) instead of only deep-linking
  // to the GUI. Reads each named source via `source(client_id=, flow_id=, artifact='Custom.X/Pivot0')`
  // (same `artifact/source` addressing huntResults uses). All ids are validated to stay safe in the literals.
  async collectionResults(clientId: string, flowId: string, artifact: string, sources: string[] = [], where?: string): Promise<VelociraptorRunResult> {
    if (!CLIENT_RE.test(clientId)) throw new Error("invalid client id");
    if (!FLOW_RE.test(flowId)) throw new Error("invalid flow id");
    if (!ARTIFACT_RE.test(artifact)) throw new Error("invalid artifact name");
    const safe = sources.filter((s) => ARTIFACT_RE.test(s));
    const refs = safe.length ? safe.map((s) => `${artifact}/${s}`) : [artifact];
    const w = sanitizeWhere(where);
    const whereClause = w ? ` WHERE (${w})` : "";
    const limit = this.config.maxRows + 1;   // +1 so cap() flags truncation
    const program = refs.length > 1
      ? `SELECT * FROM chain(${refs.map((ref, i) => `q${i}={ SELECT * FROM source(client_id='${clientId}', flow_id='${flowId}', artifact='${ref}')${whereClause} LIMIT ${limit} }`).join(", ")})`
      : `SELECT * FROM source(client_id='${clientId}', flow_id='${flowId}', artifact='${refs[0]}')${whereClause} LIMIT ${limit}`;
    return this.cap(await this.runRaw(program, this.collectCap()));
  }

  // The terminal STATE + error of a collection flow (issue #70). A flow can launch fine (a flow id is
  // returned) yet FAIL on the endpoint — e.g. the VQL passes an unknown plugin arg ("handles: Unexpected
  // arg process"). `flows(client_id=)` carries the per-flow `state` (RUNNING/FINISHED/ERROR) and, when
  // it errored, the message in `status`. So the dashboard can show the real failure instead of polling
  // "no results yet" forever. Returns `{ state: "" }` when the flow isn't found.
  async flowStatus(clientId: string, flowId: string): Promise<{ state: string; error: string; rows: number }> {
    if (!CLIENT_RE.test(clientId)) throw new Error("invalid client id");
    if (!FLOW_RE.test(flowId)) throw new Error("invalid flow id");
    const program = `SELECT state, status, total_collected_rows FROM flows(client_id='${clientId}') WHERE session_id='${flowId}' LIMIT 1`;
    const rows = await this.runRaw(program);
    const r = (rows[0] ?? {}) as { state?: unknown; status?: unknown; total_collected_rows?: unknown };
    const state = String(r.state ?? "").trim();
    const error = state.toUpperCase() === "ERROR" ? String(r.status ?? "").trim() : "";
    return { state, error, rows: Number(r.total_collected_rows ?? 0) || 0 };
  }

  // Convenience: resolve a hostname LIVE (enumerate the fleet + match in TS, short-name ⇄ FQDN
  // tolerant) then collect on it. The server's collect route prefers the persisted inventory; this is
  // the no-inventory / programmatic / CLI path. The hostname is matched in TS — never embedded in VQL.
  async collectFromHost(hostname: string, vql: string, description: string): Promise<CollectLaunchResult> {
    const host = String(hostname ?? "").trim();
    if (!host) throw new Error("a target hostname is required for a single-endpoint collection");
    if (splitVqlStatements(sanitizeVqlDurations(vql)).length === 0) throw new Error("No runnable VQL found (the query is empty or only comments)");
    const rec = matchClient(await this.listClients(), host);
    if (!rec) throw new Error(`No enrolled Velociraptor client matches host "${host}" — refresh the client list or run a fleet hunt instead`);
    return this.collectOnClient(rec.clientId, vql, description, host);
  }

  // Read a hunt's collected results across its sources (combining all endpoints' rows). Validates the
  // ids to keep them safe inside the VQL string literals.
  async huntResults(huntId: string, artifact: string, sources: string[] = [], where?: string): Promise<VelociraptorRunResult> {
    if (!HUNT_RE.test(huntId)) throw new Error("invalid hunt id");
    if (!ARTIFACT_RE.test(artifact)) throw new Error("invalid artifact name");
    // Named sources are addressed as `artifact/source` (the `source=` param does NOT match them).
    const safe = sources.filter((s) => ARTIFACT_RE.test(s));
    const refs = safe.length ? safe.map((s) => `${artifact}/${s}`) : [artifact];
    // Optional analyst WHERE filter applied BEFORE the LIMIT, so noisy rows are dropped at the source
    // and the kept rows are the relevant ones (not the first N pre-filter). LIMIT at the source so a huge
    // result set (e.g. Hayabusa across a fleet) can't blow the stdout cap; maxRows+1 so cap() flags truncation.
    const w = sanitizeWhere(where);
    const whereClause = w ? ` WHERE (${w})` : "";
    const limit = this.config.maxRows + 1;
    const program = refs.length > 1
      ? `SELECT * FROM chain(${refs.map((ref, i) => `q${i}={ SELECT * FROM hunt_results(hunt_id='${huntId}', artifact='${ref}')${whereClause} LIMIT ${limit} }`).join(", ")})`
      : `SELECT * FROM hunt_results(hunt_id='${huntId}', artifact='${refs[0]}')${whereClause} LIMIT ${limit}`;
    return this.cap(await this.runRaw(program, this.collectCap()));
  }

  // List the server's artifacts of a given type — CLIENT (collectable, for triage bundles) or
  // CLIENT_EVENT (continuous client monitoring, for the live-monitor picker, #84). Returns metadata
  // only (no evidence), so the per-query row cap is NOT applied. The type is filtered in TYPESCRIPT
  // (not VQL): `artifact_definitions()` reports the type with inconsistent casing/spacing across
  // versions (`CLIENT_EVENT` / `client_event` / `Client Event`), and a VQL `=~`/`lowercase()` filter
  // missed them → empty picker. Fetching all + normalizing the type string in TS is version-proof.
  async listClientArtifacts(type: "client" | "client_event" = "client"): Promise<VeloArtifactInfo[]> {
    const wanted = type === "client_event" ? "client_event" : "client";
    const rows = await this.runRaw("SELECT name, description, type FROM artifact_definitions() ORDER BY name", this.collectCap());
    const out: VeloArtifactInfo[] = [];
    for (const row of rows) {
      const r = row as { name?: unknown; description?: unknown; type?: unknown };
      const name = String(r.name ?? "").trim();
      if (!name) continue;
      const t = String(r.type ?? "").trim().toLowerCase().replace(/[\s-]+/g, "_");
      if (t !== wanted) continue;
      out.push({ name, description: String(r.description ?? "").replace(/[\r\n]+/g, " ").trim().slice(0, 300) });
    }
    return out;
  }

  // Diagnostics for the live-monitor features (#84) when the picker / auto-discovery come back empty
  // on a real server: the distinct artifact `type` strings + counts (so we can see the real casing),
  // the raw `get_client_monitoring()` rows (the configured monitoring table), and how many CLIENT_EVENT
  // artifacts matched. Each probe is independent — one failing doesn't abort the others. Localhost only.
  async diagnostics(): Promise<{ artifactTypes: Record<string, number>; clientEventCount: number; monitoringState: unknown; errors: Record<string, string> }> {
    const errors: Record<string, string> = {};
    const artifactTypes: Record<string, number> = {};
    let clientEventCount = 0;
    try {
      const rows = await this.runRaw("SELECT type FROM artifact_definitions()", this.collectCap());
      for (const row of rows) {
        const t = String((row as { type?: unknown }).type ?? "").trim();
        artifactTypes[t || "(empty)"] = (artifactTypes[t || "(empty)"] ?? 0) + 1;
        if (t.toLowerCase().replace(/[\s-]+/g, "_") === "client_event") clientEventCount++;
      }
    } catch (e) { errors.artifactTypes = (e as Error).message; }
    let monitoringState: unknown = null;
    try { monitoringState = await this.monitoringStateRaw(); }
    catch (e) { errors.monitoringState = (e as Error).message; }
    return { artifactTypes, clientEventCount, monitoringState, errors };
  }

  // Run the "configured client-event artifacts" VQL and return the RAW rows — used for diagnostics when
  // the monitoring-table read comes back empty, so the analyst's server log shows the actual proto
  // shape (and what to put in DFIR_VELOCIRAPTOR_MONITORED_VQL). Never throws past runRaw.
  async monitoringStateRaw(): Promise<unknown[]> {
    const program = this.config.monitoredVql && this.config.monitoredVql.trim() ? this.config.monitoredVql : DEFAULT_MONITORED_VQL;
    return this.runRaw(program);
  }

  // Read a CLIENT_EVENT (monitoring) artifact's rows over [startEpoch, endEpoch] (epoch seconds) — the
  // live-monitor poller's read step (#84). `clientId` is either a real client (`C....`) or the
  // ALL_CLIENTS sentinel (`*`) to read across EVERY enrolled client in one pass (the all-clients VQL
  // iterates `clients()` itself, so no client id is interpolated). Like collectionResults/huntResults,
  // all interpolated values are validated/bounded so they're safe inside the VQL literals: the artifact
  // name matches its charset regex and the times are coerced to non-negative integers. Uses the larger
  // collect cap (monitoring bursts — especially fleet-wide — can be large) and the row cap.
  async monitorResults(clientId: string, artifact: string, startEpoch: number, endEpoch: number): Promise<VelociraptorRunResult> {
    const all = clientId === ALL_CLIENTS;
    if (!all && !CLIENT_RE.test(clientId)) throw new Error("invalid client id");
    if (!ARTIFACT_RE.test(artifact)) throw new Error("invalid artifact name");
    const start = Math.max(0, Math.floor(Number(startEpoch) || 0));
    const end = Math.max(start, Math.floor(Number(endEpoch) || 0));
    const limit = this.config.maxRows + 1;   // +1 so cap() flags truncation
    const template = all
      ? (this.config.monitorAllVql && this.config.monitorAllVql.trim() ? this.config.monitorAllVql : DEFAULT_MONITOR_ALL_VQL)
      : (this.config.monitorVql && this.config.monitorVql.trim() ? this.config.monitorVql : DEFAULT_MONITOR_VQL);
    const program = template
      .split("__CLIENT_ID__").join(all ? "" : clientId)
      .split("__ARTIFACT__").join(artifact)
      .split("__START__").join(String(start))
      .split("__END__").join(String(end))
      .split("__LIMIT__").join(String(limit));
    return this.cap(await this.runRaw(program, this.collectCap()));
  }

  // List the client-event artifacts ALREADY enabled in Velociraptor's client monitoring table (#84
  // follow-up — "auto-listen to what's already configured"). Reads GetClientMonitoringState() (the
  // all-clients monitoring table by default; override with DFIR_VELOCIRAPTOR_MONITORED_VQL for a
  // version where the proto differs or to include label-scoped tables). Returns de-duplicated artifact
  // names; empty list (not a throw) when nothing is configured, so the caller can degrade gracefully.
  async listMonitoredArtifacts(): Promise<string[]> {
    return extractMonitoredArtifacts(await this.monitoringStateRaw());
  }

  // Launch a HUNT that collects a CHOSEN SET of existing artifacts (a saved bundle) across the fleet,
  // optionally scoped by include/exclude labels + OS. `opts.timeoutSeconds` overrides Velociraptor's
  // default per-collection timeout (600s) — some artifacts (e.g. THOR via Generic.Scanner.ThorZIP) run
  // longer. Artifact names are validated (no VQL injection); labels are sanitized to a safe charset.
  // Results arrive asynchronously — collect with huntResultsByArtifact() after a delay.
  async launchArtifactHunt(
    artifacts: string[],
    description: string,
    target: HuntTarget = {},
    opts: { timeoutSeconds?: number; params?: Record<string, Record<string, string>> } = {},
  ): Promise<ArtifactHuntLaunchResult> {
    const names = (artifacts ?? []).map((a) => String(a ?? "").trim()).filter(Boolean);
    if (names.length === 0) throw new Error("no artifacts to hunt");
    for (const n of names) {
      if (!ARTIFACT_RE.test(n)) throw new Error(`invalid artifact name: ${n}`);
    }
    const clauses = [
      `description='${oneLine("DFIR Companion: " + description)}'`,
      `artifacts=[${names.map((n) => `'${n}'`).join(", ")}]`,
    ];
    const inc = sanitizeLabels(target.includeLabels);
    const exc = sanitizeLabels(target.excludeLabels);
    if (inc.length) clauses.push(`include_labels=[${inc.map((l) => `'${l}'`).join(", ")}]`);
    if (exc.length) clauses.push(`exclude_labels=[${exc.map((l) => `'${l}'`).join(", ")}]`);
    const os = normalizeOs(target.os);
    if (os) clauses.push(`os='${os}'`);
    const timeout = Number(opts.timeoutSeconds);
    if (Number.isFinite(timeout) && timeout > 0) clauses.push(`timeout=${Math.floor(timeout)}`);   // collection timeout (s)
    const spec = buildHuntSpec(names, opts.params);   // per-artifact parameters (e.g. Hayabusa RuleLevel/RuleStatus)
    if (spec) clauses.push(spec);
    const program = `SELECT hunt(${clauses.join(", ")}) AS Hunt FROM scope()`;
    const rows = await this.runRaw(program);
    const hunt = (rows[0] as { Hunt?: Record<string, unknown> })?.Hunt ?? {};
    const huntId = String(hunt.HuntId ?? hunt.hunt_id ?? "");
    if (!HUNT_RE.test(huntId)) throw new Error("Velociraptor did not return a hunt id — check the api_client role has COLLECT_CLIENT/ARTIFACT_WRITER");
    return {
      huntId,
      artifacts: names,
      state: String(hunt.state ?? hunt.State ?? "RUNNING"),
      guiUrl: this.huntGuiUrl(huntId),
    };
  }

  // Read a bundle hunt's results, keyed by artifact name — the artifact-map shape importVelociraptor
  // consumes ({ "Windows.System.Pslist": [...rows], ... }). RESILIENT: each artifact is fetched
  // independently, and one that fails (e.g. output still over the cap) is added to `skipped` instead of
  // aborting the whole collection — so a bundle with a heavy artifact (Hayabusa) still imports the rest.
  // Only artifacts that returned rows are in `results` (empty ones are dropped; clients may not have
  // checked in yet, and the artifact-map needs non-empty arrays).
  async huntResultsByArtifact(huntId: string, artifacts: string[], filters?: Record<string, string>, sourcesByArtifact?: Record<string, string[]>): Promise<{ results: Record<string, unknown[]>; skipped: string[] }> {
    if (!HUNT_RE.test(huntId)) throw new Error("invalid hunt id");
    const results: Record<string, unknown[]> = {};
    const skipped: string[] = [];
    for (const artifact of artifacts ?? []) {
      const name = String(artifact ?? "").trim();
      if (!ARTIFACT_RE.test(name)) continue;   // skip invalid names rather than fail the whole collect
      try {
        // Named sources are addressed as `artifact/source`. Bundle artifacts use a default source (empty
        // sources is correct); a Companion-launched fleet-hunt artifact stores its rows under named sources
        // (Pivot0…), so its results are 0 unless we pass them (the cause of false "no evidence", #157).
        const res = await this.huntResults(huntId, name, sourcesByArtifact?.[name] ?? [], filters?.[name]);
        if (res.rows.length) results[name] = res.rows;
      } catch {
        skipped.push(name);   // oversized / slow / failed — keep going (the caller logs the skips)
      }
    }
    return { results, skipped };
  }

  // Read a hunt's uploaded JSON files (content included), so an artifact whose meaningful output is an
  // uploaded report (e.g. THOR/Hayabusa JSON) can be ingested. Best-effort and version-sensitive —
  // the caller should tolerate a throw (a wrong VQL for the server version) and fall back to rows.
  // Override the VQL with DFIR_VELOCIRAPTOR_UPLOAD_VQL. The hunt id is HUNT_RE-validated before
  // substitution, so interpolating it into the program is injection-safe.
  async huntUploads(huntId: string): Promise<HuntUpload[]> {
    if (!HUNT_RE.test(huntId)) throw new Error("invalid hunt id");
    const cap = this.collectCap();
    const template = this.config.uploadVql && this.config.uploadVql.trim() ? this.config.uploadVql : DEFAULT_UPLOAD_VQL;
    // __MAX_BYTES__ lets the VQL skip a single upload bigger than the cap at the source (so one huge
    // file doesn't blow the read); __HUNT_ID__ is the validated hunt id.
    const program = template.split("__HUNT_ID__").join(huntId).split("__MAX_BYTES__").join(String(cap));
    const rows = await this.runRaw(program, cap);
    const out: HuntUpload[] = [];
    for (const row of rows) {
      const r = row as { Name?: unknown; ClientId?: unknown; Content?: unknown; Path?: unknown };
      const content = typeof r.Content === "string" ? r.Content : "";
      if (!content.trim()) continue;
      out.push({
        name: String(r.Name ?? r.Path ?? "upload.json"),
        clientId: String(r.ClientId ?? ""),
        content,
      });
    }
    return out;
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
    collectMaxOutputBytes: Number(env.DFIR_VELOCIRAPTOR_COLLECT_MAX_OUTPUT) || 256 * 1024 * 1024,
    guiUrl: env.DFIR_VELOCIRAPTOR_GUI_URL?.trim() || undefined,
    guiOrg: env.DFIR_VELOCIRAPTOR_ORG?.trim() || "root",
    uploadVql: env.DFIR_VELOCIRAPTOR_UPLOAD_VQL?.trim() || undefined,
    monitorVql: env.DFIR_VELOCIRAPTOR_MONITOR_VQL?.trim() || undefined,
    monitorAllVql: env.DFIR_VELOCIRAPTOR_MONITOR_ALL_VQL?.trim() || undefined,
    monitoredVql: env.DFIR_VELOCIRAPTOR_MONITORED_VQL?.trim() || undefined,
  };
}

// Construct a client when configured, else undefined (mirrors buildIrisClient()).
export function buildVelociraptorClient(env: NodeJS.ProcessEnv = process.env): VelociraptorClient | undefined {
  const config = loadVelociraptorConfig(env);
  return config ? new VelociraptorClient(config) : undefined;
}
