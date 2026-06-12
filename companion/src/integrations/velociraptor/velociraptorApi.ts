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

// The real runner: spawn the velociraptor binary with the api config, no shell (each statement is a
// single argv element — no command injection). Uses jsonl output so multiple queries parse robustly.
// Kills the child on timeout or if output blows the cap.
export function spawnVqlRunner(config: VelociraptorApiConfig): VqlRunner {
  return (statements, opts) =>
    new Promise<VqlRunResult>((resolve, reject) => {
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
          reject(new Error(`Velociraptor query output exceeded ${opts.maxOutputBytes} bytes — raise DFIR_VELOCIRAPTOR_COLLECT_MAX_OUTPUT (collection) / DFIR_VELOCIRAPTOR_MAX_OUTPUT, or narrow the query`));
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

const ARTIFACT_RE = /^[A-Za-z0-9._]+$/;     // valid Velociraptor artifact / source name
const HUNT_RE = /^H\.[A-Za-z0-9]+$/;        // valid hunt id
const FLOW_RE = /^F\.[A-Za-z0-9]+$/;        // valid collection flow id (collect_client)

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
    if (!HUNT_RE.test(huntId)) throw new Error("Velociraptor did not return a hunt id — check the api_client role has COLLECT_CLIENT/ARTIFACT_WRITER");
    return {
      huntId,
      artifact: name,
      sources,
      state: String(hunt.state ?? hunt.State ?? "RUNNING"),
      guiUrl: this.huntGuiUrl(huntId),
    };
  }

  // Launch the VQL as a COLLECTION on a SINGLE endpoint (issue #70) — the "run on just this host"
  // counterpart to launchHunt's fleet-wide hunt. Resolves the hostname to a client_id (most-recently-
  // seen wins), packages the pivot(s) as a CLIENT artifact, then `collect_client` on that one client.
  // The hostname is the only free-text input — sanitized via oneLine() (strips the quote/backslash that
  // could break out of the single-quoted VQL literal), exactly like launchHunt's description. Results
  // are reviewed in the Velociraptor GUI via the returned flow deep link.
  async collectFromHost(hostname: string, vql: string, description: string): Promise<CollectLaunchResult> {
    const host = oneLine(hostname);
    if (!host) throw new Error("a target hostname is required for a single-endpoint collection");
    const statements = splitVqlStatements(sanitizeVqlDurations(vql));
    if (statements.length === 0) throw new Error("No runnable VQL found (the query is empty or only comments)");
    const name = "Custom.Collect.Companion." + slugify(description);
    const sources = statements.map((_, i) => `Pivot${i}`);
    const yaml = buildHuntArtifact(name, statements, sources, description);
    // One program: define the artifact, resolve the client (newest check-in for the host), collect on it.
    const program =
      `LET def = '''${yaml}'''\n` +
      `LET _set <= artifact_set(definition=def)\n` +
      `LET client <= SELECT client_id AS ClientId, os_info.hostname AS Hostname FROM clients(search='host:${host}') ORDER BY last_seen_at DESC LIMIT 1\n` +
      `SELECT ClientId, collect_client(client_id=ClientId, artifacts=['${name}']) AS Flow FROM client`;
    const rows = await this.runRaw(program);
    const row = rows[0] as { ClientId?: unknown; Flow?: Record<string, unknown> } | undefined;
    const clientId = String(row?.ClientId ?? "");
    if (!row || !clientId) throw new Error(`No enrolled Velociraptor client matches host "${host}" — check the hostname or run a fleet hunt instead`);
    const flow = row.Flow ?? {};
    const flowId = String(flow.flow_id ?? flow.FlowId ?? flow.session_id ?? "");
    if (!FLOW_RE.test(flowId)) throw new Error("Velociraptor did not return a collection flow id — check the api_client role has COLLECT_CLIENT/ARTIFACT_WRITER");
    return {
      clientId,
      flowId,
      hostname: host,
      artifact: name,
      guiUrl: this.collectGuiUrl(clientId, flowId),
    };
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

  // List the server's COLLECTABLE client artifacts (type CLIENT, not CLIENT_EVENT monitoring) so the
  // dashboard can build triage bundles from real artifact names. Returns metadata only (no evidence),
  // so the per-query row cap is NOT applied — a server can define hundreds.
  async listClientArtifacts(): Promise<VeloArtifactInfo[]> {
    const program = "SELECT name, description, type FROM artifact_definitions() WHERE type =~ '^client$' ORDER BY name";
    const rows = await this.runRaw(program);
    const out: VeloArtifactInfo[] = [];
    for (const row of rows) {
      const r = row as { name?: unknown; description?: unknown };
      const name = String(r.name ?? "").trim();
      if (!name) continue;
      out.push({ name, description: String(r.description ?? "").replace(/[\r\n]+/g, " ").trim().slice(0, 300) });
    }
    return out;
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
  async huntResultsByArtifact(huntId: string, artifacts: string[], filters?: Record<string, string>): Promise<{ results: Record<string, unknown[]>; skipped: string[] }> {
    if (!HUNT_RE.test(huntId)) throw new Error("invalid hunt id");
    const results: Record<string, unknown[]> = {};
    const skipped: string[] = [];
    for (const artifact of artifacts ?? []) {
      const name = String(artifact ?? "").trim();
      if (!ARTIFACT_RE.test(name)) continue;   // skip invalid names rather than fail the whole collect
      try {
        const res = await this.huntResults(huntId, name, [], filters?.[name]);   // per-artifact WHERE filter
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
  };
}

// Construct a client when configured, else undefined (mirrors buildIrisClient()).
export function buildVelociraptorClient(env: NodeJS.ProcessEnv = process.env): VelociraptorClient | undefined {
  const config = loadVelociraptorConfig(env);
  return config ? new VelociraptorClient(config) : undefined;
}
