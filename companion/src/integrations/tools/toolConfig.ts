// Env-driven configuration for the analyst's external forensic tools. A tool is OFF until its
// `DFIR_TOOL_<ID>_BINARY` key is set (mirrors DFIR_VELOCIRAPTOR_API_CONFIG gating loadVelociraptorConfig).
// The Companion NEVER bundles or downloads a binary — TOOL_DEFS only links to each official repo; the
// analyst installs and updates the tool themselves. Config is read from process.env so a runtime
// `POST /tools/reconnect` (reloadEnvPrefix("DFIR_TOOL_")) applies saved settings without a restart.
//
// Each tool maps to a FIXED downstream importer kind (its `importKind`) — the tool's output flows into
// the same importer the analyst would use if they ran it by hand: Hayabusa→hayabusa, Chainsaw→chainsaw,
// Velociraptor CLI→velociraptor, Suricata→network, Snort→snort, YARA→yara. The Companion runs the tool
// and ingests its verdict; it does NOT re-implement detection (see CLAUDE.md).

export type ToolId =
  "hayabusa" | "chainsaw" | "velociraptor_cli" | "suricata" | "snort" | "yara" | "socrates";

// How the Companion reaches the tool. "spawn" runs a local binary through the toolRunner; "http"
// calls a service over the network and never touches the process spawner.
export type ToolTransport = "spawn" | "http";

// How the tool emits its result:
//  - "stdout": read the process stdout (YARA, Snort -A fast -q)
//  - "file":   `<output>` is the RESULT FILE path; read it back (Hayabusa -o, Velociraptor --output)
//  - "dir":    `<output>` is a DIRECTORY the tool writes into; read `<dir>/<outputFile>` (Suricata -l → eve.json)
export type OutputMode = "stdout" | "file" | "dir";

export interface ToolConfig {
  id: string; // built-in ToolId or a custom-tool id
  binary: string; // executable path / PATH name (gates on/off); "" for http tools
  transport: ToolTransport; // spawn a binary, or call an HTTP service
  baseUrl?: string; // http tools only — the service root, no trailing slash
  runArgs: string; // args template with <target>/<output>/<rules> placeholders
  updateCommand?: string; // FULL "update rules" command line (first token = executable); blank = no button
  importKind: string; // fixed downstream importer kind
  outputMode: OutputMode;
  outputFile?: string; // result filename for "file"/"dir" modes
  rulesPath?: string; // analyst's own rules for <rules> (Snort/YARA)
  definitions?: string; // extra artifact-definitions path for <definitions> (Velociraptor CLI)
  autoRun: boolean; // run automatically when a matching raw file lands in the drop folder
  timeoutMs: number;
  maxOutputBytes: number;
  // FAIL CLOSED (#688). A parser that stops halfway still writes the rows it managed to emit, and
  // importing those is worse than importing nothing: the case then holds a silently partial view of
  // the evidence with nothing saying so. For a parser whose exit code is meaningful (Hayabusa,
  // Chainsaw, the Velociraptor CLI) a non-zero exit therefore rejects the whole run. NOT set for
  // YARA/Snort, which exit non-zero as a normal way of saying "matches found". Default false.
  failOnNonZeroExit?: boolean;
  // FAIL CLOSED (#688). The tool's detections are only as identifiable as the rules behind them, so
  // a tool whose verdicts are meaningless without a named rule set refuses to run when the path is
  // missing, empty or unreadable — rather than reporting "no detections" over rules that were never
  // loaded. Default false (a rules path is still required to be SET when `<rules>` is templated).
  requireRuleset?: boolean;
  // How to ask this binary its version, for the run's custody record. Default ["--version"].
  versionArgs?: string[];
}

interface ToolDef {
  id: ToolId;
  label: string; // display name
  repoUrl: string; // official repo (linked in the UI, never bundled)
  importKind: string;
  transport: ToolTransport;
  defaultRunArgs: string;
  outputMode: OutputMode;
  defaultOutputFile?: string;
  usesRules: boolean; // Snort/YARA need a <rules> path
  extensions: string[]; // raw file extensions this tool claims (drop-folder routing)
  defaultUpdateSubcommand?: string; // args appended to `binary` for the update button (Hayabusa: update-rules)
  defaultUpdateCommand?: string; // standalone update command line (Suricata: suricata-update)
  strictExit?: boolean; // non-zero exit rejects the run (see ToolConfig.failOnNonZeroExit)
  strictRuleset?: boolean; // the rule set must resolve to real content (see ToolConfig.requireRuleset)
  versionArgs?: string[]; // how to ask the binary its version; default ["--version"]
}

// The extensions SO-CRATES claims. Explicit rather than a catch-all: SO-CRATES YARA-scans anything
// that is not a PCAP or a log, so claiming "*" would divert every CSV/JSON import away from the
// Companion's native importers. Extensionless and hash-named samples are covered by the
// looksBinary() content sniff in analysis/dropScan.ts instead.
export const SOCRATES_EXTS: string[] = [
  ".pcap",
  ".pcapng",
  ".cap",
  ".trace",
  ".evtx",
  ".evt",
  ".exe",
  ".dll",
  ".sys",
  ".drv",
  ".scr",
  ".com",
  ".cpl",
  ".ocx",
  ".msi",
  ".bin",
  ".elf",
  ".so",
  ".dylib",
  ".lnk",
  ".msp",
  ".cab",
  ".doc",
  ".docx",
  ".xls",
  ".xlsx",
  ".ppt",
  ".pptx",
  ".pdf",
  ".rtf",
  ".zip",
  ".7z",
  ".rar",
];

// Static per-tool definitions (NOT env). The importKind + outputMode + claimed extensions are fixed;
// env carries only the analyst's per-tool overrides (binary, args, rules, toggles).
export const TOOL_DEFS: Record<ToolId, ToolDef> = {
  hayabusa: {
    id: "hayabusa",
    label: "Hayabusa",
    repoUrl: "https://github.com/Yamato-Security/hayabusa",
    importKind: "hayabusa",
    transport: "spawn",
    defaultRunArgs: "csv-timeline -f <target> -o <output> -w",
    outputMode: "file",
    defaultOutputFile: "hayabusa.csv",
    usesRules: false,
    extensions: [".evtx", ".evt"],
    defaultUpdateSubcommand: "update-rules",
    strictExit: true,
  },
  // Chainsaw (WithSecure) — the second EVTX parser the Companion orchestrates (#688). Its importer
  // has existed since the beginning; only the RUNNER was missing, so an analyst holding a raw .evtx
  // had to run Chainsaw by hand and import the file. `hunt` takes a FOLDER, so it uses <targetdir>
  // (the same original-name staging the Velociraptor CLI uses) rather than <target>.
  //
  // Chainsaw needs two paths, and both are fail-closed: <rules> is the Sigma rule directory, and
  // <definitions> is the mapping file that tells Chainsaw how Sigma field names bind to EVTX fields
  // (sigma-event-logs-all.yml in the Chainsaw release). Without the mapping Chainsaw hunts with
  // nothing loaded and reports a clean run over evidence it never actually examined.
  //
  // No update command: Chainsaw has no update subcommand — its Sigma rules are a git checkout the
  // analyst refreshes themselves, so a blank command correctly hides the button.
  chainsaw: {
    id: "chainsaw",
    label: "Chainsaw",
    repoUrl: "https://github.com/WithSecureLabs/chainsaw",
    importKind: "chainsaw",
    transport: "spawn",
    defaultRunArgs: "hunt <targetdir> -s <rules> --mapping <definitions> --json --output <output>",
    outputMode: "file",
    defaultOutputFile: "chainsaw.json",
    usesRules: true,
    extensions: [".evtx", ".evt"],
    strictExit: true,
    strictRuleset: true,
  },
  velociraptor_cli: {
    id: "velociraptor_cli",
    label: "Velociraptor CLI (offline)",
    repoUrl: "https://github.com/Velocidex/velociraptor",
    importKind: "velociraptor",
    transport: "spawn",
    // Runs the Windows.Hayabusa.Rules artifact (NON-built-in → loaded from the definitions zip) against a
    // FOLDER of EVTX (--ROOT). `<targetdir>` is a folder holding the input file under its ORIGINAL name, so
    // Velociraptor detects the channel from the filename and globs it. `--nobanner --no-debug` keep the
    // output clean, and `> <output>` redirects the JSON result rows to a file the Companion then imports
    // (handled natively — no shell). NOTE: no `-v` (verbose logs would pollute the results).
    defaultRunArgs:
      "--definitions <definitions> -r Windows.Hayabusa.Rules --ROOT <targetdir> --nobanner --no-debug > <output>",
    outputMode: "stdout",
    defaultOutputFile: "output.json",
    usesRules: false,
    extensions: [".evtx", ".evt"],
    strictExit: true,
    versionArgs: ["version"],
  },
  suricata: {
    id: "suricata",
    label: "Suricata",
    repoUrl: "https://suricata.io/download/",
    importKind: "network",
    transport: "spawn",
    defaultRunArgs: "-r <target> -l <output>",
    outputMode: "dir",
    defaultOutputFile: "eve.json",
    usesRules: false,
    extensions: [".pcap", ".pcapng"],
    versionArgs: ["-V"],
    // No default update command: `suricata-update` is a Linux/pip tool that isn't present on a stock
    // Windows install. On Windows, download the ET Open ruleset (emerging-all.rules) manually and point
    // suricata.yaml at it — the dashboard links the ruleset + a setup guide. A user who has
    // suricata-update installed can set it as the update command.
  },
  snort: {
    id: "snort",
    label: "Snort",
    repoUrl: "https://github.com/snort3/snort3",
    importKind: "snort",
    transport: "spawn",
    defaultRunArgs: "-r <target> -c <rules> -A fast -q",
    outputMode: "stdout",
    usesRules: true,
    extensions: [".pcap", ".pcapng"],
    versionArgs: ["-V"],
  },
  yara: {
    id: "yara",
    label: "YARA",
    repoUrl: "https://github.com/VirusTotal/yara",
    importKind: "yara",
    transport: "spawn",
    defaultRunArgs: "-s -m -r <rules> <target>",
    outputMode: "stdout",
    usesRules: true,
    extensions: [], // YARA scans files/dirs on demand — not a raw drop-folder extension
  },
  socrates: {
    id: "socrates",
    label: "SO-CRATES",
    repoUrl: "https://github.com/dougburks/so-crates",
    importKind: "socrates",
    transport: "http",
    // Not a spawned command — the client in integrations/socrates drives the HTTP API instead.
    defaultRunArgs: "",
    outputMode: "stdout",
    usesRules: false,
    extensions: SOCRATES_EXTS,
  },
};

// Uppercase env id per tool (DFIR_TOOL_<ENV>_*).
const ENV_ID: Record<ToolId, string> = {
  hayabusa: "HAYABUSA",
  chainsaw: "CHAINSAW",
  velociraptor_cli: "VELOCIRAPTOR_CLI",
  suricata: "SURICATA",
  snort: "SNORT",
  yara: "YARA",
  socrates: "SOCRATES",
};

function boolEnv(v: string | undefined, dflt: boolean): boolean {
  const s = v?.trim().toLowerCase();
  if (s === undefined || s === "") return dflt;
  return s !== "false" && s !== "0" && s !== "no" && s !== "off";
}

function quoteIfNeeded(s: string): string {
  return /\s/.test(s) ? `"${s}"` : s;
}

// Build a tool's config from env, or null when its BINARY key is unset (tool disabled).
export function loadToolConfig(id: ToolId, env: NodeJS.ProcessEnv = process.env): ToolConfig | null {
  const def = TOOL_DEFS[id];
  const p = `DFIR_TOOL_${ENV_ID[id]}_`;

  // Auto-run is doubly gated: a master kill-switch (default on) AND the per-tool toggle (default OFF —
  // opt-in). Default off so a dropped/imported raw file ASKS the analyst first (a confirmation banner)
  // instead of silently spawning a tool; set _AUTO_RUN=on per tool for hands-off running.
  const masterAuto = boolEnv(env.DFIR_TOOL_AUTO_RUN, true);
  const toolAuto = boolEnv(env[`${p}AUTO_RUN`], false);

  // HTTP tools are gated on a base URL, not an executable path.
  if (def.transport === "http") {
    const baseUrl = env[`${p}URL`]?.trim();
    if (!baseUrl) return null;
    return {
      id,
      binary: "",
      transport: "http",
      baseUrl: baseUrl.replace(/\/+$/, ""),
      runArgs: "",
      importKind: def.importKind,
      outputMode: def.outputMode,
      autoRun: masterAuto && toolAuto,
      timeoutMs: Number(env[`${p}TIMEOUT_MS`]) || 1_200_000, // 20 min: Suricata over a large PCAP
      maxOutputBytes: Number(env[`${p}MAX_OUTPUT`]) || 100 * 1024 * 1024,
      versionArgs: def.versionArgs ?? ["--version"],
    };
  }

  const binary = env[`${p}BINARY`]?.trim();
  if (!binary) return null;

  const envUpdate = env[`${p}UPDATE_CMD`]?.trim();
  const updateCommand = envUpdate
    ? envUpdate
    : def.defaultUpdateCommand
      ? def.defaultUpdateCommand
      : def.defaultUpdateSubcommand
        ? `${quoteIfNeeded(binary)} ${def.defaultUpdateSubcommand}`
        : undefined;

  return {
    id,
    binary,
    transport: "spawn",
    runArgs: env[`${p}RUN_ARGS`]?.trim() || def.defaultRunArgs,
    updateCommand,
    importKind: def.importKind,
    outputMode: def.outputMode,
    outputFile: env[`${p}OUTPUT_FILE`]?.trim() || def.defaultOutputFile,
    rulesPath: env[`${p}RULES`]?.trim() || undefined,
    definitions: env[`${p}DEFINITIONS`]?.trim() || undefined,
    autoRun: masterAuto && toolAuto,
    timeoutMs: Number(env[`${p}TIMEOUT_MS`]) || 300_000,
    maxOutputBytes: Number(env[`${p}MAX_OUTPUT`]) || 100 * 1024 * 1024,
    failOnNonZeroExit: def.strictExit === true,
    requireRuleset: def.strictRuleset === true,
    versionArgs: def.versionArgs ?? ["--version"],
  };
}

// All configured tools (binary set), keyed by id.
export function loadAllToolConfigs(env: NodeJS.ProcessEnv = process.env): Map<ToolId, ToolConfig> {
  const out = new Map<ToolId, ToolConfig>();
  for (const id of Object.keys(TOOL_DEFS) as ToolId[]) {
    const cfg = loadToolConfig(id, env);
    if (cfg) out.set(id, cfg);
  }
  return out;
}

// Static preference when several tools could claim a raw extension (evtx→Hayabusa then Velociraptor CLI;
// pcap→Suricata then Snort). Derived from TOOL_DEFS so it stays in sync.
export function toolPreferenceForExtension(ext: string): ToolId[] {
  const e = ext.toLowerCase();
  // Order matters: the first CONFIGURED tool wins for drop-folder auto-run. SO-CRATES is last so a
  // tuned local Suricata/Hayabusa keeps priority; the import banner offers every claimant instead.
  const order: ToolId[] = [
    "hayabusa",
    "chainsaw",
    "velociraptor_cli",
    "suricata",
    "snort",
    "yara",
    "socrates",
  ];
  return order.filter((id) => TOOL_DEFS[id].extensions.includes(e));
}

// The configured tool that should handle a raw extension, honoring the static preference. Null when the
// extension isn't a raw-tool input or no claiming tool is configured.
export function toolForExtension(ext: string, configured: Map<string, ToolConfig>): ToolId | null {
  for (const id of toolPreferenceForExtension(ext)) if (configured.has(id)) return id;
  return null;
}

// The default tool to SUGGEST for a raw extension even when none is configured (for the "Configure X"
// banner). Null when the extension isn't a raw-tool input.
export function suggestedToolForExtension(ext: string): ToolId | null {
  return toolPreferenceForExtension(ext)[0] ?? null;
}
