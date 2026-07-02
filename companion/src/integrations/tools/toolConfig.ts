// Env-driven configuration for the analyst's external forensic tools. A tool is OFF until its
// `DFIR_TOOL_<ID>_BINARY` key is set (mirrors DFIR_VELOCIRAPTOR_API_CONFIG gating loadVelociraptorConfig).
// The Companion NEVER bundles or downloads a binary — TOOL_DEFS only links to each official repo; the
// analyst installs and updates the tool themselves. Config is read from process.env so a runtime
// `POST /tools/reconnect` (reloadEnvPrefix("DFIR_TOOL_")) applies saved settings without a restart.
//
// Each tool maps to a FIXED downstream importer kind (its `importKind`) — the tool's output flows into
// the same importer the analyst would use if they ran it by hand: Hayabusa→hayabusa, Velociraptor
// CLI→velociraptor, Suricata→network, Snort→snort, YARA→yara. The Companion runs the tool and ingests
// its verdict; it does NOT re-implement detection (see CLAUDE.md).

export type ToolId = "hayabusa" | "velociraptor_cli" | "suricata" | "snort" | "yara";

// How the tool emits its result:
//  - "stdout": read the process stdout (YARA, Snort -A fast -q)
//  - "file":   `<output>` is the RESULT FILE path; read it back (Hayabusa -o, Velociraptor --output)
//  - "dir":    `<output>` is a DIRECTORY the tool writes into; read `<dir>/<outputFile>` (Suricata -l → eve.json)
export type OutputMode = "stdout" | "file" | "dir";

export interface ToolConfig {
  id: string;                 // built-in ToolId or a custom-tool id
  binary: string;             // executable path / PATH name (gates on/off)
  runArgs: string;            // args template with <target>/<output>/<rules> placeholders
  updateCommand?: string;     // FULL "update rules" command line (first token = executable); blank = no button
  importKind: string;         // fixed downstream importer kind
  outputMode: OutputMode;
  outputFile?: string;        // result filename for "file"/"dir" modes
  rulesPath?: string;         // analyst's own rules for <rules> (Snort/YARA)
  definitions?: string;       // extra artifact-definitions path for <definitions> (Velociraptor CLI)
  autoRun: boolean;           // run automatically when a matching raw file lands in the drop folder
  timeoutMs: number;
  maxOutputBytes: number;
}

interface ToolDef {
  id: ToolId;
  label: string;                    // display name
  repoUrl: string;                  // official repo (linked in the UI, never bundled)
  importKind: string;
  defaultRunArgs: string;
  outputMode: OutputMode;
  defaultOutputFile?: string;
  usesRules: boolean;               // Snort/YARA need a <rules> path
  extensions: string[];             // raw file extensions this tool claims (drop-folder routing)
  defaultUpdateSubcommand?: string; // args appended to `binary` for the update button (Hayabusa: update-rules)
  defaultUpdateCommand?: string;    // standalone update command line (Suricata: suricata-update)
}

// Static per-tool definitions (NOT env). The importKind + outputMode + claimed extensions are fixed;
// env carries only the analyst's per-tool overrides (binary, args, rules, toggles).
export const TOOL_DEFS: Record<ToolId, ToolDef> = {
  hayabusa: {
    id: "hayabusa",
    label: "Hayabusa",
    repoUrl: "https://github.com/Yamato-Security/hayabusa",
    importKind: "hayabusa",
    defaultRunArgs: "csv-timeline -f <target> -o <output> -w",
    outputMode: "file",
    defaultOutputFile: "hayabusa.csv",
    usesRules: false,
    extensions: [".evtx", ".evt"],
    defaultUpdateSubcommand: "update-rules",
  },
  velociraptor_cli: {
    id: "velociraptor_cli",
    label: "Velociraptor CLI (offline)",
    repoUrl: "https://github.com/Velocidex/velociraptor",
    importKind: "velociraptor",
    // Runs the Windows.Hayabusa.Rules artifact (NON-built-in → loaded from the definitions zip) against a
    // FOLDER of EVTX (--ROOT). `<targetdir>` is a folder holding the input file under its ORIGINAL name, so
    // Velociraptor detects the channel from the filename and globs it. `--nobanner --no-debug` keep the
    // output clean, and `> <output>` redirects the JSON result rows to a file the Companion then imports
    // (handled natively — no shell). NOTE: no `-v` (verbose logs would pollute the results).
    defaultRunArgs: "--definitions <definitions> -r Windows.Hayabusa.Rules --ROOT <targetdir> --nobanner --no-debug > <output>",
    outputMode: "stdout",
    defaultOutputFile: "output.json",
    usesRules: false,
    extensions: [".evtx", ".evt"],
  },
  suricata: {
    id: "suricata",
    label: "Suricata",
    repoUrl: "https://suricata.io/download/",
    importKind: "network",
    defaultRunArgs: "-r <target> -l <output>",
    outputMode: "dir",
    defaultOutputFile: "eve.json",
    usesRules: false,
    extensions: [".pcap", ".pcapng"],
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
    defaultRunArgs: "-r <target> -c <rules> -A fast -q",
    outputMode: "stdout",
    usesRules: true,
    extensions: [".pcap", ".pcapng"],
  },
  yara: {
    id: "yara",
    label: "YARA",
    repoUrl: "https://github.com/VirusTotal/yara",
    importKind: "yara",
    defaultRunArgs: "-s -m -r <rules> <target>",
    outputMode: "stdout",
    usesRules: true,
    extensions: [],   // YARA scans files/dirs on demand — not a raw drop-folder extension
  },
};

// Uppercase env id per tool (DFIR_TOOL_<ENV>_*).
const ENV_ID: Record<ToolId, string> = {
  hayabusa: "HAYABUSA",
  velociraptor_cli: "VELOCIRAPTOR_CLI",
  suricata: "SURICATA",
  snort: "SNORT",
  yara: "YARA",
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
  const binary = env[`${p}BINARY`]?.trim();
  if (!binary) return null;

  // Auto-run is doubly gated: a master kill-switch (default on) AND the per-tool toggle (default OFF —
  // opt-in). Default off so a dropped/imported raw file ASKS the analyst first (a confirmation banner)
  // instead of silently spawning a tool; set _AUTO_RUN=on per tool for hands-off running.
  const masterAuto = boolEnv(env.DFIR_TOOL_AUTO_RUN, true);
  const toolAuto = boolEnv(env[`${p}AUTO_RUN`], false);

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
  const order: ToolId[] = ["hayabusa", "velociraptor_cli", "suricata", "snort", "yara"];
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
