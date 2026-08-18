// The third-party binaries an artifact needs (THOR, Chainsaw, Hayabusa, …) and whether the SERVER can
// actually obtain them — the pre-flight that keeps one unconfigured tool from costing a whole hunt.
//
// Velociraptor resolves every artifact's tools while it compiles a hunt request, by fetching each
// tool's URL. A URL that is not a URL — the `todo.<tool>.download.url` placeholder the licensed-tool
// artifacts ship with — makes that fetch fail (`unsupported protocol scheme ""`) and `hunt()` then
// returns NULL for the ENTIRE request. The built-in "Best Practice" bundle contains one such artifact
// (Generic.Scanner.ThorZIP: THOR Lite is licensed, so it cannot ship a URL), which is why running that
// bundle against an untouched server collected nothing from any of its 45 artifacts.

/** One tool, as `artifact_definitions().tools` and `inventory()` both report it. */
export interface VeloArtifactTool {
  name: string;
  url?: string; // the configured download URL; omitted when the server reports none
  materialized?: boolean; // the server holds the file itself (it recorded a hash for it)
}

/**
 * Tolerant parse of a `tools` column or an `inventory()` result — the two share their field names.
 * Same contract as parseArtifactParams: anything the server didn't promise degrades to [], never
 * throws — tool metadata must not break the artifact picker.
 *
 * `hash` is the ONLY field that evidences a file the server actually HOLDS. `filestore_path`,
 * `serve_url` and `serve_urls` are DERIVED: measured on a live 0.77.2 server, all 85 inventory rows
 * carried a filestore_path — including the unconfigured ThorZIP whose fetch then failed the hunt — so
 * reading them as "materialized" would wave through the very tool this check exists to catch.
 */
export function parseArtifactTools(raw: unknown): VeloArtifactTool[] {
  if (!Array.isArray(raw)) return [];
  const out: VeloArtifactTool[] = [];
  for (const t of raw) {
    if (!t || typeof t !== "object") continue;
    const r = t as Record<string, unknown>;
    const name = String(r.name ?? r.Name ?? "").trim();
    if (!name) continue;
    const url = String(r.url ?? r.Url ?? "").trim();
    const materialized = Boolean(String(r.hash ?? r.Hash ?? "").trim());
    out.push({ name, ...(url ? { url } : {}), ...(materialized ? { materialized: true } : {}) });
  }
  return out;
}

/**
 * The server's TOOL INVENTORY, keyed by tool name — the authority on what a tool's URL currently is,
 * and on whether the server holds the file.
 *
 * `artifact_definitions().tools` can answer neither: it echoes the artifact's YAML, so an analyst who
 * uploads THOR or fixes its URL under Server Artifacts → Tools changes nothing there. Measured on a
 * live 0.77.2 server: of the 95 tool entries the definitions reported, ZERO carried a hash, filename or
 * filestore path, while `inventory()` carried a hash for 9 tools and a filename for 69. Judging
 * availability from the definitions alone would go on dropping an artifact whose tool the analyst had
 * already configured — and would reject a THOR-only bundle outright.
 */
export function parseToolInventory(rows: unknown): Map<string, VeloArtifactTool> {
  return new Map(parseArtifactTools(rows).map((t) => [t.name, t]));
}

/**
 * Why this artifact would abort a hunt, or undefined when it is safe to collect.
 *
 * Deliberately narrow, because dropping an artifact from a run is destructive. An EMPTY url is NOT a
 * problem (a healthy server has many such tools — unused, or materialized another way — and hunts that
 * use them compile fine), and neither is a tool the server already holds.
 */
export function artifactToolProblem(
  a: { tools?: VeloArtifactTool[] },
  inventory?: Map<string, VeloArtifactTool>,
): string | undefined {
  for (const declared of a.tools ?? []) {
    // The inventory row wins wherever there is one — it carries the analyst's overrides and the file
    // the server holds. The declared entry is the fallback for a tool the inventory doesn't list.
    const t = inventory?.get(declared.name) ?? declared;
    const url = (t.url ?? "").trim();
    if (!url || t.materialized) continue;
    if (/^https?:\/\//i.test(url)) continue;
    return `tool "${declared.name}" has no valid download URL ("${url}") — upload the file or set its URL in Velociraptor (Server Artifacts → Tools)`;
  }
  return undefined;
}

/** One artifact a run must skip, and the sentence that explains it. */
export interface UnavailableArtifact {
  artifact: string;
  reason: string;
}

/**
 * Split the artifacts a bundle wants into the ones the server can collect and the ones whose tools it
 * cannot fetch. An artifact missing from `definitions` is left in `runnable`: only the catalog
 * pre-flight decides what exists, and this one must not silently duplicate that judgement.
 *
 * `inventory` is the server's tool state (parseToolInventory). Omit it only when that read FAILED: the
 * check then falls back to what each artifact declares, which still catches a placeholder URL but
 * cannot see a tool the analyst has since uploaded or re-pointed.
 */
export function partitionByToolAvailability(
  artifacts: readonly string[],
  definitions: readonly { name: string; tools?: VeloArtifactTool[] }[],
  inventory?: Map<string, VeloArtifactTool>,
): { runnable: string[]; unavailable: UnavailableArtifact[] } {
  const byName = new Map(definitions.map((d) => [d.name, d]));
  const runnable: string[] = [];
  const unavailable: UnavailableArtifact[] = [];
  for (const artifact of artifacts) {
    const def = byName.get(artifact);
    const reason = def ? artifactToolProblem(def, inventory) : undefined;
    if (reason) unavailable.push({ artifact, reason });
    else runnable.push(artifact);
  }
  return { runnable, unavailable };
}
