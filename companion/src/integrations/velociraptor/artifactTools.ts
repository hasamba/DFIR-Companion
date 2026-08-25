// The third-party binaries an artifact needs (THOR, Chainsaw, Hayabusa, …) and whether the SERVER can
// actually obtain them — the pre-flight that keeps one unconfigured tool from costing a whole hunt.
//
// Velociraptor resolves every artifact's tools while it compiles a hunt request, by fetching each
// tool's URL. A URL that is not a URL — the `todo.<tool>.download.url` placeholder the licensed-tool
// artifacts ship with — makes that fetch fail (`unsupported protocol scheme ""`) and `hunt()` then
// returns NULL for the ENTIRE request. The built-in "Best Practice" bundle contains one such artifact
// (Generic.Scanner.ThorZIP: THOR Lite is licensed, so it cannot ship a URL), which is why running that
// bundle against an untouched server collected nothing from any of its 45 artifacts.

import { isNoLaunchIdError } from "./vqlDiagnostics.js";

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

/** One tool the server has no file for yet, and the bundle artifacts that need it. */
export interface UnheldTool {
  tool: string;
  url: string; // where Velociraptor would fetch it from; "" when the tool has no URL at all
  artifacts: string[]; // every artifact in this run that declares it
}

// A hint is a banner, not a report: enough tools to recognise the problem, not the whole list.
const UNHELD_HINT_MAX = 6;
const listSome = (items: readonly string[]): string =>
  items.length > UNHELD_HINT_MAX
    ? `${items.slice(0, UNHELD_HINT_MAX).join(", ")} (+${items.length - UNHELD_HINT_MAX} more)`
    : items.join(", ");

/**
 * The tools this run needs that the server has NOT downloaded yet.
 *
 * artifactToolProblem answers a different, narrower question — "is this tool's URL a URL?" — and is
 * allowed to DROP an artifact on the answer. This one is the warning that check cannot give: a tool
 * with a perfectly valid GitHub URL that the server has never fetched looks healthy to every check we
 * had, and on a server without egress (an air-gapped lab, a proxy, a firewall) Velociraptor still fails
 * to fetch it while compiling the hunt — which loses the ENTIRE run, artifacts and all, and reports
 * only "no hunt id". We cannot know from here whether the server has egress. We CAN see what it holds.
 *
 * Nothing is dropped on this: on a server WITH egress these tools fetch on first use and the hunt is
 * fine, so acting on it would silently gut a sweep that would have worked. `inventory` must be the
 * server's REAL tool state — the declared metadata never carries a hash, so passing that would report
 * every tool in the bundle as missing.
 */
export function toolsNotHeldByServer(
  artifacts: readonly string[],
  definitions: readonly { name: string; tools?: VeloArtifactTool[] }[],
  inventory: Map<string, VeloArtifactTool>,
): UnheldTool[] {
  const byName = new Map(definitions.map((d) => [d.name, d]));
  const out = new Map<string, UnheldTool>();
  for (const artifact of artifacts) {
    for (const declared of byName.get(artifact)?.tools ?? []) {
      const t = inventory.get(declared.name) ?? declared;
      if (t.materialized) continue; // the server holds the file — nothing to fetch
      const entry = out.get(declared.name) ?? {
        tool: declared.name,
        url: (t.url ?? "").trim(),
        artifacts: [],
      };
      if (!entry.artifacts.includes(artifact)) entry.artifacts.push(artifact);
      out.set(declared.name, entry);
    }
  }
  return [...out.values()];
}

/**
 * The sentence to append to a launch failure, naming the tools that are the likeliest cause and what
 * to do about them. Empty when the server holds every tool the run needs — then the failure is
 * something else and this must not add noise to it.
 */
export function unheldToolsHint(unheld: readonly UnheldTool[]): string {
  if (!unheld.length) return "";
  const tools = listSome(unheld.map((u) => (u.url ? `${u.tool} (${u.url})` : `${u.tool} (no download URL)`)));
  const artifacts = listSome([...new Set(unheld.flatMap((u) => u.artifacts))]);
  return (
    ` This bundle also needs ${unheld.length} tool(s) this server has not downloaded yet, which is the` +
    " likeliest cause: Velociraptor fetches every tool while it compiles the hunt, so ONE it cannot" +
    ` reach aborts the whole run — ${tools}.` +
    ` Upload them in Velociraptor (Server Artifacts → Tools), or remove the artifact(s) that need them` +
    ` from the bundle: ${artifacts}.`
  );
}

/**
 * Launch, and when Velociraptor refuses with its bare NULL, say what the pre-flight already knows.
 *
 * `hunt()` answers a request it could not compile with no reason at all, so the generic message can
 * only guess. Where the pre-flight found tools this server has never fetched, they are the likeliest
 * cause on a server without egress — and the only thing the analyst can act on — so they are appended
 * to the failure rather than left in the server's own log. Every other failure is rethrown untouched.
 */
export async function launchWithUnheldToolHint<T>(
  unheld: readonly UnheldTool[],
  launch: () => Promise<T>,
): Promise<T> {
  try {
    return await launch();
  } catch (e) {
    const message = (e as Error).message;
    const hint = isNoLaunchIdError(message) ? unheldToolsHint(unheld) : "";
    throw hint ? new Error(message + hint) : e;
  }
}
