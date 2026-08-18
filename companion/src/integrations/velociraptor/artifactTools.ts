// The third-party binaries an artifact needs (THOR, Chainsaw, Hayabusa, …) and whether the SERVER can
// actually obtain them — the pre-flight that keeps one unconfigured tool from costing a whole hunt.
//
// Velociraptor resolves every artifact's tools while it compiles a hunt request, by fetching each
// tool's URL. A URL that is not a URL — the `todo.<tool>.download.url` placeholder the licensed-tool
// artifacts ship with — makes that fetch fail (`unsupported protocol scheme ""`) and `hunt()` then
// returns NULL for the ENTIRE request. The built-in "Best Practice" bundle contains one such artifact
// (Generic.Scanner.ThorZIP: THOR Lite is licensed, so it cannot ship a URL), which is why running that
// bundle against an untouched server collected nothing from any of its 45 artifacts.

/** One tool an artifact needs, as `artifact_definitions()` reports it. */
export interface VeloArtifactTool {
  name: string;
  url?: string; // the configured download URL; omitted when the server reports none
  materialized?: boolean; // the server already holds the file (hash / filestore path / serve url set)
}

/**
 * Tolerant parse of a definition's `tools` column. Same contract as parseArtifactParams: anything the
 * server didn't promise degrades to [], never throws — tool metadata must not break the artifact picker.
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
    // "The server already has the file", however it got there: an uploaded or served tool keeps
    // whatever url it was defined with, so without this an uploaded THOR would look broken forever.
    const materialized = Boolean(
      String(r.hash ?? "").trim() ||
      String(r.filestore_path ?? "").trim() ||
      String(r.serve_url ?? "").trim() ||
      (Array.isArray(r.serve_urls) && r.serve_urls.length),
    );
    out.push({ name, ...(url ? { url } : {}), ...(materialized ? { materialized: true } : {}) });
  }
  return out;
}

/**
 * Why this artifact would abort a hunt, or undefined when it is safe to collect.
 *
 * Deliberately narrow, because dropping an artifact from a run is destructive. An EMPTY url is NOT a
 * problem (a healthy server has many such tools — unused, or materialized another way — and hunts that
 * use them compile fine), and neither is a tool the server already holds.
 */
export function artifactToolProblem(a: { tools?: VeloArtifactTool[] }): string | undefined {
  for (const t of a.tools ?? []) {
    const url = (t.url ?? "").trim();
    if (!url || t.materialized) continue;
    if (/^https?:\/\//i.test(url)) continue;
    return `tool "${t.name}" has no valid download URL ("${url}") — upload the file or set its URL in Velociraptor (Server Artifacts → Tools)`;
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
 */
export function partitionByToolAvailability(
  artifacts: readonly string[],
  definitions: readonly { name: string; tools?: VeloArtifactTool[] }[],
): { runnable: string[]; unavailable: UnavailableArtifact[] } {
  const byName = new Map(definitions.map((d) => [d.name, d]));
  const runnable: string[] = [];
  const unavailable: UnavailableArtifact[] = [];
  for (const artifact of artifacts) {
    const def = byName.get(artifact);
    const reason = def ? artifactToolProblem(def) : undefined;
    if (reason) unavailable.push({ artifact, reason });
    else runnable.push(artifact);
  }
  return { runnable, unavailable };
}
