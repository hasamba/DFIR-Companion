// What `artifact_definitions()` reports about one artifact, and how the Companion parses it.
//
// Every parser here is TOLERANT by the same rule: an unexpected shape degrades to empty rather than
// throwing. Velociraptor's own casing and column shapes drift across versions, and none of this is
// evidence — it drives a picker, a time-scope guess and a fallback read. A server that reports
// metadata oddly must still collect normally.
//
// Split out of velociraptorApi.ts, whose file-size ledger entry freezes it (#384). Re-exported from
// there so existing importers are unaffected.
import type { VeloArtifactTool } from "./artifactTools.js";
import { isSafeSourceName } from "./artifactRefs.js";

// One parameter an artifact accepts, as reported by artifact_definitions(). `type` is lowercased
// ("timestamp", "string", "bool", …) because Velociraptor's casing varies across versions — the same
// reason listClientArtifacts normalizes the artifact `type` in TypeScript rather than in VQL.
export interface VeloArtifactParam {
  name: string;
  type?: string; // omitted (never "") when the server reports no type for this parameter
}

// One collectable CLIENT artifact definition on the server (for the bundle builder's picker).
export interface VeloArtifactInfo {
  name: string; // e.g. "Windows.System.Pslist"
  description: string; // one-line summary
  parameters: VeloArtifactParam[]; // [] when the server reports none (older versions / odd shapes)
  tools?: VeloArtifactTool[]; // omitted when the artifact needs none (most of them)
  // The artifact's NAMED sources, when it has any (see artifactRefs.ts for why they matter). Omitted,
  // not [], when every source is unnamed.
  sources?: string[];
  // Set when the definition does not say which named sources it has: the `sources` column is missing
  // or not a list, or a named source was dropped as unusable. Its absent `sources` then proves nothing,
  // so a hunt read of it is "not read", never "empty" (#1635).
  sourcesUnknown?: true;
}

// Tolerant parse of a definition's `parameters` column: anything that isn't an array of named objects
// degrades to []. Never throws — a server that reports parameters in an unexpected shape must not break
// the artifact picker, it just means time-scope auto-detection falls back to the shipped table.
export function parseArtifactParams(raw: unknown): VeloArtifactParam[] {
  if (!Array.isArray(raw)) return [];
  const out: VeloArtifactParam[] = [];
  for (const p of raw) {
    if (!p || typeof p !== "object") continue;
    const r = p as { name?: unknown; type?: unknown };
    const name = String(r.name ?? "").trim();
    if (!name) continue;
    const type = String(r.type ?? "")
      .trim()
      .toLowerCase();
    out.push(type ? { name, type } : { name });
  }
  return out;
}

// A definition's `sources` column as catalog fields: the named sources, plus `sourcesUnknown` when the
// column cannot prove the list complete (#1635). Every artifact has at least one source, so a missing
// or non-list column is version skew or a bad row, not "single-source". An element that is not an
// object, or a named source the parser drops as unsafe, leaves the list incomplete too.
export function catalogSources(raw: unknown): Pick<VeloArtifactInfo, "sources" | "sourcesUnknown"> {
  const sources = parseArtifactSources(raw);
  const incomplete =
    !Array.isArray(raw) ||
    raw.some((s) => {
      if (!s || typeof s !== "object") return true;
      const name = String((s as { name?: unknown }).name ?? "").trim();
      return !!name && !isSafeSourceName(name);
    });
  return { ...(sources.length ? { sources } : {}), ...(incomplete ? { sourcesUnknown: true } : {}) };
}

// Tolerant parse of a definition's `sources` column into its NAMED source names. Unnamed sources (the
// single-source majority) contribute nothing: they ARE the bare artifact name. The names are checked
// HERE rather than at the call site, so an unusable one can never reach a VQL literal and "this
// artifact has named sources" stays honest instead of yielding a ref that cannot run.
export function parseArtifactSources(raw: unknown): string[] {
  if (!Array.isArray(raw)) return [];
  const out: string[] = [];
  for (const s of raw) {
    if (!s || typeof s !== "object") continue;
    const name = String((s as { name?: unknown }).name ?? "").trim();
    if (isSafeSourceName(name) && !out.includes(name)) out.push(name);
  }
  return out;
}
