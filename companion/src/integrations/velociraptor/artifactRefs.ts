// How a Velociraptor artifact's RESULTS are addressed, and the multi-source case that silently lost
// evidence. A single-source artifact is read by bare name; an artifact with NAMED sources stores its
// rows ONLY under `Artifact/Source`, and a bare-name read of one returns zero rows and NO error.
//
// Both import paths got that wrong, in opposite directions, and a hunt's whole THOR scan
// (Generic.Scanner.ThorZIP → ThorExec / ThorResultsJson) never reached the case:
//
//   • Importing the COLLECTION dropped it outright. `flows().artifacts_with_results` reports a
//     multi-source artifact one source at a time, in the qualified form — so the server itself
//     returned "Generic.Scanner.ThorZIP/ThorResultsJson", and the reader rejected the slash as an
//     invalid artifact name. The import still reported success; only a per-artifact log line said
//     otherwise, while the collection's 17 single-source artifacts imported normally.
//   • Collecting the HUNT failed more quietly still: the hunt asks for the artifact NAMES it
//     launched, the bare-name read came back empty, and an empty read is not an error — so the
//     artifact was recorded as having found nothing on every host.
//
// Split out of velociraptorApi.ts (its own file-size ledger entry forbids growing it) and shaped so
// both fixes live beside the explanation rather than in two distant call sites.
import type { VelociraptorRunResult } from "./velociraptorApi.js";

/** A bare ARTIFACT name — a dotted identifier. Every one of the 402 shipped artifacts fits this. */
export const ARTIFACT_RE = /^[A-Za-z0-9._]+$/;

// What a single-quoted VQL string literal cannot carry: the quote that would close it early, the
// backslash that could escape that quote, and control characters that would break the query's shape.
const UNSAFE_IN_VQL_LITERAL = /['\\\u0000-\u001f\u007f]/;

/**
 * Is this a usable SOURCE name?
 *
 * A source name is free-form YAML prose, NOT an identifier: "Recent Entries", "Yara Disk",
 * "Microsoft-Windows-Hyper-V-VMMS-Admin" and "Login/Logout Hooks" are all real. Judging them by
 * ARTIFACT_RE rejected 40 of the 180 source names in the shipped artifact set — every one of those
 * sources went unread, silently, the same way THOR did.
 *
 * So this is a DENY-list of what the VQL literal cannot hold, not an allow-list of the punctuation
 * today's names happen to use — otherwise the next artifact to use a bracket or a comma reopens the
 * same bug. A `..` segment is refused as well: nothing is legitimately named that, and it keeps a ref
 * from carrying a traversal segment to any consumer that treats it as a path.
 */
export function isSafeSourceName(name: string): boolean {
  if (!name || UNSAFE_IN_VQL_LITERAL.test(name)) return false;
  return !name.split("/").includes("..");
}

/**
 * A result ADDRESS: a bare artifact name, or the `Artifact/Source` form naming ONE named source.
 * Velociraptor hands back the qualified form itself, so every reader that takes a name straight from
 * the server must accept it. Split on the FIRST slash only — the artifact half is an identifier, so
 * any slash after it belongs to the source name.
 */
export function isArtifactRef(ref: string): boolean {
  const slash = ref.indexOf("/");
  if (slash < 0) return ARTIFACT_RE.test(ref);
  return ARTIFACT_RE.test(ref.slice(0, slash)) && isSafeSourceName(ref.slice(slash + 1));
}

/**
 * The `artifact=` addresses to read, given a caller's name and its `sources` list.
 *
 * The name may ALREADY carry its source, so the two inputs can describe the same thing twice —
 * appending regardless would build a nonsense "Artifact/Source/Source" that matches nothing. An
 * already-qualified name wins: it names the exact source the server said has results.
 * Throws on a malformed name so a bad ref can never reach the VQL literal.
 */
export function artifactRefs(artifact: string, sources: string[]): string[] {
  if (!isArtifactRef(artifact)) throw new Error("invalid artifact name");
  if (artifact.includes("/")) return [artifact];
  const safe = sources.filter(isSafeSourceName);
  return safe.length ? safe.map((s) => `${artifact}/${s}`) : [artifact];
}

/**
 * Read one hunt artifact's rows, COMPLETE across its sources: the bare-name read (the default,
 * unnamed source) MERGED with a read of every named source the server catalog reports.
 *
 * Both halves are needed, because the three source layouts fail differently and an artifact can only
 * be told apart by asking the catalog:
 *
 *   - no named sources (most artifacts) — the bare read is everything; the merge never runs.
 *   - only named sources (Generic.Scanner.ThorZIP) — the bare read is EMPTY and silent, which is how
 *     a whole THOR scan was reported as a clean host.
 *   - unnamed AND named (DetectRaptor.Windows.Registry.NetworkProvider, and dozens more in the
 *     shipped bundle) — the bare read returns the default source's rows and looks like a success,
 *     so retrying only on an empty result would still lose every named source.
 *
 * A caller who passed sources, or an already-qualified `Artifact/Source` ref, has said exactly what
 * it wants and is left alone. A catalog failure degrades to the bare read rather than failing the
 * collect. Rows are de-duplicated on merge: whether a single-source artifact answers to BOTH its
 * bare name and its source name is a Velociraptor storage detail, and double-counting evidence is
 * worse than the cost of the check.
 */
export async function readHuntArtifactRows(
  read: (artifact: string, sources: string[]) => Promise<VelociraptorRunResult>,
  catalog: () => Promise<{ name: string; sources?: string[] }[]>,
  artifact: string,
  sources: string[] = [],
): Promise<VelociraptorRunResult> {
  if (sources.length || artifact.includes("/")) return read(artifact, sources);
  const base = await read(artifact, []);
  let named: string[] = [];
  try {
    named = (await catalog()).find((a) => a.name === artifact)?.sources ?? [];
  } catch {
    return base; // catalog unreachable — report the bare read, don't fail the collect
  }
  return named.length ? mergeRuns(base, await read(artifact, named)) : base;
}

/** Concatenate two reads of the same artifact, dropping rows the second repeats from the first. */
function mergeRuns(a: VelociraptorRunResult, b: VelociraptorRunResult): VelociraptorRunResult {
  if (!a.rows.length) return b;
  if (!b.rows.length) return a;
  const seen = new Set(a.rows.map((r) => JSON.stringify(r)));
  const fresh = b.rows.filter((r) => !seen.has(JSON.stringify(r)));
  return {
    rows: a.rows.concat(fresh),
    // Exact whenever neither read was capped; an estimate once one was, which is what `total` already
    // means for a capped read.
    total: a.total + b.total - (b.rows.length - fresh.length),
    truncated: a.truncated || b.truncated,
  };
}
