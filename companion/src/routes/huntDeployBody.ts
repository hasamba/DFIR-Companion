// The body of POST /cases/:id/velociraptor/deploy-hunt, parsed once (#157, #14, #803). Extracted from
// routes/velociraptor.ts, which sits at its file-size cap. Pure: no I/O, no request object.

import type { HuntCoverage, HuntOutcomeSource } from "../analysis/huntOutcomes.js";
import { vqlSizeProblem } from "../analysis/vqlInput.js";

export interface DeployHuntBody {
  vql: string;
  title: string;
  description: string;
  source: HuntOutcomeSource;
  mitreTechniques: string[];
  mode: "hunt" | "collection";
  hostname: string;
  relatedHypothesisId?: string;
  coverage?: HuntCoverage;
}

const ALLOWED_SOURCES: readonly HuntOutcomeSource[] = ["fleet", "playbook", "technique"]; // "bundle" is server-set, not client-supplied

const str = (v: unknown): string => (typeof v === "string" ? v.trim() : "");

// Same as routes/velociraptor.ts's module-private helper (itself a copy of createApp's): a comma
// list or an array becomes trimmed non-empty strings; anything else is [].
const toStringArray = (v: unknown): string[] => {
  if (typeof v === "string")
    return v
      .split(",")
      .map((x) => x.trim())
      .filter(Boolean);
  if (Array.isArray(v)) return v.map((x) => String(x).trim()).filter(Boolean);
  return [];
};

export function parseDeployHuntBody(raw: unknown): DeployHuntBody {
  const body = (raw ?? {}) as Record<string, unknown>;
  const vql = str(body.vql);
  const title = str(body.title);
  const description = str(body.description) ? String(body.description) : title;
  const rawSource = String(body.source ?? "");
  const source = ALLOWED_SOURCES.includes(rawSource as HuntOutcomeSource)
    ? (rawSource as HuntOutcomeSource)
    : "fleet";
  // #803: a hunt whose VQL reads live state (a compiled Sigma rule over pslist()/netstat()/glob())
  // says so with coverage "snapshot". Its empty result is not negative evidence, so it is never
  // linked to a hypothesis — an empty snapshot must not count toward exhausting one.
  const coverage: HuntCoverage | undefined = body.coverage === "snapshot" ? "snapshot" : undefined;
  // ACH hunt→hypothesis link (investigation-guidance #14): when the analyst deploys a hunt to TEST a
  // specific hypothesis, carry its id so an empty result counts as a MISS against that exact
  // hypothesis (→ eventual `exhausted`), not just a technique-overlap match.
  const relatedHypothesisId =
    !coverage && str(body.relatedHypothesisId) ? str(body.relatedHypothesisId) : undefined;
  return {
    vql,
    title,
    description,
    source,
    mitreTechniques: toStringArray(body.mitreTechniques),
    mode: body.mode === "collection" ? "collection" : "hunt",
    hostname: str(body.hostname),
    ...(relatedHypothesisId ? { relatedHypothesisId } : {}),
    ...(coverage ? { coverage } : {}),
  };
}

/**
 * The 400 this body earns, or null when it is usable.
 *
 * Lives here rather than in the route because routes/velociraptor.ts is at its file-size cap, and
 * because the size check belongs with the parse: deploy-hunt was the one VQL-carrying route that
 * never got `vqlSizeProblem` (#871), so an oversized program was packaged into a generated
 * artifact — embedded into the outer program, so duplicated several times over — and only failed
 * at the spawn, as an E2BIG the analyst could do nothing with.
 */
export function deployHuntBodyProblem(
  body: Pick<DeployHuntBody, "vql" | "title" | "mode" | "hostname">,
): string | null {
  if (!body.vql) return "vql is required";
  if (!body.title) return "title is required";
  if (body.mode === "collection" && !body.hostname) return "hostname is required for a collection";
  return vqlSizeProblem(body.vql);
}
