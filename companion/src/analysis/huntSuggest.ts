import { z } from "zod";
import type { Finding, IOC, InvestigationState, Severity } from "./stateTypes.js";

// AI-generated Velociraptor VQL fleet-hunts from the case findings (issue #57). The Companion
// already lets the analyst COLLECT artifacts and run per-entity hunt templates; this is the
// "so what next" step: read the synthesized findings / ATT&CK techniques / pivotable IOCs and
// propose PROACTIVE hunts — VQL queries that run across EVERY enrolled endpoint to find the same
// tradecraft (webshell signatures, persistence, a malicious process) on hosts not yet in scope.
//
// The AI call lives in the pipeline (`suggestHunts`); this module holds the PURE, unit-tested
// pieces: the response schema (lenient `.catch` like responseSchema.ts so a slightly-off model
// reply still parses), the digest renderers that feed the model, and the sanitizer that drops
// useless suggestions and clamps field lengths before they reach the analyst / Velociraptor.
//
// Suggestions are EPHEMERAL (generated on demand, shown for review, deployed by the analyst) —
// like `ask`/`executiveSummary` they do not mutate InvestigationState. Deploy reuses the existing
// `launchHunt` flow (POST /velociraptor/hunt), so the analyst always sees the VQL + rationale
// before anything runs on their estate.

const severityEnum = z.enum(["Critical", "High", "Medium", "Low", "Info"]);

// One proposed fleet-hunt. Every field is lenient so one off value never rejects the whole reply.
export const huntSuggestionSchema = z.object({
  title: z.string().catch(""),               // short hunt name, e.g. "Hunt for ASPX webshells in web roots"
  rationale: z.string().catch(""),           // why: which finding triggered it + what the query looks for + how to triage hits
  vql: z.string().catch(""),                 // a single CLIENT-side Velociraptor VQL statement, run on each endpoint
  severity: severityEnum.catch("Medium"),    // priority of the underlying threat (drives display ordering)
  mitreTechniques: z.array(z.string()).catch([]),
  relatedFindingIds: z.array(z.string()).catch([]),
});

export type HuntSuggestion = z.infer<typeof huntSuggestionSchema>;

// The model returns { suggestions: [...] }. `.catch` at every level keeps a partial reply usable.
export const huntSuggestionsResponseSchema = z.object({
  suggestions: z.array(huntSuggestionSchema).catch([]),
});

export type HuntSuggestionsResponse = z.infer<typeof huntSuggestionsResponseSchema>;

// Default cap on how many hunts to surface (override per case via DFIR_HUNT_SUGGEST_MAX). A short,
// high-signal list beats a wall of near-duplicate queries the analyst won't read.
export const HUNT_SUGGEST_MAX_DEFAULT = 8;

const MAX_VQL_LEN = 4000;        // a runaway query is a sign of a confused model; keep it pasteable
const MAX_TITLE_LEN = 200;
const MAX_RATIONALE_LEN = 2000;

// IOC types that a VQL hunt can actually pivot on (a file / hash / process name / network
// indicator). "other" IOCs carry no hunt value, so they're left out of the model's pivot list.
const PIVOTABLE_IOC_TYPES: ReadonlySet<IOC["type"]> = new Set<IOC["type"]>(["hash", "file", "process", "domain", "ip", "url"]);

// Drop unusable suggestions and clamp fields. A hunt with no VQL or no title is useless; a
// suggestion list longer than `max` is trimmed. Pure — deterministic, no I/O. Order is preserved
// (the pipeline hands events in the model's order; display sorting happens in the dashboard).
export function sanitizeHuntSuggestions(raw: readonly HuntSuggestion[] | undefined, max: number = HUNT_SUGGEST_MAX_DEFAULT): HuntSuggestion[] {
  const out: HuntSuggestion[] = [];
  const cap = Number.isFinite(max) && max > 0 ? Math.floor(max) : HUNT_SUGGEST_MAX_DEFAULT;
  for (const s of raw ?? []) {
    const vql = String(s?.vql ?? "").trim();
    const title = String(s?.title ?? "").trim();
    if (!vql || !title) continue;            // no query or no name → nothing to deploy
    out.push({
      title: title.slice(0, MAX_TITLE_LEN),
      rationale: String(s?.rationale ?? "").trim().slice(0, MAX_RATIONALE_LEN),
      vql: vql.slice(0, MAX_VQL_LEN),
      severity: s?.severity ?? "Medium",
      mitreTechniques: dedupeStrings((s?.mitreTechniques ?? []).map((t) => String(t).trim()).filter(Boolean)).slice(0, 20),
      relatedFindingIds: dedupeStrings((s?.relatedFindingIds ?? []).map((i) => String(i).trim()).filter(Boolean)).slice(0, 20),
    });
    if (out.length >= cap) break;
  }
  return out;
}

function dedupeStrings(arr: string[]): string[] {
  return [...new Set(arr)];
}

// Render the case findings the model should hunt around: id (so it can back-link via
// relatedFindingIds), severity, MITRE techniques, title, and a short description snippet.
// Dismissed findings are excluded (the analyst already ruled them out). Capped for the budget.
export function renderHuntFindings(findings: readonly Finding[], limit = 60): string {
  const kept = (findings ?? []).filter((f) => f.status !== "dismissed").slice(0, limit);
  if (!kept.length) return "(no findings yet)";
  return kept
    .map((f) => {
      const mitre = f.mitreTechniques?.length ? ` ATT&CK: ${f.mitreTechniques.join(", ")}` : "";
      const desc = (f.description ?? "").replace(/\s+/g, " ").trim().slice(0, 240);
      return `[${f.id}] [${f.severity}] ${f.title}${mitre}${desc ? ` — ${desc}` : ""}`;
    })
    .join("\n");
}

// Render the pivotable IOCs grouped by type so the model writes hunts keyed to the case's REAL
// indicators (these exact hashes / file paths / process names / domains / IPs) instead of
// inventing them. Non-pivotable ("other") IOCs are skipped; each group is capped.
export function renderHuntIocs(iocs: readonly IOC[], perTypeLimit = 25): string {
  const groups = new Map<IOC["type"], string[]>();
  for (const ioc of iocs ?? []) {
    if (!PIVOTABLE_IOC_TYPES.has(ioc.type)) continue;
    const val = String(ioc.value ?? "").trim();
    if (!val) continue;
    const list = groups.get(ioc.type) ?? [];
    if (list.length < perTypeLimit && !list.includes(val)) list.push(val);
    groups.set(ioc.type, list);
  }
  const order: IOC["type"][] = ["hash", "file", "process", "domain", "ip", "url"];
  const lines = order
    .filter((t) => groups.get(t)?.length)
    .map((t) => `${t}: ${groups.get(t)!.join(", ")}`);
  return lines.length ? lines.join("\n") : "(no pivotable IOCs)";
}

// Whether the case has enough signal to bother asking the model for hunts. With no non-dismissed
// findings AND no forensic events there is nothing to pivot on — the route returns [] without
// spending an AI call (and the dashboard shows a "synthesize first" hint).
export function hasHuntMaterial(state: InvestigationState): boolean {
  const liveFindings = (state.findings ?? []).some((f) => f.status !== "dismissed");
  return liveFindings || (state.forensicTimeline ?? []).length > 0;
}

// Severity rank for display ordering (Critical first). Exposed so the dashboard and any report
// stay consistent with the rest of the app's severity ordering.
export const HUNT_SEVERITY_RANK: Record<Severity, number> = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 };
