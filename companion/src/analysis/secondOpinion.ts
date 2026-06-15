import { z } from "zod";
import type { Finding, InvestigationState, Severity, Technique } from "./stateTypes.js";

// Second LLM opinion (issue #116). A QA control: a DIFFERENT model independently re-synthesizes
// the same case, and we surface where it disagrees with the primary synthesis so the analyst can
// adjudicate before finalizing a report. This module is PURE (no I/O, no AI) — it computes the
// deterministic delta set between the two analyses, shapes the reconcile prompt, merges the
// reconcile AI's per-delta verdicts, and applies the analyst's accepted deltas back onto the case.
//
// Findings are DERIVED in this architecture (synthesis rewrites them), so an accepted delta is made
// durable by re-applying it via `applyAcceptedSecondOpinion` — used by BOTH the apply route and
// synthesize()'s post-processing, so an accepted model-B call never silently regresses.

export type SecondOpinionDeltaKind = "b_only" | "a_only" | "severity" | "mitre_added" | "mitre_removed";
export type DeltaStatus = "pending" | "accepted" | "rejected";
export type DeltaRecommendation = "accept_b" | "keep_a" | "review";

export interface SecondOpinionDelta {
  id: string;                         // stable: `${kind}:${slug(title)}`
  kind: SecondOpinionDeltaKind;
  title: string;                      // finding title, or the ATT&CK technique id for mitre_* deltas
  aSeverity?: Severity;               // severity/ a_only: model A's severity
  bSeverity?: Severity;               // severity / b_only: model B's severity
  finding?: Finding;                  // b_only: B's finding (merged on accept); a_only/severity: A's finding (edited in place)
  techniqueName?: string;             // mitre_added: the technique name, so accept can add a labelled Technique
  rationale: string;                  // one-line reconcile-AI judgement (default "")
  recommendation: DeltaRecommendation; // reconcile-AI suggestion (default "review")
  status: DeltaStatus;                // pending | accepted | rejected
}

export interface SecondOpinion {
  generatedAt: string;
  modelA: string;                     // primary synthesis model label
  modelB: string;                     // second-opinion model label
  summary: string;                    // reconcile-AI overall assessment (default "")
  agreementCount: number;             // findings BOTH models share (by normalized title)
  deltas: SecondOpinionDelta[];
}

const norm = (title: string): string => String(title).trim().toLowerCase().replace(/\s+/g, " ");

// URL/id-safe slug for a stable delta id. Collapses runs of non-alphanumerics to single dashes.
function slug(text: string): string {
  return String(text).trim().toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "") || "x";
}

// First occurrence of each normalized title wins (mirrors findingsDiff.byTitle), keeping the
// displayed finding object so we can carry/merge it.
function byTitle(findings: readonly Finding[]): Map<string, Finding> {
  const map = new Map<string, Finding>();
  for (const f of findings) {
    const key = norm(f.title);
    if (!key || map.has(key)) continue;
    map.set(key, f);
  }
  return map;
}

// Compute the deterministic delta set between model A (primary, saved) and model B (second opinion).
// b_only: B raised a finding A missed; a_only: A has a finding B dropped; severity: shared title,
// different severity; mitre_added/removed: ATT&CK techniques present on one side only (by id).
export function buildSecondOpinionDeltas(a: InvestigationState, b: InvestigationState): SecondOpinionDelta[] {
  const aF = byTitle(a.findings);
  const bF = byTitle(b.findings);
  const deltas: SecondOpinionDelta[] = [];

  for (const [key, bf] of bF) {
    const af = aF.get(key);
    if (!af) {
      deltas.push(delta("b_only", bf.title, { finding: bf, bSeverity: bf.severity }));
    } else if (af.severity !== bf.severity) {
      deltas.push(delta("severity", af.title, { finding: af, aSeverity: af.severity, bSeverity: bf.severity }));
    }
  }
  for (const [key, af] of aF) {
    if (!bF.has(key)) deltas.push(delta("a_only", af.title, { finding: af, aSeverity: af.severity }));
  }

  const aTech = new Map(a.mitreTechniques.map((t) => [t.id, t]));
  const bTech = new Map(b.mitreTechniques.map((t) => [t.id, t]));
  for (const [id, t] of bTech) {
    if (!aTech.has(id)) deltas.push(delta("mitre_added", id, { techniqueName: t.name }));
  }
  for (const [id, t] of aTech) {
    if (!bTech.has(id)) deltas.push(delta("mitre_removed", id, { techniqueName: t.name }));
  }
  return deltas;
}

function delta(kind: SecondOpinionDeltaKind, title: string, extra: Partial<SecondOpinionDelta>): SecondOpinionDelta {
  return {
    id: `${kind}:${slug(title)}`,
    kind,
    title,
    rationale: "",
    recommendation: "review",
    status: "pending",
    ...extra,
  };
}

// Findings BOTH models produced (intersection of normalized titles) — a simple agreement signal.
function agreementCount(a: InvestigationState, b: InvestigationState): number {
  const aT = byTitle(a.findings);
  let n = 0;
  for (const key of byTitle(b.findings).keys()) if (aT.has(key)) n++;
  return n;
}

export interface BuildSecondOpinionInput {
  a: InvestigationState;
  b: InvestigationState;
  modelA: string;
  modelB: string;
  now: () => string;
}

// Assemble a fresh SecondOpinion record (deltas pending, no reconcile verdicts yet).
export function buildSecondOpinion(input: BuildSecondOpinionInput): SecondOpinion {
  return {
    generatedAt: input.now(),
    modelA: input.modelA,
    modelB: input.modelB,
    summary: "",
    agreementCount: agreementCount(input.a, input.b),
    deltas: buildSecondOpinionDeltas(input.a, input.b),
  };
}

// --- Reconcile AI pass (annotate the deltas with rationale + recommendation) -------------------

export const reconcileResponseSchema = z.object({
  summary: z.string().catch(""),
  verdicts: z.array(z.object({
    id: z.string(),
    rationale: z.string().catch(""),
    // Lenient enum: an unexpected value falls back to "review" instead of rejecting the response.
    recommendation: z.enum(["accept_b", "keep_a", "review"]).catch("review"),
  })).catch([]),
});

export type ReconcileResponse = z.infer<typeof reconcileResponseSchema>;

// System prompt for the reconcile call (overridable via DFIR_AI_RECONCILE_PROMPT[_FILE]).
export const RECONCILE_PROMPT = [
  "You are a senior DFIR analyst RECONCILING two INDEPENDENT analyses of the SAME investigation:",
  "Model A (the primary synthesis) and Model B (an independent second opinion run by a different model).",
  "You are given the points where they DISAGREE. For EACH numbered delta, judge which call is better",
  "supported by standard DFIR reasoning and give a one-line rationale plus a recommendation:",
  "- accept_b: Model B is right — adopt B's call (add B's finding, take B's severity, add/remove the technique).",
  "- keep_a:   Model A is right — keep A as-is and reject B's change.",
  "- review:   genuinely ambiguous — the analyst must decide.",
  "Be decisive but honest: prefer 'review' only when the evidence truly doesn't settle it. Do NOT invent",
  "evidence; reason only from the finding titles, severities, descriptions, and the case summaries shown.",
  "Also write a 1-2 sentence 'summary' of how the two analyses compare overall.",
  "",
  "Return ONLY raw JSON (no markdown fences) with EXACTLY this shape — echo each delta's id verbatim:",
  JSON.stringify({
    summary: "one to two sentences comparing the two analyses",
    verdicts: [{ id: "b_only:example-finding", rationale: "why one model's call is better supported", recommendation: "accept_b|keep_a|review" }],
  }, null, 2),
].join("\n");

const sevLabel = (s?: Severity): string => s ?? "?";

// Render one delta as a numbered line the reconcile model can judge.
function renderDelta(d: SecondOpinionDelta): string {
  const desc = d.finding?.description ? ` — ${d.finding.description.slice(0, 240)}` : "";
  switch (d.kind) {
    case "b_only":
      return `[${d.id}] (B-only finding) "${d.title}" [severity ${sevLabel(d.bSeverity)}]: Model B raised this; Model A did NOT.${desc}`;
    case "a_only":
      return `[${d.id}] (A-only finding) "${d.title}" [severity ${sevLabel(d.aSeverity)}]: Model A has this; Model B DROPPED it (B may judge it unsupported/benign).${desc}`;
    case "severity":
      return `[${d.id}] (severity disagreement) "${d.title}": Model A says ${sevLabel(d.aSeverity)}, Model B says ${sevLabel(d.bSeverity)}.${desc}`;
    case "mitre_added":
      return `[${d.id}] (ATT&CK technique) ${d.title}${d.techniqueName ? ` (${d.techniqueName})` : ""}: Model B maps this technique; Model A does not.`;
    case "mitre_removed":
      return `[${d.id}] (ATT&CK technique) ${d.title}${d.techniqueName ? ` (${d.techniqueName})` : ""}: Model A maps this technique; Model B does not.`;
  }
}

// Build the reconcile USER prompt: the two case summaries + every disagreement, each tagged with its id.
export function buildReconcilePrompt(a: InvestigationState, b: InvestigationState, deltas: readonly SecondOpinionDelta[]): string {
  const aSummary = a.lastSummary?.trim() || a.attackerPath?.trim() || "(no summary)";
  const bSummary = b.lastSummary?.trim() || b.attackerPath?.trim() || "(no summary)";
  return [
    `MODEL A (primary) summary: ${aSummary}`,
    "",
    `MODEL B (second opinion) summary: ${bSummary}`,
    "",
    `DISAGREEMENTS (${deltas.length}):`,
    ...deltas.map(renderDelta),
    "",
    "Return your reconciliation as raw JSON in the required shape — one verdict object per delta id above.",
  ].join("\n");
}

// Merge the reconcile AI's per-delta verdicts (rationale + recommendation) onto the matching deltas
// by id, and set the overall summary. Unknown ids are ignored. Immutable.
export function mergeReconcileVerdicts(so: SecondOpinion, parsed: ReconcileResponse): SecondOpinion {
  const byId = new Map(parsed.verdicts.map((v) => [v.id, v]));
  return {
    ...so,
    summary: parsed.summary,
    deltas: so.deltas.map((d) => {
      const v = byId.get(d.id);
      return v ? { ...d, rationale: v.rationale, recommendation: v.recommendation } : d;
    }),
  };
}

// --- Analyst actions --------------------------------------------------------------------------

// Immutably set one delta's status (pending | accepted | rejected). Other deltas are untouched.
export function setDeltaStatus(so: SecondOpinion, id: string, status: DeltaStatus): SecondOpinion {
  return { ...so, deltas: so.deltas.map((d) => (d.id === id ? { ...d, status } : d)) };
}

// Bulk variant for accept-all / reject-all: set EVERY still-pending delta to `status`. Deltas the
// analyst already decided (accepted/rejected) are left as-is, so a bulk action never silently
// reverses an individual decision. Immutable.
export function setAllPendingStatus(so: SecondOpinion, status: DeltaStatus): SecondOpinion {
  return { ...so, deltas: so.deltas.map((d) => (d.status === "pending" ? { ...d, status } : d)) };
}

// Apply EVERY accepted delta onto a case state. Pure, immutable, IDEMPOTENT (safe to run on every
// read/synthesis): b_only adds B's finding if absent by title; a_only dismisses A's finding in
// place; severity rewrites A's finding severity; mitre_added/removed add/remove the technique.
// Used by both the apply route (on the live state) and synthesize() post-processing (durability).
export function applyAcceptedSecondOpinion(state: InvestigationState, so: SecondOpinion | null): InvestigationState {
  if (!so) return state;
  const accepted = so.deltas.filter((d) => d.status === "accepted");
  if (accepted.length === 0) return state;

  let findings = state.findings;
  let techniques = state.mitreTechniques;

  for (const d of accepted) {
    if (d.kind === "b_only" && d.finding) {
      const key = norm(d.title);
      if (!findings.some((f) => norm(f.title) === key)) {
        findings = [...findings, { ...d.finding, id: `so:${slug(d.title)}`, status: "open" }];
      }
    } else if (d.kind === "a_only") {
      findings = mapByTitle(findings, d.title, (f) => ({ ...f, status: "dismissed" as const }));
    } else if (d.kind === "severity" && d.bSeverity) {
      const sev = d.bSeverity;
      findings = mapByTitle(findings, d.title, (f) => ({ ...f, severity: sev }));
    } else if (d.kind === "mitre_added") {
      if (!techniques.some((t) => t.id === d.title)) {
        techniques = [...techniques, { id: d.title, name: d.techniqueName || d.title, findingIds: [] } satisfies Technique];
      }
    } else if (d.kind === "mitre_removed") {
      techniques = techniques.filter((t) => t.id !== d.title);
    }
  }

  if (findings === state.findings && techniques === state.mitreTechniques) return state;
  return { ...state, findings, mitreTechniques: techniques };
}

function mapByTitle(findings: readonly Finding[], title: string, fn: (f: Finding) => Finding): Finding[] {
  const key = norm(title);
  return findings.map((f) => (norm(f.title) === key ? fn(f) : f));
}
