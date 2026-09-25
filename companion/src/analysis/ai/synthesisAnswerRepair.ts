import { ZodError } from "zod";
import { techniqueName } from "../attackTechniqueNames.js";
import { AiAnswerParseError } from "./providerCall.js";

/**
 * Make synthesis survive a partial model answer (#1602).
 *
 * A model that returns good findings but leaves out a list that is often empty used to lose the
 * whole answer to one schema error, and every retry resent the identical request, so the model
 * gave the identical answer. Two pure helpers fix that:
 *
 * - `fillOptionalSynthesisFields` defaults the four often-empty lists and the timeline note. It
 *   never fills `findings` or `summary`: an answer without those has nothing worth keeping.
 *   `mitreTechniques` is NOT filled with `[]`: synthesis replaces the case's MITRE table with this
 *   list, so an empty default would erase every technique the findings still carry. It is rebuilt
 *   from the techniques the answer's own findings name instead.
 * - `synthesisRetryNote` turns the failure into one sentence the NEXT attempt appends to its
 *   request. It is runtime context, not prompt text, so the prompt constants stay untouched.
 */

const LIST_FIELDS = ["iocs", "threadsOpened", "threadsClosed"] as const;
const MAX_NAMED_PATHS = 10;

export function fillOptionalSynthesisFields(parsed: unknown): { value: unknown; filled: string[] } {
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return { value: parsed, filled: [] };
  const src = parsed as Record<string, unknown>;
  const out: Record<string, unknown> = { ...src };
  const filled: string[] = [];
  for (const f of LIST_FIELDS) {
    if (src[f] === undefined || src[f] === null) {
      out[f] = [];
      filled.push(f);
    }
  }
  if (src.mitreTechniques === undefined || src.mitreTechniques === null) {
    out.mitreTechniques = techniquesFromFindings(src.findings);
    filled.push("mitreTechniques");
  }
  if (src.timelineNote === undefined || src.timelineNote === null) {
    out.timelineNote = "";
    filled.push("timelineNote");
  }
  return { value: out, filled };
}

// The distinct technique ids the findings name, as the table rows synthesis would have written.
function techniquesFromFindings(findings: unknown): Array<{ id: string; name: string }> {
  if (!Array.isArray(findings)) return [];
  const ids = new Set<string>();
  for (const f of findings) {
    const techs: unknown =
      f && typeof f === "object" ? (f as { mitreTechniques?: unknown }).mitreTechniques : undefined;
    if (!Array.isArray(techs)) continue;
    for (const t of techs) if (typeof t === "string" && t.trim()) ids.add(t.trim());
  }
  return [...ids].map((id) => ({ id, name: techniqueName(id) }));
}

function isOmitted(issue: ZodError["issues"][number]): boolean {
  return issue.path.length === 1 && issue.code === "invalid_type" && issue.received === "undefined";
}

/**
 * The note for the next attempt, or `undefined` when this failure says nothing about the answer
 * (a provider or network error). `undefined` means KEEP the current note, not clear it.
 */
export function synthesisRetryNote(err: unknown): string | undefined {
  if (err instanceof AiAnswerParseError)
    return "Your previous answer was not valid JSON. Return one complete JSON object and nothing else.";
  if (!(err instanceof ZodError)) return undefined;
  const omitted = [...new Set(err.issues.filter(isOmitted).map((i) => String(i.path[0])))];
  if (omitted.length > 0)
    return `Your previous answer omitted: ${omitted.join(", ")}. Return the complete JSON object with every field.`;
  const paths = [...new Set(err.issues.map((i) => (i.path.length ? i.path.join(".") : "<root>")))];
  return (
    `Your previous answer had invalid fields: ${paths.slice(0, MAX_NAMED_PATHS).join(", ")}. ` +
    "Return the complete JSON object with every field in the required shape."
  );
}
