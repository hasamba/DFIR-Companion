import { z } from "zod";
import type { WatsonLookup } from "./types.js";

// Boundary for the lookup Watson asks for in its reply (Task 11). The reply is untrusted model JSON:
// a lookup over a limit or of the wrong shape is dropped whole with a reason the analyst sees, never
// clamped and never thrown. Selection itself is timelineLookup.ts.

export const WATSON_LOOKUP_LIMITS = {
  findingIds: 10,
  eventIds: 50,
  chars: 200,
  idChars: 200,
  windowDays: 7,
} as const;

/** A checked lookup to run, or why the one Watson asked for was dropped. */
export type WatsonLookupAsk = { ok: true; query: WatsonLookup } | { ok: false; why: string };

const DAY_MS = 86_400_000;
const L = WATSON_LOOKUP_LIMITS;
const id = z.string().trim().min(1).max(L.idChars);
const words = z.string().trim().min(1).max(L.chars);
const stamp = z.string().refine((s) => Number.isFinite(Date.parse(s)), "not a timestamp");

const lookupObject = z.object({
  findingIds: z.array(id).max(L.findingIds).optional(),
  eventIds: z.array(id).max(L.eventIds).optional(),
  from: stamp.optional(),
  to: stamp.optional(),
  host: words.optional(),
  text: words.optional(),
});

/** Models often send null or [] for a field they do not use: those count as not given. */
function present(raw: Record<string, unknown>): Record<string, unknown> {
  return Object.fromEntries(
    Object.entries(raw).filter(([, v]) => v !== null && v !== undefined && !(Array.isArray(v) && !v.length)),
  );
}

function windowProblem(q: WatsonLookup): string | null {
  if (q.from === undefined && q.to === undefined) return null;
  if (q.from === undefined || q.to === undefined) return "a time window needs both 'from' and 'to'";
  const span = Date.parse(q.to) - Date.parse(q.from);
  if (span < 0) return "'from' is after 'to'";
  if (span > L.windowDays * DAY_MS) return `the time window is longer than ${L.windowDays} days`;
  return null;
}

const issueText = (e: z.ZodError): string =>
  e.issues
    .slice(0, 2)
    .map((i) => `${i.path.join(".") || "lookup"}: ${i.message}`)
    .join("; ");

/** Null when the reply asked for no lookup; otherwise a checked lookup or the reason it was dropped. */
export function parseLookup(raw: unknown): WatsonLookupAsk | null {
  if (raw === null || raw === undefined) return null;
  if (typeof raw !== "object" || Array.isArray(raw)) return { ok: false, why: "it was not a lookup object" };
  const parsed = lookupObject.safeParse(present(raw as Record<string, unknown>));
  if (!parsed.success) return { ok: false, why: issueText(parsed.error) };
  const query = Object.fromEntries(
    Object.entries(parsed.data).filter(([, v]) => v !== undefined),
  ) as WatsonLookup;
  if (Object.keys(query).length === 0) {
    return { ok: false, why: "it named no finding, event, time window, host or text" };
  }
  const bad = windowProblem(query);
  return bad ? { ok: false, why: bad } : { ok: true, query };
}

/** The reply field: anything in, a checked lookup (or its drop reason) out. */
export const lookupFieldSchema = z.unknown().transform(parseLookup);

const listed = (ids: readonly string[], max = 5): string =>
  ids.slice(0, max).join(", ") + (ids.length > max ? ` (+${ids.length - max} more)` : "");

/** The lookup in plain words, for the analyst's card and the prompt's block title. */
export function describeLookup(q: WatsonLookup): string {
  const parts = [
    q.findingIds ? `events cited by finding ${listed(q.findingIds)}` : "",
    q.eventIds ? `event ${listed(q.eventIds)}` : "",
    q.from && q.to ? `from ${q.from} to ${q.to}` : "",
    q.host ? `on host ${q.host}` : "",
    q.text ? `containing "${q.text}"` : "",
  ];
  return parts.filter(Boolean).join("; ");
}
