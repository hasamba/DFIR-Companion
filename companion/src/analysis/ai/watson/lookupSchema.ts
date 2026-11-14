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
  superTextMin: 3,
} as const;

/** A checked lookup to run, or why the one Watson asked for was dropped. */
export type WatsonLookupAsk = { ok: true; query: WatsonLookup } | { ok: false; why: string };

const DAY_MS = 86_400_000;
const L = WATSON_LOOKUP_LIMITS;
const id = z.string().trim().min(1).max(L.idChars);
const words = z.string().trim().min(1).max(L.chars);
const stamp = z.string().refine((s) => Number.isFinite(Date.parse(s)), "not a timestamp");

const hashText = z
  .string()
  .trim()
  .regex(/^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$/i);

const lookupObject = z.object({
  source: z.enum(["forensic", "supertimeline"]).optional(),
  hash: hashText.optional(),
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

/** True for a search of the analyst-only super-timeline rather than the forensic timeline. */
export const isSuperLookup = (q: WatsonLookup): boolean => q.source === "supertimeline";

function superProblem(q: WatsonLookup): string | null {
  if (!isSuperLookup(q)) return q.hash !== undefined ? "a hash search is for the super-timeline" : null;
  if (q.findingIds || q.eventIds) {
    return "a super-timeline search takes text, a hash, a host or a time window, not ids";
  }
  if (q.text === undefined && q.hash === undefined && q.host === undefined && q.from === undefined) {
    return "a super-timeline search needs text, a hash, a host or a time window";
  }
  if (q.text !== undefined && q.text.length < L.superTextMin) {
    return `super-timeline search text must be at least ${L.superTextMin} characters`;
  }
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
  // "forensic" is the default source: it is stored only for the super-timeline.
  const query = Object.fromEntries(
    Object.entries(parsed.data).filter(([k, v]) => v !== undefined && !(k === "source" && v === "forensic")),
  ) as WatsonLookup;
  if (Object.keys(query).length === 0) {
    return { ok: false, why: "it named no finding, event, time window, host or text" };
  }
  const bad = windowProblem(query) ?? superProblem(query);
  return bad ? { ok: false, why: bad } : { ok: true, query };
}

/** The reply field: anything in, a checked lookup (or its drop reason) out. */
export const lookupFieldSchema = z.unknown().transform(parseLookup);

const listed = (ids: readonly string[], max = 5): string =>
  ids.slice(0, max).join(", ") + (ids.length > max ? ` (+${ids.length - max} more)` : "");

/** The lookup in plain words, for the analyst's card and the prompt's block title. */
export function describeLookup(q: WatsonLookup): string {
  const parts = [
    isSuperLookup(q) ? "super-timeline rows" : "",
    q.findingIds ? `events that finding ${listed(q.findingIds)} cites` : "",
    q.eventIds ? `event ${listed(q.eventIds)}` : "",
    q.from && q.to ? `from ${q.from} to ${q.to}` : "",
    q.host ? `on host ${q.host}` : "",
    q.hash ? `with hash ${q.hash}` : "",
    q.text ? `with the text "${q.text}"` : "",
  ].filter(Boolean);
  // The "super-timeline rows" lead reads as a noun phrase: the criteria follow it, not a semicolon.
  return isSuperLookup(q)
    ? [parts[0], parts.slice(1).join("; ")].filter(Boolean).join(" ")
    : parts.join("; ");
}
