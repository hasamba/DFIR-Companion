import { z } from "zod";
import { LANGUAGE_PLATFORM, type CopyHuntLanguage } from "./huntLanguage.js";
import { normalizeHuntPlatform, type HuntPlatform } from "./huntPlatforms.js";
import { HUNT_SUGGEST_MAX_DEFAULT } from "./huntSuggest.js";
import { PLAYBOOK_HUNT_SUGGEST_MAX_DEFAULT } from "./playbookHunt.js";

// AI-written behaviour hunts in the case's main-source language (#2559) — the non-VQL sibling of
// huntSuggest.ts (fleet hunts) and playbookHunt.ts (per-task hunts). Pure pieces: the lenient
// response schema, a cheap per-language shape check, and the sanitizers.
//
// The query text lives in `query`, NEVER in a field named `vql`: everything that deploys a hunt,
// fingerprints it for the hit/miss ledger or records an outcome reads `.vql`, so a CQL/KQL/ES|QL/SPL
// hunt cannot reach Velociraptor by construction. These hunts are copy-ready only.
//
// Validation mirrors the VQL path (trim, drop empty, clamp) and adds two checks VQL never needed:
// the answer must look like the language it was asked for (a model that answers in VQL or SPL when
// asked for KQL is dropped, not shown under the wrong label), and an answer that names a different
// platform is dropped. AI output can be sanitised but not escaped; the analyst reviews before running.

const severityEnum = z.enum(["Critical", "High", "Medium", "Low", "Info"]);

export const languageHuntSchema = z.object({
  taskId: z.string().catch(""), // playbook hunts only
  relevant: z.boolean().catch(true), // playbook hunts only — false → dropped
  platform: z.string().catch(""), // optional echo of the language; a different platform → dropped
  title: z.string().catch(""),
  rationale: z.string().catch(""),
  query: z.string().catch(""),
  severity: severityEnum.catch("Medium"),
  mitreTechniques: z.array(z.string()).catch([]),
  relatedFindingIds: z.array(z.string()).catch([]),
});

export type RawLanguageHunt = z.infer<typeof languageHuntSchema>;

export const languageHuntResponseSchema = z.object({
  suggestions: z.array(languageHuntSchema).catch([]),
});

export interface LanguageHuntSuggestion {
  language: CopyHuntLanguage;
  platform: HuntPlatform;
  title: string;
  rationale: string;
  query: string;
  severity: z.infer<typeof severityEnum>;
  mitreTechniques: string[];
  relatedFindingIds: string[];
}

export interface PlaybookLanguageHunt extends Omit<LanguageHuntSuggestion, "relatedFindingIds"> {
  taskId: string;
}

const MAX_QUERY_LEN = 4000;
const MAX_TITLE_LEN = 200;
const MAX_RATIONALE_LEN = 2000;

const SQL_SELECT_RE = /^\s*SELECT\b/i; // VQL (or SQL) — never right for these languages
const KQL_LET_RE = /^\s*let\s+[^;]*;\s*/i;
const KQL_FIRST_TABLE_RE = /^\s*([A-Za-z_][A-Za-z0-9_]*)\b/;
const KQL_DEVICE_TABLE_RE =
  /^(Device[A-Za-z]*|Alert[A-Za-z]*|Email[A-Za-z]*|Identity[A-Za-z]*|union|search|find)$/;
const KQL_CLOUD_TABLE_RE =
  /^(SigninLogs|AADNonInteractiveUserSignInLogs|AADServicePrincipalSignInLogs|AuditLogs|OfficeActivity|CloudAppEvents|IdentityLogonEvents|IdentityDirectoryEvents|union|search|find)$/;
// SPL's implicit `search` accepts almost any leading term, so SPL is checked by what it must NOT be:
// a KQL table piped into a KQL operator, an ES|QL FROM, or a CQL event tag.
const KQL_SHAPE_RE = /^\s*[A-Za-z_][A-Za-z0-9_]*\s*\|\s*(where|project|extend|summarize|take)\b/i;
const ESQL_START_RE = /^\s*FROM\s+\S/i;
const CQL_EVENT_RE = /#event_simpleName\s*=|#repo\s*=|\bevent_simpleName\s*=/;
const CQL_FOREIGN_RE = /^\s*(FROM\s|index\s*=|sourcetype\s*=)/i;

// Leading `//` comment lines are valid in KQL, ES|QL and CQL; the shape is read after them.
const LEADING_COMMENTS_RE = /^(\s*\/\/[^\n]*\n)+/;
const withoutLeadingComments = (q: string): string => q.replace(LEADING_COMMENTS_RE, "");

function kqlFirstTable(query: string): string {
  let q = query;
  while (KQL_LET_RE.test(q)) q = q.replace(KQL_LET_RE, "");
  return KQL_FIRST_TABLE_RE.exec(q)?.[1] ?? "";
}

/** A cheap shape check: does the query look like the language it was asked for? */
export function isPlausibleHuntQuery(language: CopyHuntLanguage, raw: string): boolean {
  const query = language === "spl" ? raw : withoutLeadingComments(raw);
  if (!query.trim() || SQL_SELECT_RE.test(query)) return false;
  switch (language) {
    case "kql-device":
      return KQL_DEVICE_TABLE_RE.test(kqlFirstTable(query));
    case "kql-cloud":
      return KQL_CLOUD_TABLE_RE.test(kqlFirstTable(query));
    case "esql":
      return ESQL_START_RE.test(query);
    case "spl":
      return !KQL_SHAPE_RE.test(query) && !ESQL_START_RE.test(query) && !CQL_EVENT_RE.test(query);
    case "cql":
      return CQL_EVENT_RE.test(query) && !CQL_FOREIGN_RE.test(query);
  }
}

const FENCE_RE = /^```[A-Za-z|-]*\s*\n([\s\S]*?)\n?```\s*$/;

function cleanQuery(raw: string): string {
  const t = String(raw ?? "").trim();
  return (FENCE_RE.exec(t)?.[1] ?? t).trim();
}

const dedupe = (xs: string[]): string[] => [...new Set(xs.map((x) => String(x).trim()).filter(Boolean))];

function cleanCommon(
  s: RawLanguageHunt,
  language: CopyHuntLanguage,
  exclude: string | undefined,
): Omit<LanguageHuntSuggestion, "relatedFindingIds"> | null {
  const query = cleanQuery(s.query);
  const title = String(s.title ?? "").trim();
  if (!query || !title) return null;
  const echoed = s.platform ? normalizeHuntPlatform(s.platform) : null;
  if (s.platform && echoed !== LANGUAGE_PLATFORM[language]) return null; // answered for another tool
  if (!isPlausibleHuntQuery(language, query)) return null;
  if (exclude && query === cleanQuery(exclude)) return null; // regenerate must give something new
  return {
    language,
    platform: LANGUAGE_PLATFORM[language],
    title: title.slice(0, MAX_TITLE_LEN),
    rationale: String(s.rationale ?? "")
      .trim()
      .slice(0, MAX_RATIONALE_LEN),
    query: query.slice(0, MAX_QUERY_LEN),
    severity: s.severity ?? "Medium",
    mitreTechniques: dedupe(s.mitreTechniques ?? []).slice(0, 20),
  };
}

const capOf = (max: number | undefined, fallback: number): number =>
  max !== undefined && Number.isFinite(max) && max > 0 ? Math.floor(max) : fallback;

/** Fleet (finding) hunts: drop unusable answers, keep only cited findings that were sent. */
export function sanitizeLanguageHunts(
  raw: readonly RawLanguageHunt[] | undefined,
  language: CopyHuntLanguage,
  opts: { allowedFindingIds?: ReadonlySet<string>; exclude?: string; max?: number },
): LanguageHuntSuggestion[] {
  const cap = capOf(opts.max, HUNT_SUGGEST_MAX_DEFAULT);
  const out: LanguageHuntSuggestion[] = [];
  for (const s of raw ?? []) {
    const base = cleanCommon(s, language, opts.exclude);
    if (!base) continue;
    const ids = dedupe(s.relatedFindingIds ?? []);
    const allowed = opts.allowedFindingIds;
    out.push({
      ...base,
      relatedFindingIds: (allowed ? ids.filter((i) => allowed.has(i)) : ids).slice(0, 20),
    });
    if (out.length >= cap) break;
  }
  return out;
}

/** Playbook hunts: one per task that was sent and that the model marked relevant. */
export function sanitizePlaybookLanguageHunts(
  raw: readonly RawLanguageHunt[] | undefined,
  language: CopyHuntLanguage,
  taskIds: ReadonlySet<string>,
  opts: { exclude?: string; max?: number } = {},
): PlaybookLanguageHunt[] {
  const cap = capOf(opts.max, PLAYBOOK_HUNT_SUGGEST_MAX_DEFAULT);
  const out: PlaybookLanguageHunt[] = [];
  const seen = new Set<string>();
  for (const s of raw ?? []) {
    const taskId = String(s.taskId ?? "").trim();
    if (!s.relevant || !taskIds.has(taskId) || seen.has(taskId)) continue;
    const base = cleanCommon(s, language, opts.exclude);
    if (!base) continue;
    seen.add(taskId);
    out.push({ ...base, taskId });
    if (out.length >= cap) break;
  }
  return out;
}
