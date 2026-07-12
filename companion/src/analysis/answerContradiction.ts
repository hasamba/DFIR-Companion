// Answer-contradiction validator (investigation-guidance #3). The most dangerous single output an IR
// tool can produce is a flatly WRONG negative conclusion delivered with authority — e.g. halcyon
// answered q_exfiltration "No data exfiltration has been confirmed" while the xcopy-to-E: and 7z
// staging commands sat verbatim, correctly technique-tagged, in the timeline. Nothing validated the
// answer against the deterministic technique tags the system already computed.
//
// This is a PURE, deterministic post-synthesis pass over data already in state: it maps each standard
// DFIR question to the ATT&CK technique FAMILIES that would evidence it, and when a question's answer
// ASSERTS AN ABSENCE but in-scope (non-FP) events carry those techniques, it forces the status to
// "partial" and rewrites the pointer to cite the contradicting events, plus stamps a `contradicted`
// flag the UI/report render as a badge. No AI call. It never fabricates a positive answer — it only
// refuses to let an unqualified "no" stand against the timeline.

import type { ForensicEvent, InvestigationQuestion } from "./stateTypes.js";

// A question ↔ technique-family rule. A question matches when its id contains any `idPatterns` token OR
// its text contains any `textKeywords` token (the model chooses ids freely past the four examples in the
// synthesis prompt, so we match text too). `techniquePrefixes` are matched as PREFIXES, so "T1041"
// covers "T1041.001". Kept deliberately to families where an absence claim is falsifiable by a tag.
interface ContradictionRule {
  key: string;
  idPatterns: string[];
  textKeywords: string[];
  techniquePrefixes: string[];
}

export const CONTRADICTION_RULES: readonly ContradictionRule[] = [
  {
    key: "exfiltration",
    idPatterns: ["exfil"],
    textKeywords: ["exfiltrat", "data theft", "data was stolen", "data transfer out"],
    // exfil channels + physical medium/USB + local & remote staging (halcyon: xcopy→E:, 7z archive)
    techniquePrefixes: ["T1041", "T1048", "T1052", "T1567", "T1030", "T1020", "T1074", "T1560"],
  },
  {
    key: "lateral_movement",
    idPatterns: ["lateral"],
    textKeywords: ["lateral movement", "moved between hosts", "pivot"],
    techniquePrefixes: ["T1021", "T1570", "T1550", "T1563"],
  },
  {
    key: "persistence",
    idPatterns: ["persist"],
    textKeywords: ["persistence", "maintain access", "foothold"],
    techniquePrefixes: ["T1053", "T1543", "T1546", "T1547", "T1136", "T1098", "T1505", "T1574"],
  },
  {
    key: "privilege_escalation",
    idPatterns: ["priv", "escalat"],
    textKeywords: ["privilege escalation", "elevated privileges", "escalate"],
    techniquePrefixes: ["T1548", "T1068", "T1134", "T1484", "T1055"],
  },
  {
    key: "credential_access",
    idPatterns: ["cred"],
    textKeywords: ["credential", "password", "hash dump", "kerberoast"],
    techniquePrefixes: ["T1003", "T1110", "T1555", "T1552", "T1558", "T1556", "T1187"],
  },
  {
    key: "command_and_control",
    idPatterns: ["c2", "command_and_control", "command", "control"],
    textKeywords: ["command & control", "command and control", "c2", "beacon"],
    techniquePrefixes: ["T1071", "T1105", "T1572", "T1090", "T1568", "T1219", "T1102", "T1573"],
  },
  {
    key: "initial_access",
    idPatterns: ["initial"],
    textKeywords: ["initial access", "how did they get in", "entry vector", "first compromise"],
    techniquePrefixes: ["T1566", "T1190", "T1133", "T1189", "T1195", "T1078", "T1091", "T1200"],
  },
  {
    key: "log_tampering",
    idPatterns: ["log_tamper", "anti_forensic", "tamper"],
    textKeywords: ["cleared logs", "log tampering", "anti-forensic", "deleted logs", "wiped logs"],
    techniquePrefixes: ["T1070", "T1562", "T1027", "T1218"],
  },
];

// Does the answer ASSERT AN ABSENCE (not merely "unknown")? Needs a negation token AND an absence/
// confirmation word, so "No data exfiltration has been confirmed" trips it but "not only X but Y" and a
// neutral answer do not. An empty answer is NOT an absence assertion ("we don't know" ≠ "it didn't
// happen") — the caller also gates on a non-empty answer.
const NEGATION_RE = /\b(no|not|never|none|without|nothing|didn'?t|wasn'?t|weren'?t|isn'?t|aren'?t|un(?:confirmed|observed|detected))\b/i;
const ABSENCE_CONTEXT_RE =
  /\b(evidence|confirmed?|observ\w*|found|detect\w*|identif\w*|occurr\w*|present|indication|sign|signs|activity|seen|no such|took place|happen\w*)\b/i;

export function assertsAbsence(answer: string): boolean {
  const a = String(answer ?? "").trim();
  if (!a) return false;
  return NEGATION_RE.test(a) && ABSENCE_CONTEXT_RE.test(a);
}

function matchesRule(q: Pick<InvestigationQuestion, "id" | "question">, rule: ContradictionRule): boolean {
  const id = String(q.id ?? "").toLowerCase();
  if (rule.idPatterns.some((p) => id.includes(p))) return true;
  const text = String(q.question ?? "").toLowerCase();
  return rule.textKeywords.some((k) => text.includes(k));
}

function eventHasPrefix(techniques: readonly string[] | undefined, prefixes: readonly string[]): string[] {
  const hits: string[] = [];
  for (const t of techniques ?? []) {
    const up = String(t).toUpperCase();
    if (prefixes.some((p) => up === p || up.startsWith(p + "."))) hits.push(up);
  }
  return hits;
}

const MAX_CITED_EVENTS = 3;

// The techniques + a few event ids in `events` that contradict `rule` (i.e. evidence the question's
// negative answer overlooked). Empty techniques ⇒ no contradiction.
export function findContradictingEvents(
  events: readonly ForensicEvent[],
  rule: ContradictionRule,
): { techniques: string[]; eventIds: string[] } {
  const techniques = new Set<string>();
  const eventIds: string[] = [];
  for (const e of events ?? []) {
    const hits = eventHasPrefix(e.mitreTechniques, rule.techniquePrefixes);
    if (!hits.length) continue;
    hits.forEach((h) => techniques.add(h));
    if (eventIds.length < MAX_CITED_EVENTS) eventIds.push(e.id);
  }
  return { techniques: [...techniques].sort(), eventIds };
}

// For each question whose answer asserts an absence but whose technique family IS present in the
// in-scope events, force status → "partial", stamp `contradicted`, and rewrite the pointer to cite the
// contradicting events. `events` MUST already be the in-scope, non-false-positive set (the same the
// model saw). Pure: returns new question objects, never mutates. A question already flagged is
// recomputed idempotently (the flag is cleared first, so a since-corrected answer loses the badge).
export function flagContradictedAnswers(
  questions: readonly InvestigationQuestion[],
  events: readonly ForensicEvent[],
): InvestigationQuestion[] {
  return (questions ?? []).map((q) => {
    const { contradicted: _prev, ...clean } = q;   // recompute from scratch each pass
    if (!assertsAbsence(clean.answer)) return clean;
    const rule = CONTRADICTION_RULES.find((r) => matchesRule(clean, r));
    if (!rule) return clean;
    const { techniques, eventIds } = findContradictingEvents(events, rule);
    if (!techniques.length) return clean;
    const cite = eventIds.length ? ` [${eventIds.join(", ")}]` : "";
    return {
      ...clean,
      status: "partial" as const,
      pointer:
        `Timeline contains ${techniques.join(", ")} events${cite} that contradict this negative answer — ` +
        `review before concluding.` + (clean.pointer ? ` (was: ${clean.pointer})` : ""),
      contradicted: { techniques, eventIds },
    };
  });
}
