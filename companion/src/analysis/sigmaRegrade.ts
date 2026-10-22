// Re-grade an imported case with the current Sigma rules (#2206): the PURE half. It compares each
// stored row with the same raw record parsed again under the current rule set, and says what would
// change. It writes nothing — routes/sigmaRegrade.ts writes, and #2209 reuses this diff to preview
// a release before it is installed.
//
// A stored row is paired with a re-parsed row by its raw-record locator(s) AND its base text (the
// description without the Sigma head and without correlation notes). The ids are positional and
// cannot be used. A row whose pair is missing or reads differently is reported, never guessed.
//
// Only Sigma-derived fields change: severity, the description's Sigma head, the "Sigma rule:" and
// "Sigma note:" message lines, the Sigma ATT&CK techniques and the `sigma:` provenance token.
// The new severity is the highest of the importer's grade, the new Sigma grade and the content
// tagger's grade; it can go down. A row an analyst promoted stays in the forensic timeline.

import { SEVERITY_RANK as GATE_RANK } from "./forensicGate.js";
import { isManualId } from "./manualId.js";
import { mergedSeverity } from "./eventRevision.js";
import { splitDerivedNotes } from "./derivedNote.js";
import { PROMOTED_MARKER } from "./labIntel.js";
import type { ForensicEvent, Severity } from "./stateTypes.js";
import type { SiemEvent } from "./siemImport.js";

const SIGMA_LINE = /^Sigma (?:rule|note): /;
const RULE_LINE = /^Sigma rule: (.*) \[([^\]\s]+)\] — level (\w+)/;
const TOKEN_PREFIX = "sigma:";

/** Rule id → its ATT&CK techniques, or undefined when the rule is not known to this server. */
export type SigmaRuleMitre = (id: string) => readonly string[] | undefined;

export type RegradeKind = "changed" | "token-only" | "unchanged";

/** Why a stored row was not re-graded. */
export type UnmatchedReason = "file-missing" | "file-changed" | "no-record" | "text-differs";

/** One stored row the re-grade can rewrite: its two copies before and after. */
export interface RegradeRow {
  id: string;
  file: string;
  kind: RegradeKind;
  /** The severity the analyst sees now, and after the re-grade. */
  before: Severity;
  after: Severity;
  forensic?: { before: ForensicEvent; after: ForensicEvent };
  super?: { before: ForensicEvent; after: ForensicEvent };
  /** Not in the forensic timeline now; at or above the gate after. */
  entersForensic: boolean;
  /** In the forensic timeline now; below the gate after, and not analyst-placed. */
  leavesForensic: boolean;
  /** A counted (grouped) row: re-graded on the record that sets its identity. */
  counted: boolean;
  /** Old Sigma rule ids whose techniques are unknown here, so their techniques were kept. */
  unresolvedRules: string[];
}

export interface RegradeFileSummary {
  file: string;
  importer: string;
  rows: number;
  /** "current": every row carries the active token; "never": no row was ever graded by Sigma. */
  status: "current" | "other" | "never" | "skipped";
  reason?: UnmatchedReason;
}

export interface RegradeCounts {
  rows: number;
  raised: number;
  lowered: number;
  unchanged: number;
  changed: number;
  tokenOnly: number;
  entersForensic: number;
  leavesForensic: number;
  counted: number;
  unmatched: number;
  /** Records a rule matches now that the import did not keep as their own row. */
  notKept: number;
}

export interface RegradePlan {
  token: string;
  rows: RegradeRow[];
  files: RegradeFileSummary[];
  counts: RegradeCounts;
  unmatched: { id: string; file: string; reason: UnmatchedReason }[];
}

/** A stored row: its forensic copy, its super-timeline copy, or both. */
export interface StoredRow {
  forensic?: ForensicEvent;
  super?: ForensicEvent;
}

export interface RegradeFileInput {
  file: string;
  importer: string;
  /** The rows the import wrote from this file, by id. */
  rows: ReadonlyMap<string, StoredRow>;
  /** The file parsed again under the current rules, or why it could not be. */
  reparsed: readonly SiemEvent[] | { skipped: UnmatchedReason };
}

/** Every `sigma:` token on a row. */
export function sigmaTokensOf(e: Pick<ForensicEvent, "canonical">): string[] {
  return (e.canonical?.producer?.ruleVersions ?? []).filter((v) => v.startsWith(TOKEN_PREFIX));
}

/** The raw-record locators that identify a row's record(s), as one key. */
export function recordKey(e: Pick<ForensicEvent, "canonical">): string | undefined {
  const raw = e.canonical?.evidence?.rawRecords ?? [];
  const parts = raw.map((r) => `${r.source}|${r.locator}`).sort();
  return parts.length ? parts.join("\n") : undefined;
}

interface Overlay {
  /** The description without the Sigma head. */
  description: string;
  /** The message without the Sigma lines. */
  message: string;
  /** The Sigma lines, in order. */
  lines: string[];
  ruleIds: string[];
}

/** The Sigma overlay split off a row's text (sigmaImportGrade.applySigmaMatches writes it). */
export function splitSigmaOverlay(description: string, message: string | undefined): Overlay {
  const all = (message ?? "").split("\n");
  const lines = all.filter((l) => SIGMA_LINE.test(l));
  const rules = lines.flatMap((l) => {
    const m = RULE_LINE.exec(l);
    return m ? [{ title: m[1], id: m[2], level: m[3] }] : [];
  });
  const more = rules.length > 1 ? ` (+${rules.length - 1} more)` : "";
  const heads = rules.flatMap((r) => [
    `Sigma: ${r.title}${more} - `,
    `Sigma (${r.level}, tag only): ${r.title}${more} - `,
  ]);
  const head = heads.find((h) => description.startsWith(h));
  return {
    description: head ? description.slice(head.length) : description,
    message: all.filter((l) => !SIGMA_LINE.test(l)).join("\n"),
    lines,
    ruleIds: rules.map((r) => r.id),
  };
}

/** Two base texts read the same: equal, or one is the other cut at the 600-character cap. */
function sameBase(a: string, b: string): boolean {
  const x = a.trim();
  const y = b.trim();
  if (x === y) return true;
  const [short, long] = x.length < y.length ? [x, y] : [y, x];
  return short.length >= 40 && long.startsWith(short);
}

const uniq = <T>(xs: readonly T[]): T[] => [...new Set(xs)];

/** Analyst-placed: promoted from the super-timeline, or typed in. The forensic gate keeps these. */
export function analystPlaced(e: ForensicEvent): boolean {
  return !!e.promotedAt || (e.provenance ?? []).includes(PROMOTED_MARKER) || isManualId(e.id);
}

function capped(e: ForensicEvent): boolean {
  const lab = (e as ForensicEvent & { labSetup?: { cappedFrom?: Severity } }).labSetup;
  return !!e.buildTime?.cappedFrom || !!lab?.cappedFrom;
}

function sameList(a: readonly string[], b: readonly string[]): boolean {
  return a.length === b.length && a.every((x, i) => x === b[i]);
}

/**
 * One copy of a stored row re-graded by its re-parsed record. Undefined when the two do not read
 * the same. Never mutates; never touches `promotedAt`, `provenance` or the id.
 */
export function regradeCopy(
  stored: ForensicEvent,
  fresh: SiemEvent,
  ruleMitre: SigmaRuleMitre,
): { event: ForensicEvent; unresolved: string[] } | undefined {
  const old = splitSigmaOverlay(stored.description, stored.message);
  const now = splitSigmaOverlay(fresh.description, fresh.message);
  const notes = splitDerivedNotes(old.description).notes;
  if (!sameBase(splitDerivedNotes(old.description).base, now.description)) return undefined;
  // A build-time or lab-setup cap re-applies only at import: keep the capped grade.
  const severity = capped(stored)
    ? stored.severity
    : mergedSeverity(stored, { severity: fresh.severity }, {}).severity;
  const oldTechniques = new Set<string>();
  const unresolved: string[] = [];
  for (const id of old.ruleIds) {
    const t = ruleMitre(id);
    if (t) for (const x of t) oldTechniques.add(x);
    else unresolved.push(id);
  }
  const mitreTechniques = uniq([
    ...stored.mitreTechniques.filter((t) => !oldTechniques.has(t) || fresh.mitreTechniques.includes(t)),
    ...fresh.mitreTechniques,
  ]);
  const message = [old.message, ...now.lines].filter(Boolean).join("\n");
  // A row imported with Sigma off has a producer but no ruleVersions: it gets its first token here.
  const versions = stored.canonical?.producer?.ruleVersions ?? [];
  const canonical =
    stored.canonical?.producer && (stored.canonical.producer.ruleVersions || sigmaTokensOf(fresh).length)
      ? {
          ...stored.canonical,
          producer: {
            ...stored.canonical.producer,
            ruleVersions: [...versions.filter((v) => !v.startsWith(TOKEN_PREFIX)), ...sigmaTokensOf(fresh)],
          },
        }
      : stored.canonical;
  const description = notes ? `${fresh.description} ${notes}` : fresh.description;
  const event: ForensicEvent = {
    ...stored,
    description,
    severity,
    mitreTechniques,
    ...(message ? { message } : {}),
    ...(canonical ? { canonical } : {}),
  };
  if (!message) delete event.message;
  return { event, unresolved };
}

/** What changed between two copies of one row. */
export function regradeKind(before: ForensicEvent, after: ForensicEvent): RegradeKind {
  const visible =
    before.severity !== after.severity ||
    before.description !== after.description ||
    (before.message ?? "") !== (after.message ?? "") ||
    !sameList(before.mitreTechniques, after.mitreTechniques);
  if (visible) return "changed";
  return sameList(sigmaTokensOf(before), sigmaTokensOf(after)) ? "unchanged" : "token-only";
}

function pairFresh(rows: readonly SiemEvent[]): Map<string, SiemEvent[]> {
  const byKey = new Map<string, SiemEvent[]>();
  for (const r of rows) {
    const k = recordKey(r);
    if (!k) continue;
    byKey.set(k, [...(byKey.get(k) ?? []), r]);
  }
  return byKey;
}

/** The re-parsed row that reads like `stored`; several siblings share one locator (Entra audit). */
function findFresh(stored: ForensicEvent, candidates: readonly SiemEvent[]): SiemEvent | undefined {
  const base = splitDerivedNotes(splitSigmaOverlay(stored.description, stored.message).description).base;
  return candidates.find((c) => sameBase(base, splitSigmaOverlay(c.description, c.message).description));
}

const RANK = (s: Severity): number => GATE_RANK[s];

function planRow(
  id: string,
  file: string,
  row: StoredRow,
  fresh: SiemEvent,
  gate: Severity,
  ruleMitre: SigmaRuleMitre,
): RegradeRow | undefined {
  const f = row.forensic ? regradeCopy(row.forensic, fresh, ruleMitre) : undefined;
  const s = row.super ? regradeCopy(row.super, fresh, ruleMitre) : undefined;
  if ((row.forensic && !f) || (row.super && !s) || (!f && !s)) return undefined;
  const lead = row.forensic ?? row.super!;
  const after = (f ?? s)!.event;
  const kinds = [
    ...(f ? [regradeKind(row.forensic!, f.event)] : []),
    ...(s ? [regradeKind(row.super!, s.event)] : []),
  ];
  const kind: RegradeKind = kinds.includes("changed")
    ? "changed"
    : kinds.includes("token-only")
      ? "token-only"
      : "unchanged";
  const above = RANK(after.severity) >= RANK(gate);
  return {
    id,
    file,
    kind,
    before: lead.severity,
    after: after.severity,
    ...(f ? { forensic: { before: row.forensic!, after: f.event } } : {}),
    ...(s ? { super: { before: row.super!, after: s.event } } : {}),
    entersForensic: !row.forensic && above,
    leavesForensic: !!row.forensic && !above && !analystPlaced(row.forensic),
    counted: (lead.count ?? 1) > 1,
    unresolvedRules: uniq([...(f?.unresolved ?? []), ...(s?.unresolved ?? [])]),
  };
}

function fileStatus(rows: readonly StoredRow[], token: string): RegradeFileSummary["status"] {
  const tokens = rows.flatMap((r) => sigmaTokensOf((r.forensic ?? r.super)!));
  if (!tokens.length) return "never";
  return rows.every((r) => sigmaTokensOf((r.forensic ?? r.super)!).every((t) => t === token)) &&
    rows.every((r) => sigmaTokensOf((r.forensic ?? r.super)!).length > 0)
    ? "current"
    : "other";
}

/** Rows whose re-parsed record a rule matches but that no stored row claimed. */
function countNotKept(fresh: readonly SiemEvent[], claimed: ReadonlySet<SiemEvent>): number {
  return fresh.filter((r) => !claimed.has(r) && /(?:^|\n)Sigma rule: /.test(r.message ?? "")).length;
}

/**
 * The re-grade plan for a case: every stored row of every file, paired, re-graded and classified.
 * Rows with nothing to change are counted as unchanged and carry kind "unchanged".
 */
export function planSigmaRegrade(input: {
  files: readonly RegradeFileInput[];
  token: string;
  /** The forensic gate: rows at or above it belong in the forensic timeline. */
  gate: Severity;
  ruleMitre: SigmaRuleMitre;
}): RegradePlan {
  const rows: RegradeRow[] = [];
  const files: RegradeFileSummary[] = [];
  const unmatched: RegradePlan["unmatched"] = [];
  let notKept = 0;
  for (const f of input.files) {
    const stored = [...f.rows.entries()];
    if (!Array.isArray(f.reparsed)) {
      const reason = (f.reparsed as { skipped: UnmatchedReason }).skipped;
      for (const [id] of stored) unmatched.push({ id, file: f.file, reason });
      files.push({ file: f.file, importer: f.importer, rows: stored.length, status: "skipped", reason });
      continue;
    }
    const reparsed = f.reparsed as readonly SiemEvent[];
    const byKey = pairFresh(reparsed);
    const claimed = new Set<SiemEvent>();
    // Only rows the current rules grade: a re-parsed row without a token was never Sigma's to grade.
    const graded = stored.filter(([, r]) => {
      const k = recordKey((r.forensic ?? r.super)!);
      return !!k && (byKey.get(k) ?? []).some((c) => sigmaTokensOf(c).length > 0);
    });
    for (const [id, r] of stored) {
      const lead = (r.forensic ?? r.super)!;
      const k = recordKey(lead);
      const candidates = (k && byKey.get(k)) || [];
      if (!candidates.length) {
        if (sigmaTokensOf(lead).length) unmatched.push({ id, file: f.file, reason: "no-record" });
        continue;
      }
      const fresh = findFresh(lead, candidates);
      if (!fresh) {
        unmatched.push({ id, file: f.file, reason: "text-differs" });
        continue;
      }
      claimed.add(fresh);
      if (!sigmaTokensOf(fresh).length) continue; // a record this rule pack does not grade
      const planned = planRow(id, f.file, r, fresh, input.gate, input.ruleMitre);
      if (planned) rows.push(planned);
      else unmatched.push({ id, file: f.file, reason: "text-differs" });
    }
    notKept += countNotKept(reparsed, claimed);
    if (graded.length || stored.some(([, r]) => sigmaTokensOf((r.forensic ?? r.super)!).length))
      files.push({
        file: f.file,
        importer: f.importer,
        rows: graded.length,
        status: fileStatus(
          graded.map(([, r]) => r),
          input.token,
        ),
      });
  }
  return { token: input.token, rows, files, unmatched, counts: countPlan(rows, unmatched.length, notKept) };
}

/**
 * The row the merge restates: the re-graded copy with its correlation notes taken off, as a
 * re-import would send it — the passes put their notes back after the merge.
 */
export function regradeMergeRow(r: RegradeRow): ForensicEvent {
  const after = (r.forensic ?? r.super)!.after;
  return { ...after, description: splitDerivedNotes(after.description).base.trim() };
}

/**
 * After the merge, the fields it does not restate exactly: the merge unions ATT&CK techniques and
 * rule versions and keeps a message it is not handed, so the old Sigma techniques, lines and token
 * are replaced here. A row lifted from the super-timeline keeps its original import time. Returns
 * `e` itself when nothing differs (idempotent: rewriteRows may re-run it). Never sets `promotedAt`.
 */
export function finalizeRegradedRow(
  e: ForensicEvent,
  planned: ForensicEvent,
  lifted?: Pick<ForensicEvent, "importedAt" | "importBatchId">,
): ForensicEvent {
  const next: ForensicEvent = { ...e };
  let changed = false;
  if (!sameList(e.mitreTechniques, planned.mitreTechniques)) {
    next.mitreTechniques = [...planned.mitreTechniques];
    changed = true;
  }
  if ((e.message ?? "") !== (planned.message ?? "")) {
    if (planned.message) next.message = planned.message;
    else delete next.message;
    changed = true;
  }
  const wanted = sigmaTokensOf(planned);
  if (e.canonical?.producer && !sameList(sigmaTokensOf(e), wanted)) {
    const versions = e.canonical.producer.ruleVersions ?? [];
    next.canonical = {
      ...e.canonical,
      producer: {
        ...e.canonical.producer,
        ruleVersions: [...versions.filter((v) => !v.startsWith(TOKEN_PREFIX)), ...wanted],
      },
    };
    changed = true;
  }
  if (lifted?.importedAt && !e.importedAt) {
    next.importedAt = lifted.importedAt;
    if (lifted.importBatchId) next.importBatchId = lifted.importBatchId;
    changed = true;
  }
  return changed ? next : e;
}

function countPlan(rows: readonly RegradeRow[], unmatched: number, notKept: number): RegradeCounts {
  const by = (p: (r: RegradeRow) => boolean) => rows.filter(p).length;
  return {
    rows: rows.length,
    raised: by((r) => RANK(r.after) > RANK(r.before)),
    lowered: by((r) => RANK(r.after) < RANK(r.before)),
    unchanged: by((r) => r.after === r.before),
    changed: by((r) => r.kind === "changed"),
    tokenOnly: by((r) => r.kind === "token-only"),
    entersForensic: by((r) => r.entersForensic),
    leavesForensic: by((r) => r.leavesForensic),
    counted: by((r) => r.counted),
    unmatched,
    notKept,
  };
}
