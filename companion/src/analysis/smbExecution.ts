// Two joins for #933 item 4's correlation half (#1092), on top of the SMB operation rows #1085
// built: a share write of an executable-shaped file, then the evidence it ran; a service-control or
// task-scheduling pipe call, then the service/task it may have created. Both are merge-time passes
// over the forensic timeline, like `downloadExecution.ts` (#985) — the same family of "a file
// appeared through some channel, did it run?" problem, for SMB instead of a download mark.
//
// Neither join ever concludes lateral movement or execution from a share write or a pipe open
// alone (#933 item 4's own guardrail): only an independently-corroborated match raises anything,
// and the wording never claims more than the records show — a pipe CREATE is a successful open,
// never "an RPC call happened."
//
// Cross-import limitation, same as #985's own accepted tradeoff: SMB rows are Info-severity, and
// this codebase demotes Info events out of the forensic timeline case-wide after every import
// settles. If the write and its corroborating evidence land in separate imports, whichever lands
// first may already be demoted by the time the second import's merge runs, and nothing matches.
// `downloadExecution.ts`'s own header names this same limitation — not something this pass invents
// or is scoped to fix.
//
// Host attribution is more conservative than #985's own fallback: an SMB row's identity is a
// destination IP, not a collection-host name — a different namespace from the `asset` field every
// host-collected artifact carries. A match with no established host identity between the two sides
// still surfaces (the file/service identity is real evidence), but the note discloses the gap and
// the severity raise is capped at Medium, never High.

import type { Severity } from "./stateTypes.js";
import { worstSeverity } from "./stateTypes.js";
import { appendDerivedNote, splitDerivedNotes } from "./derivedNote.js";
import { filePath, hashVeto, sameHash, sameLocation, type FilePath } from "./downloadExecution.js";

// The timeline layer may not import the ingest layer (ARCHITECTURE.md — the same rule
// downloadExecution.ts's own header names), so the executable-extension list stagingPaths.ts
// owns is restated here and pinned against the original in tests/analysis/smbExecution.test.ts.
export const STAGING_EXT =
  "exe|dll|com|bat|cmd|ps1|vbs|vbe|js|jse|wsf|wsh|msi|scr|cpl|ocx|sys|drv|hta|jar|py|pyw|msc|lnk";

// ───────────────────────────── shapes ─────────────────────────────

interface SmbCanonical {
  command?: string;
  status?: string;
  outcome?: string;
  shareType?: string;
  share?: string;
}

interface TimelineEventShape {
  description?: string;
  asset?: string;
  severity?: Severity;
  mitreTechniques?: string[];
  path?: string;
  sha256?: string;
  md5?: string;
  sources?: string[];
  timestamp?: string;
  canonical?: { event?: { category?: string; type?: string }; smb?: SmbCanonical };
}

const hostOf = (e: TimelineEventShape): string => (e.asset ?? "").trim().toLowerCase();

const ms = (iso: string | undefined): number | null => {
  if (!iso) return null;
  const t = Date.parse(iso);
  return Number.isFinite(t) ? t : null;
};

/** A match inside this window of the anchor has no established order — same tolerance as #985. */
export const ORDER_TOLERANCE_MS = 2000;
/** Records indexed per path/hash bucket; the rest are counted, never read. */
const BUCKET_MAX = 64;
/** Matches named on one row's note; the rest are counted as "+N more". */
const NAMED_MAX = 8;
const NOTE_MAX = 900;
const EXCERPT_MAX = 200;

const neutral = (t: string): string =>
  t
    .replace(/\[/g, "(")
    .replace(/\]/g, ")")
    .replace(/[\u0000-\u001f\u007f-\u009f]/g, " ")
    .replace(/\s+/g, " ")
    .replace(/[a-f0-9]{32,}/gi, (m) => `${m.slice(0, 8)}…${m.slice(-4)}`)
    .trim();
const excerpt = (s: string): string => neutral(s).slice(0, EXCERPT_MAX);
const clipNote = (s: string): string => (s.length > NOTE_MAX ? `${s.slice(0, NOTE_MAX - 1)}…` : s);

function gapWords(gapMs: number): string {
  const s = Math.round(Math.abs(gapMs) / 1000);
  if (s < 60) return `${s} s`;
  if (s < 3600) return `${Math.round(s / 60)} min`;
  if (s < 86_400) return `${Math.round(s / 3600)} h`;
  return `${Math.round(s / 86_400)} d`;
}

// ───────────────────────────── markers ─────────────────────────────

export const SMB_WRITE_EXECUTED_MARKER = "[smb-staged file executed:";
export const RAN_SMB_STAGED_MARKER = "[ran a share-staged file:";
export const PIPE_CALL_CORROBORATED_MARKER = "[service/task creation after a pipe call:";
export const SERVICE_TASK_FROM_PIPE_MARKER = "[preceded by a service-control pipe call:";
const OWN_MARKERS = [
  SMB_WRITE_EXECUTED_MARKER,
  RAN_SMB_STAGED_MARKER,
  PIPE_CALL_CORROBORATED_MARKER,
  SERVICE_TASK_FROM_PIPE_MARKER,
];
const OWN_NOTE_NAMES = OWN_MARKERS.map((m) => m.slice(1, -1));

function withoutOwnNotes(description: string | undefined): string {
  const { base, notes } = splitDerivedNotes(description);
  if (!notes) return base;
  const kept = notes.replace(
    new RegExp(
      `\\s*\\[(?:${OWN_NOTE_NAMES.map((n) => n.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("|")}):[\\s\\S]{0,1200}?\\]`,
      "gu",
    ),
    "",
  );
  return [base, kept.trim()].filter(Boolean).join(" ");
}

// ───────────────────────────── join A: staged write → execution ─────────────────────────────

const STAGING_EXT_RE = new RegExp(`\\.(?:${STAGING_EXT})$`, "i");

/**
 * A CREATE that confirmedly opened a NEW or overwritten object, or a WRITE that itself succeeded
 * — never an existing-file open, an ambiguous `_IF` disposition, a denial, or an unknown outcome —
 * naming a target whose extension is executable-shaped. #933 item 4's own guardrail: an existing
 * file being opened, or a request that failed, stages nothing.
 */
export function isSmbStagedWrite(e: TimelineEventShape): boolean {
  const smb = e.canonical?.smb;
  if (!smb) return false;
  if (e.canonical?.event?.category !== "network" || e.canonical.event.type !== "smb") return false;
  if (smb.shareType && smb.shareType.toUpperCase() !== "FILE") return false; // PIPE is join B's job
  const cmd = (smb.command ?? "").toUpperCase();
  if (cmd.includes("CREATE")) {
    if (smb.outcome !== "created-new" && smb.outcome !== "overwritten-existing") return false;
  } else if (cmd.includes("WRITE")) {
    if ((smb.status ?? "").toUpperCase() !== "STATUS_SUCCESS") return false;
  } else {
    return false;
  }
  return STAGING_EXT_RE.test(e.path ?? "");
}

/**
 * A share resolves to a local path only for the well-known admin shares — a drive-letter share
 * (`C$`) or `ADMIN$` (assumed `%SystemRoot%`, the default on the overwhelming majority of real
 * installs). Any other share name (a custom distribution share, `IPC$`, …) gets NO path-based
 * claim: an ordinary share has no fixed local mount point this pass can assume, so only a hash
 * match can corroborate a write to it — never a basename/path guess.
 */
export function resolveShareToLocal(share: string | undefined, relative: string): FilePath | null {
  const s = (share ?? "").trim().toUpperCase();
  const driveShare = /^([A-Z])\$$/.exec(s);
  if (driveShare) return filePath(`${driveShare[1]}:\\${relative}`);
  if (s === "ADMIN$") return filePath(`C:\\Windows\\${relative}`);
  return null;
}

/** A share resolves to a genuine admin share (drive-letter `X$` or `ADMIN$`) — T1021.002 territory. */
function isAdminShare(share: string | undefined): boolean {
  const s = (share ?? "").trim().toUpperCase();
  return /^[A-Z]\$$/.test(s) || s === "ADMIN$";
}

function isExecutionEvidence(e: TimelineEventShape): "process" | "service" | null {
  if (e.canonical?.event?.category === "process" && e.canonical.event.type === "start") return "process";
  const src = (e.sources ?? []).join(" ");
  if (/Prefetch/i.test(src)) return "process";
  if (/Amcache|ShimCache/i.test(src)) return null; // presence only, never a match target on its own
  // A service-creation event (4697/7045) names its own binary in `path` (siemImport.ts:791) —
  // matching it here is #933 item 4's "remote-service... evidence when available", independent of
  // any pipe call. `(EID 4697)` / `(EID 7045)` are the literal event ids siemImport.ts's generic
  // Windows-event description always carries (`${tool} ${def.label} (EID ${eid})`).
  if (e.canonical?.event?.category === "service" || /\(EID (4697|7045)\)/.test(e.description ?? ""))
    return "service";
  return null;
}

interface Bucket {
  records: TimelineEventShape[];
  beyond: number;
}
function addToBucket(map: Map<string, Bucket>, key: string, r: TimelineEventShape): void {
  const b = map.get(key) ?? map.set(key, { records: [], beyond: 0 }).get(key)!;
  if (b.records.length < BUCKET_MAX) b.records.push(r);
  else b.beyond += 1;
}

interface WriteMatch {
  record: TimelineEventShape;
  by: "path" | "hash";
  hostEstablished: boolean;
}

function candidatesForWrite(
  write: TimelineEventShape,
  writeFile: FilePath | null,
  byPath: Map<string, Bucket>,
  byHash: Map<string, Bucket>,
): { matches: WriteMatch[]; reused: number } {
  let reused = 0;
  const eligible: Omit<WriteMatch, "hostEstablished">[] = [];
  const seen = new Set<TimelineEventShape>();
  if (writeFile) {
    for (const r of byPath.get(writeFile.relative)?.records ?? []) {
      if (seen.has(r)) continue;
      const loc = sameLocation(writeFile, filePath(r.path ?? "") ?? writeFile);
      if (!loc.same) continue;
      if (hashVeto(write, r)) {
        reused += 1;
        continue;
      }
      seen.add(r);
      eligible.push({ record: r, by: "path" });
    }
  }
  for (const h of [write.sha256, write.md5].filter((x): x is string => !!x)) {
    for (const r of byHash.get(h.toLowerCase())?.records ?? []) {
      if (seen.has(r) || hashVeto(write, r) || !sameHash(write, r)) continue;
      seen.add(r);
      eligible.push({ record: r, by: "hash" });
    }
  }
  const writeHost = hostOf(write);
  const matches: WriteMatch[] = [];
  for (const m of eligible) {
    const rHost = hostOf(m.record);
    if (writeHost && rHost && writeHost !== rHost) continue; // named hosts disagree — excluded
    matches.push({ ...m, hostEstablished: !!writeHost && !!rHost && writeHost === rHost });
  }
  matches.sort((a, b) => (a.record.timestamp ?? "").localeCompare(b.record.timestamp ?? ""));
  return { matches, reused };
}

// ───────────────────────────── join B: pipe call → service/task creation ─────────────────────────

const SERVICE_PIPES = /\\pipe\\svcctl$/i;
const TASK_PIPES = /\\pipe\\atsvc$/i;
/** No claim beyond this window — a routine pipe open hours before an unrelated install never matches. */
const PIPE_WINDOW_MS = 15 * 60 * 1000;

function pipeName(e: TimelineEventShape): string | undefined {
  const smb = e.canonical?.smb;
  return smb?.share; // #1085 reads a pipe's name into `share`; verify against a real sample (PLAN-1092 open question 1)
}

export function isRpcPipeCall(e: TimelineEventShape): "service" | "task" | null {
  const smb = e.canonical?.smb;
  if (!smb || e.canonical?.event?.category !== "network" || e.canonical.event.type !== "smb") return null;
  if ((smb.shareType ?? "").toUpperCase() !== "PIPE") return null;
  if ((smb.command ?? "").toUpperCase() !== "SMB2_COMMAND_CREATE" && (smb.command ?? "") !== "CREATE")
    return null;
  if (smb.status && smb.status.toUpperCase() !== "STATUS_SUCCESS") return null;
  const name = pipeName(e) ?? "";
  if (SERVICE_PIPES.test(name)) return "service";
  if (TASK_PIPES.test(name)) return "task";
  return null;
}

/**
 * A service-installed (4697/7045) or a scheduled-task-CREATED (4698 specifically — never
 * 4699/4700/4702, deleted/enabled/updated) event, by the literal event id siemImport.ts's
 * description always carries.
 */
export function isServiceOrTaskCreation(e: TimelineEventShape): "service" | "task" | null {
  const desc = e.description ?? "";
  if (/\(EID (4697|7045)\)/.test(desc)) return "service";
  if (/\(EID 4698\)/.test(desc)) return "task";
  return null;
}

interface PipeMatch {
  record: TimelineEventShape;
  hostEstablished: boolean;
}

function candidatesForPipe(
  pipe: TimelineEventShape,
  kind: "service" | "task",
  targets: readonly TimelineEventShape[],
): PipeMatch[] {
  const anchor = ms(pipe.timestamp);
  const pipeHost = hostOf(pipe);
  const out: PipeMatch[] = [];
  for (const t of targets) {
    if (isServiceOrTaskCreation(t) !== kind) continue;
    const at = ms(t.timestamp);
    if (anchor === null || at === null) continue;
    const gap = at - anchor;
    if (gap < 0 || gap > PIPE_WINDOW_MS) continue; // strictly after, within the bounded window
    const tHost = hostOf(t);
    if (pipeHost && tHost && pipeHost !== tHost) continue;
    out.push({ record: t, hostEstablished: !!pipeHost && !!tHost && pipeHost === tHost });
  }
  out.sort((a, b) => (a.record.timestamp ?? "").localeCompare(b.record.timestamp ?? ""));
  return out;
}

// ───────────────────────────── the pass ─────────────────────────────

/**
 * Corroborate every SMB staged write with the execution evidence for the same file, and every
 * RPC-service/task pipe call with the service/task creation it may have preceded. Only ever
 * raises; recomputes its own notes from the current evidence on every merge.
 */
export function corroborateSmbExecution<T extends TimelineEventShape>(events: readonly T[]): T[] {
  const writes = events.filter(isSmbStagedWrite);
  const pipes = events.filter((e) => isRpcPipeCall(e) !== null);
  if (!writes.length && !pipes.length) {
    return events.map((e) => {
      const description = withoutOwnNotes(e.description);
      return description === (e.description ?? "") ? e : { ...e, description };
    });
  }

  // Join A indices: every OTHER event that is execution evidence, by path and by hash.
  const byPath = new Map<string, Bucket>();
  const byHash = new Map<string, Bucket>();
  for (const e of events) {
    if (isSmbStagedWrite(e) || !isExecutionEvidence(e)) continue;
    const f = filePath(e.path ?? "");
    if (f) addToBucket(byPath, f.relative, e);
    for (const h of [e.sha256, e.md5]) if (h) addToBucket(byHash, h.toLowerCase(), e);
  }

  const writeNotes = new Map<T, string>();
  const writeSeverity = new Map<T, Severity>();
  const executionNotes = new Map<T, { rows: string[]; more: number }>();
  for (const w of writes) {
    const smb = w.canonical?.smb;
    const writeFile = resolveShareToLocal(smb?.share, w.path ?? "");
    const { matches, reused } = candidatesForWrite(w, writeFile, byPath, byHash);
    const anchor = ms(w.timestamp);
    const after = (m: WriteMatch) => {
      const t = ms(m.record.timestamp);
      return t !== null && anchor !== null && t - anchor > ORDER_TOLERANCE_MS;
    };
    // A hash-mismatch disclosure with no actual candidate is not worth a note on its own — there is
    // nothing for it to qualify. Only a real candidate (matched or merely un-ordered) is shown.
    if (!matches.length) continue;
    const named: string[] = [];
    for (const m of matches) {
      if (named.length >= NAMED_MAX) break;
      const t = ms(m.record.timestamp);
      const order =
        anchor === null || t === null
          ? "order not established (no readable time)"
          : Math.abs(t - anchor) <= ORDER_TOLERANCE_MS
            ? `order not established (within ${ORDER_TOLERANCE_MS / 1000} s)`
            : t > anchor
              ? `${gapWords(t - anchor)} after`
              : `${gapWords(t - anchor)} before`;
      const hostNote = m.hostEstablished ? "" : "; host identity not established between the two records";
      named.push(`${excerpt(m.record.path ?? "")} (${m.by}, ${order}${hostNote})`);
    }
    const tail: string[] = [];
    if (matches.length > named.length) tail.push(`+${matches.length - named.length} more`);
    if (reused) tail.push(`path reused: ${reused} record(s)' hash differs — not the same file`);
    writeNotes.set(w, clipNote([...named, ...tail].join("; ")));
    const confirmed = matches.filter(after);
    if (confirmed.length) {
      // High only when at least one confirmed match's host identity is established; a
      // network(IP)-to-host(collected-asset) join with no established identity is genuinely less
      // certain than two host-collected artifacts agreeing on a name, so it's capped at Medium.
      writeSeverity.set(w, confirmed.some((m) => m.hostEstablished) ? "High" : "Medium");
    }
    for (const m of confirmed) {
      const c = executionNotes.get(m.record as T) ?? { rows: [], more: 0 };
      if (c.rows.length < NAMED_MAX)
        c.rows.push(`${excerpt(w.path ?? "")}${m.hostEstablished ? "" : " (host not established)"}`);
      else c.more += 1;
      executionNotes.set(m.record as T, c);
    }
  }

  // Join B: pipeNotes/pipeSeverity key the PIPE row's own note ("followed by a creation");
  // targetNotes keys the service/task row's note ("preceded by a pipe call").
  const pipeNotes = new Map<T, string>();
  const pipeSeverity = new Map<T, Severity>();
  const targetNotes = new Map<T, { rows: string[]; more: number }>();
  for (const p of pipes) {
    const kind = isRpcPipeCall(p);
    if (!kind) continue;
    const matches = candidatesForPipe(p, kind, events);
    if (!matches.length) continue;
    const named = matches.slice(0, NAMED_MAX).map((m) => {
      const hostNote = m.hostEstablished ? "" : "; host identity not established";
      return `${excerpt(m.record.description ?? "")} (${gapWords(ms(m.record.timestamp)! - ms(p.timestamp)!)} after${hostNote})`;
    });
    const more = matches.length > NAMED_MAX ? [`+${matches.length - NAMED_MAX} more`] : [];
    pipeNotes.set(p, clipNote([...named, ...more].join("; ")));
    pipeSeverity.set(p, matches.some((m) => m.hostEstablished) ? "High" : "Medium");
    for (const m of matches) {
      const c = targetNotes.get(m.record as T) ?? { rows: [], more: 0 };
      if (c.rows.length < NAMED_MAX) c.rows.push(excerpt(p.description ?? ""));
      else c.more += 1;
      targetNotes.set(m.record as T, c);
    }
  }

  return events.map((e) => {
    const base = withoutOwnNotes(e.description);
    let description = base;
    let severity = e.severity ?? "Info";

    const wNote = writeNotes.get(e);
    if (wNote !== undefined) {
      description = appendDerivedNote(description, SMB_WRITE_EXECUTED_MARKER, wNote);
      const raiseTo = writeSeverity.get(e);
      if (raiseTo) severity = worstSeverity(severity, raiseTo);
    }
    const eNote = executionNotes.get(e);
    if (eNote) {
      const words = [...eNote.rows, ...(eNote.more ? [`+${eNote.more} more`] : [])].join("; ");
      description = appendDerivedNote(description, RAN_SMB_STAGED_MARKER, clipNote(words));
      severity = worstSeverity(severity, "Medium");
    }
    const pNote = pipeNotes.get(e);
    if (pNote !== undefined) {
      description = appendDerivedNote(description, PIPE_CALL_CORROBORATED_MARKER, pNote);
      const raiseTo = pipeSeverity.get(e);
      if (raiseTo) severity = worstSeverity(severity, raiseTo);
    }
    const tNote = targetNotes.get(e);
    if (tNote) {
      const words = [...tNote.rows, ...(tNote.more ? [`+${tNote.more} more`] : [])].join("; ");
      description = appendDerivedNote(description, SERVICE_TASK_FROM_PIPE_MARKER, clipNote(words));
      severity = worstSeverity(severity, "Medium");
    }

    if (description === (e.description ?? "") && severity === (e.severity ?? "Info")) return e;
    const mitre = [...(e.mitreTechniques ?? [])];
    if (wNote !== undefined && severity !== "Info") {
      const tech = isAdminShare(e.canonical?.smb?.share) ? "T1021.002" : "T1570";
      if (!mitre.includes(tech)) mitre.push(tech);
    }
    return { ...e, description, severity, ...(mitre.length ? { mitreTechniques: mitre } : {}) };
  });
}
