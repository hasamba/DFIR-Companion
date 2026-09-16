// What a memory "handles" plugin table establishes about object ownership (#933 item 13). See
// RECOMMENDATION-933.13.md for the full design rationale, including the 2 High findings a Codex
// adversarial design review round found in the first draft (a PID-reuse correlation bug, and
// output that was not actually bounded) and how each was fixed.
//
// classify() in memoryImport.ts already recognizes a "handles" plugin table; the dispatch has
// always been `case "handle": break` — every row silently dropped. This module is what makes that
// category produce anything, and it deliberately produces very little: a process can hold
// thousands of ordinary File/Key/Event handles, and flooding the timeline with them would bury
// the four shapes actually worth an analyst's attention (mirrors cloudBulkRead.ts's own "ONE
// summary, not ten thousand rows" precedent).
//
// ─────────────────────────── REUSED, NOT REINVENTED ───────────────────────────
//
// Correlating a handle's own holder PID against the upload's own process rows is the IDENTICAL
// problem memoryNetObjects.ts (#933 item 14) already solved for socket ownership: PIDs are
// reused, a submitted PID can have zero, one, or several candidate process records, and only
// "exactly one, and it agrees" is ever treated as resolved. `ProcessIndex`/`indexProcessRows()`/
// `canonicalOffset()` are reused here verbatim — a second, weaker copy of the same correlation
// logic is exactly the kind of mistake this session's own "sibling file, not a variant" default
// exists to avoid repeating when the shared piece is already genuinely domain-blind.
//
// ─────────────────────────── REFERENCE VS. USE ───────────────────────────
//
// A handle row states that a process HOLDS A REFERENCE to an object with some GRANTED ACCESS
// bits. It does not state the process ever read, wrote, or otherwise exercised that access — a
// browser that opens a file handle and never reads it looks identical in this data to one that
// read every byte. Every note below says "reference"/"granted", never "used," and GrantedAccess
// is reported as the raw value Volatility rendered — decoding it into named rights depends on the
// object type AND the Windows version, neither of which this module has verified against a real,
// current source, so it is not attempted.

import { getCI, baseName } from "./siemImport.js";
import { cellStr, isPlaceholderCell } from "./memoryFields.js";
import { shown, canonicalOffset, type ProcessIndex } from "./memoryNetObjects.js";

type Row = Record<string, unknown>;

export type HandleFactKind =
  "cross-process-access" | "shared-object" | "residual-handle" | "unconfirmed-process";

export interface HandleOwnershipFact {
  kind: HandleFactKind;
  pid: string;
  holderProcess: string;
  type: string;
  name: string;
  /** The raw value Volatility rendered — never decoded into named access rights. */
  grantedAccess: string;
  /** "shared-object" only: every OTHER pid holding a handle to the same object, capped. */
  sharedWith?: string[];
  /** "cross-process-access" only: the target process's own identity, read from the handle row's
   * own embedded name — never independently re-resolved against the process tables. */
  targetPid?: string;
  targetProcess?: string;
  note: string;
}

export interface HandleOwnershipResult {
  facts: HandleOwnershipFact[];
  /** True when the upload submitted no process rows at all — one coverage note stands in for what
   * would otherwise be an "unconfirmed-process" fact on every single handle row. */
  noProcessTablesSubmitted: boolean;
  /** True when any per-kind cap below was reached — the result is a sample, not the full set. */
  truncated: boolean;
}

const MAX_FACTS_PER_KIND = 50;
const MAX_SHARED_WITH_SHOWN = 10;

// The plugin renders a Type="Process" handle's own Name as "<ImageFileName> Pid <UniqueProcessId>"
// (confirmed against Volatility 3's own real source, windows/handles.py, 2026-09-16). Anchored to
// the END of the string — an unanchored `Pid (\d+)` could otherwise match an attacker-chosen
// substring earlier in a crafted image name (Codex code-review finding M1 on the design review).
const TARGET_PID_RE = /\sPid\s+([0-9]{1,10})\s*$/;

// A real Windows PID never exceeds a 32-bit value (10 decimal digits) — a longer digit string is
// not a PID this module can trust, and bounding it here keeps every downstream field (and the
// aggregation key built from it) bounded too (Codex code-review finding M1).
function pidOf(row: Row): string {
  const s = cellStr(getCI(row, "PID") ?? getCI(row, "Pid") ?? getCI(row, "pid")).trim();
  return /^\d{1,10}$/.test(s) ? s : "";
}

function cell(row: Row, keys: readonly string[]): string {
  for (const k of keys) {
    const s = cellStr(getCI(row, k)).trim();
    if (s && !isPlaceholderCell(s)) return s;
  }
  return "";
}

function normalizedPid(raw: string): string {
  // Strips leading zeros so "007" and "7" compare equal — a decimal PID has no other spelling.
  return raw.replace(/^0+(?=\d)/, "");
}

interface ParsedHandle {
  pid: string;
  holderProcess: string;
  type: string;
  name: string;
  grantedAccess: string;
  offset: string;
  targetPid?: string;
  targetProcess?: string;
}

function parseHandleRow(row: Row): ParsedHandle | null {
  const pid = pidOf(row);
  if (!pid) return null;
  const type = cell(row, ["Type", "type"]);
  const name = cell(row, ["Name", "name"]);
  const holderProcess = cell(row, ["Process", "process", "ImageFileName"]);
  const grantedAccess = cell(row, ["GrantedAccess", "granted_access", "Access", "access"]);
  const offset = canonicalOffset(row);

  let targetPid: string | undefined;
  let targetProcess: string | undefined;
  if (/^process$/i.test(type) && name) {
    const m = TARGET_PID_RE.exec(name);
    if (m) {
      const parsedTarget = normalizedPid(m[1]);
      if (parsedTarget && parsedTarget !== normalizedPid(pid)) {
        targetPid = parsedTarget;
        targetProcess = baseName(name.slice(0, m.index).trim());
      }
    }
    // A missing, duplicated, or malformed suffix means "target not readable" — no guess is made.
  }

  return { pid, holderProcess, type, name, grantedAccess, offset, targetPid, targetProcess };
}

export function handleOwnershipFacts(
  handleRows: readonly Row[],
  processIndex: ProcessIndex,
): HandleOwnershipResult {
  const parsed = handleRows.map(parseHandleRow).filter((h): h is ParsedHandle => h !== null);

  if (!processIndex.any) {
    // Every single row would otherwise resolve to "unconfirmed" — one honest coverage note beats
    // flooding the result with a copy of the same fact per handle row (Codex finding H2).
    const pids = new Set(parsed.map((h) => h.pid));
    const crossProcess = buildCrossProcessFacts(parsed);
    const shared = buildSharedObjectFacts(parsed);
    const facts = [...crossProcess.facts, ...shared.facts];
    if (pids.size > 0) {
      facts.push({
        kind: "unconfirmed-process",
        pid: "",
        holderProcess: "",
        type: "",
        name: "",
        grantedAccess: "",
        note: `no process rows were submitted in this upload at all — the process identity and lifetime of every one of the ${pids.size} distinct PID(s) named in this handle table are unconfirmed from this upload's own tables.`,
      });
    }
    return {
      facts,
      noProcessTablesSubmitted: true,
      truncated: crossProcess.truncated || shared.truncated,
    };
  }

  const byPid = new Map<string, ParsedHandle[]>();
  for (const h of parsed) {
    const list = byPid.get(h.pid) ?? [];
    list.push(h);
    byPid.set(h.pid, list);
  }

  const facts: HandleOwnershipFact[] = [];
  let truncated = false;

  for (const [pid, handles] of byPid) {
    if (
      facts.filter((f) => f.kind === "residual-handle" || f.kind === "unconfirmed-process").length >=
      MAX_FACTS_PER_KIND
    ) {
      truncated = true;
      break;
    }
    const candidates = processIndex.byPid.get(pid) ?? [];
    const head = handles[0];
    if (candidates.length === 0) {
      facts.push({
        kind: "unconfirmed-process",
        pid,
        holderProcess: shown(head.holderProcess),
        type: "",
        name: "",
        grantedAccess: "",
        note: `no submitted process row has PID ${pid} — this upload's own ${handles.length} handle-table row(s) for it have an unconfirmed process identity and lifetime.`,
      });
      continue;
    }
    if (candidates.length > 1) {
      facts.push({
        kind: "unconfirmed-process",
        pid,
        holderProcess: shown(head.holderProcess),
        type: "",
        name: "",
        grantedAccess: "",
        note: `ambiguous: ${candidates.length} distinct submitted process rows have PID ${pid} — this upload's own ${handles.length} handle-table row(s) for it cannot be scoped to one process lifetime.`,
      });
      continue;
    }
    const [candidate] = candidates;
    // A resolved PID whose OWN name disagrees with the handle row's own holder name is not
    // resolved at all — it is the PID-reuse case the ambiguity check above cannot see when the
    // upload happens to submit only one (stale) process row for a PID a later process reused
    // (Codex code-review finding H1).
    const candidateName = candidate.name.trim();
    const holderName = baseName(head.holderProcess).trim();
    if (candidateName && holderName && candidateName.toLowerCase() !== holderName.toLowerCase()) {
      facts.push({
        kind: "unconfirmed-process",
        pid,
        holderProcess: shown(head.holderProcess),
        type: "",
        name: "",
        grantedAccess: "",
        note: `conflict: this upload's own submitted process row for PID ${pid} names it ${shown(candidateName)}, but its own handle-table row(s) for PID ${pid} name the holder ${shown(holderName)} — likely PID reuse, so neither identity is trusted for this PID.`,
      });
      continue;
    }
    if (candidate.exited.status === "ok") {
      facts.push({
        kind: "residual-handle",
        pid,
        holderProcess: shown(candidate.name || head.holderProcess),
        type: "",
        name: "",
        grantedAccess: "",
        note: `this upload's own submitted process row for PID ${pid} (${shown(candidate.name || "unnamed")}) records an exit — a handle-table row was still recovered for it. This does not establish that the handle was used after exit, only that both were reported in this upload.`,
      });
    }
  }

  const crossProcess = buildCrossProcessFacts(parsed);
  const shared = buildSharedObjectFacts(parsed);
  facts.push(...crossProcess.facts, ...shared.facts);
  truncated = truncated || crossProcess.truncated || shared.truncated;

  return { facts, noProcessTablesSubmitted: false, truncated };
}

function buildCrossProcessFacts(parsed: readonly ParsedHandle[]): {
  facts: HandleOwnershipFact[];
  truncated: boolean;
} {
  const facts: HandleOwnershipFact[] = [];
  const seen = new Set<string>();
  let truncated = false;
  for (const h of parsed) {
    if (!h.targetPid) continue;
    const key = `${h.pid}|${h.targetPid}`;
    if (seen.has(key)) continue;
    seen.add(key);
    if (facts.length >= MAX_FACTS_PER_KIND) {
      truncated = true;
      break;
    }
    facts.push({
      kind: "cross-process-access",
      pid: h.pid,
      holderProcess: shown(h.holderProcess),
      type: shown(h.type),
      name: shown(h.name),
      grantedAccess: shown(h.grantedAccess),
      targetPid: h.targetPid,
      targetProcess: h.targetProcess ? shown(h.targetProcess) : undefined,
      note: `process ${shown(h.holderProcess) || h.pid} (PID ${h.pid}) holds an open handle to process ${h.targetProcess ? shown(h.targetProcess) : "?"} (PID ${h.targetPid}), with granted access ${shown(h.grantedAccess) || "not recorded"}. This is a reference the process was granted, not evidence the access was exercised.`,
    });
  }
  return { facts, truncated };
}

// canonicalOffset() falls back to returning malformed, non-hex text verbatim (lowercased) when a
// row's own Offset cell fails every recognized shape — that fallback is fine for DISPLAY but not
// for identity: two rows both carrying the same unparsed garbage (or two different plugins'
// distinct malformed strings that happen to collide once type is joined onto them with a plain
// delimiter) would otherwise correlate as "the same object" (Codex code-review finding M2/M3).
// Only a canonicalOffset() result that is PURE lowercase hex — the shape every successful branch
// of that function actually produces — is trusted as a join key here.
const VALID_CANONICAL_OFFSET_RE = /^[0-9a-f]+$/;

function buildSharedObjectFacts(parsed: readonly ParsedHandle[]): {
  facts: HandleOwnershipFact[];
  truncated: boolean;
} {
  const byObject = new Map<
    string,
    { type: string; name: string; grantedAccess: string; pids: Set<string> }
  >();
  for (const h of parsed) {
    if (!VALID_CANONICAL_OFFSET_RE.test(h.offset)) continue;
    const key = JSON.stringify([h.type.toLowerCase(), h.offset]); // structured — never delimiter-collision-prone
    const entry = byObject.get(key) ?? {
      type: h.type,
      name: h.name,
      grantedAccess: h.grantedAccess,
      pids: new Set(),
    };
    entry.pids.add(h.pid);
    byObject.set(key, entry);
  }
  const facts: HandleOwnershipFact[] = [];
  let truncated = false;
  for (const entry of byObject.values()) {
    if (entry.pids.size < 2) continue;
    if (facts.length >= MAX_FACTS_PER_KIND) {
      truncated = true;
      break;
    }
    const pids = [...entry.pids].sort((a, b) => Number(a) - Number(b));
    const shownPids = pids.slice(0, MAX_SHARED_WITH_SHOWN);
    const more = pids.length - shownPids.length;
    facts.push({
      kind: "shared-object",
      pid: shownPids[0],
      holderProcess: "",
      type: shown(entry.type),
      name: shown(entry.name),
      grantedAccess: shown(entry.grantedAccess),
      sharedWith: more > 0 ? [...shownPids, `+${more} more`] : shownPids,
      note: `${pids.length} distinct processes in this upload hold a handle to the same ${shown(entry.type) || "object"} (identity within this submitted snapshot only — an address can be reused across time, a smeared capture, or recovered structures): PIDs ${shownPids.join(", ")}${more > 0 ? ` and ${more} more` : ""}. This does not establish creation order, continued validity, or activity.`,
    });
  }
  return { facts, truncated };
}
