import { z } from "zod";
import { isValidCaseId } from "../storage/caseStore.js";

// ── Investigation snapshot (issue #56) ────────────────────────────────────────────────────────
// A portable, single-JSON bundle of a case's INVESTIGATION DATA — timeline, findings, IOCs, the
// asset graph state, analyst decisions (scope/legitimate/tags/comments/playbook) and evidence
// REFERENCES — so an investigation can be handed to a teammate on another machine WITHOUT
// re-running analysis. It carries no AI API keys, no machine-specific config, and no raw evidence
// bytes (only references): keys live in `.env` and never touch case state, and the state files
// that DO encode machine/account state are excluded by the allowlist below.
//
// This module is PURE (assembly / validation / redaction). All filesystem I/O lives in
// snapshotIo.ts so the rules here can be unit-tested without touching disk.

export const SNAPSHOT_FORMAT = "dfir-companion-snapshot" as const;
export const SNAPSHOT_VERSION = 1 as const;

// ALLOWLIST (not a denylist) of the per-case state/*.json files a snapshot carries. An allowlist
// is the safe default for an OPSEC-sensitive export: a store added later is NOT exported until it
// is deliberately added here, so nothing machine-specific leaks by accident. These are the files
// that hold investigation data + analyst decisions and are meaningful on any machine.
export const SNAPSHOT_STATE_FILES = [
  "investigation.json",     // the core: forensic timeline, findings, IOCs, MITRE, attacker path, questions, next steps
  "legitimate.json",        // analyst false-positive / known-good markers
  "scope.json",             // analyst investigation time-window
  "comments.json",          // investigator comments on entities
  "tags.json",              // analyst triage labels
  "notebook.json",          // analyst notebook (hypotheses, notes)
  "report-meta.json",       // human-authored report sections (title page, distribution, BIA, glossary…)
  "playbook.json",          // response playbook (tracked checklist)
  "playbook-control.json",  // per-case IR-templates toggle
  "asset-overrides.json",   // analyst edits to the asset ↔ IoC graph (graph state)
  "customer.json",          // customer-exposure targets (victim org domains/emails the analyst entered)
  "customer-exposure.json", // exposure summary (already password-stripped at write time)
  "synth-meta.json",        // when synthesis last ran + findings diff (investigation history)
  "import-meta.json",       // when the last import ran + timeline/IOC diff (investigation history)
  "hunt-outcomes.json",     // #157 per-case hunting profile (what was hunted, what hit/missed) — investigation data
] as const;

// Documented for intent: these state files exist but are DELIBERATELY excluded from a snapshot
// because they are machine-specific, account-specific, transient, or an OPSEC footgun. Listed so
// the exclusion reads as a decision, not an oversight (see CLAUDE.md OPSEC invariants).
export const SNAPSHOT_EXCLUDED_STATE_FILES = [
  "ai-control.json",        // transient AI runtime status (analyzing/idle/error)
  "enrich-control.json",    // external-enrichment opt-in — recipient must re-opt-in (default local-only)
  "pending_analysis.json",  // transient queue of screenshots awaiting analysis on THIS machine
  "notion-export.json",     // remote Notion page/container ids — tied to the exporter's account
  "clickup-export.json",    // remote ClickUp task ids — tied to the exporter's account
  "velo-hunt.json",         // in-flight Velociraptor hunt jobs — tied to a specific server, transient
  "anon-control.json",      // anonymization config — local to how this machine tokenizes for AI
  "anon-entities.json",
  "anon-discovered.json",
  "import-undo-stack.json", // #76 import undo/redo snapshots — machine-local convenience, large, transient
  "second-opinion.json",    // #116 second-LLM-opinion QA scratch — transient; ACCEPTED deltas already live in investigation.json
] as const;

const ALLOWED = new Set<string>(SNAPSHOT_STATE_FILES);

export interface SnapshotCaseMeta {
  caseId: string;
  name: string;
  createdAt: string;
  investigator: string;
}

// Lightweight headline counts so the dashboard can show "imported N events / M findings / K IOCs"
// without re-deriving anything from the bundled state.
export interface SnapshotCounts {
  forensicEvents: number;
  findings: number;
  iocs: number;
  captures: number;
  imports: number;
}

export interface CaseSnapshot {
  format: typeof SNAPSHOT_FORMAT;
  version: number;
  exportedAt: string;        // ISO time the snapshot was generated
  generatedBy: string;       // Companion version that produced it (informational)
  case: SnapshotCaseMeta;
  state: Record<string, unknown>;   // allowlisted state/<file> → parsed JSON
  evidence: {
    captures: unknown[];     // CaptureMetadata[] — REFERENCES only (filenames, urls, hashes); no bytes
    imports: unknown[];      // ImportMetadata[] — REFERENCES only; the raw files are not shipped
  };
  counts: SnapshotCounts;
}

export interface BuildSnapshotInput {
  caseMeta: SnapshotCaseMeta;
  state: Record<string, unknown>;   // any subset of state files; non-allowlisted entries are dropped
  captures: unknown[];
  imports: unknown[];
  exportedAt: string;
  generatedBy: string;
}

// Keep only the allowlisted state files, dropping `undefined`/absent entries. Used on BOTH export
// (never bundle a non-allowlisted file) and import (never write one back) — so this single rule is
// the trust boundary for what a snapshot may contain.
export function sanitizeSnapshotState(state: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const name of SNAPSHOT_STATE_FILES) {
    const value = state[name];
    if (value !== undefined && value !== null) out[name] = value;
  }
  return out;
}

function countFrom(state: Record<string, unknown>, captures: unknown[], imports: unknown[]): SnapshotCounts {
  const inv = state["investigation.json"];
  const arr = (obj: unknown, key: string): unknown[] => {
    if (obj && typeof obj === "object" && Array.isArray((obj as Record<string, unknown>)[key])) {
      return (obj as Record<string, unknown[]>)[key];
    }
    return [];
  };
  return {
    forensicEvents: arr(inv, "forensicTimeline").length,
    findings: arr(inv, "findings").length,
    iocs: arr(inv, "iocs").length,
    captures: captures.length,
    imports: imports.length,
  };
}

// Assemble a snapshot from already-loaded parts. Pure: the caller supplies `exportedAt` and
// `generatedBy` (no clock / package read here) so it is deterministic under test.
export function buildSnapshot(input: BuildSnapshotInput): CaseSnapshot {
  const state = sanitizeSnapshotState(input.state);
  const captures = Array.isArray(input.captures) ? input.captures : [];
  const imports = Array.isArray(input.imports) ? input.imports : [];
  return {
    format: SNAPSHOT_FORMAT,
    version: SNAPSHOT_VERSION,
    exportedAt: input.exportedAt,
    generatedBy: input.generatedBy,
    case: {
      caseId: input.caseMeta.caseId,
      name: input.caseMeta.name,
      createdAt: input.caseMeta.createdAt,
      investigator: input.caseMeta.investigator,
    },
    state,
    evidence: { captures, imports },
    counts: countFrom(state, captures, imports),
  };
}

const snapshotSchema = z.object({
  format: z.literal(SNAPSHOT_FORMAT),
  version: z.number().int().positive(),
  exportedAt: z.string().optional(),
  generatedBy: z.string().optional(),
  case: z.object({
    caseId: z.string(),
    name: z.string().optional(),
    createdAt: z.string().optional(),
    investigator: z.string().optional(),
  }),
  state: z.record(z.unknown()),
  evidence: z
    .object({ captures: z.array(z.unknown()).optional(), imports: z.array(z.unknown()).optional() })
    .optional(),
  counts: z.unknown().optional(),
});

// Validate + normalize an untrusted (uploaded) snapshot. Throws a human-readable Error on anything
// that isn't a usable snapshot, so the import route can surface a 400 with the reason. Forward-
// compatible: a snapshot from a NEWER Companion (version > ours) is rejected rather than silently
// half-imported.
export function parseSnapshot(raw: unknown): CaseSnapshot {
  const parsed = snapshotSchema.safeParse(raw);
  if (!parsed.success) {
    const looksLikeSnapshot = raw && typeof raw === "object" && "format" in (raw as object);
    if (!looksLikeSnapshot) {
      throw new Error("not a DFIR Companion snapshot (missing the snapshot envelope)");
    }
    throw new Error(`invalid snapshot: ${parsed.error.issues.map((i) => i.message).join("; ")}`);
  }
  const snap = parsed.data;
  if (snap.version > SNAPSHOT_VERSION) {
    throw new Error(
      `snapshot version ${snap.version} is newer than this Companion supports (${SNAPSHOT_VERSION}) — upgrade the Companion to import it`,
    );
  }
  if (!isValidCaseId(snap.case.caseId)) {
    throw new Error(`snapshot case id "${snap.case.caseId}" is not a valid case id`);
  }
  return {
    format: SNAPSHOT_FORMAT,
    version: snap.version,
    exportedAt: snap.exportedAt ?? "",
    generatedBy: snap.generatedBy ?? "",
    case: {
      caseId: snap.case.caseId,
      name: snap.case.name ?? snap.case.caseId,
      createdAt: snap.case.createdAt ?? "",
      investigator: snap.case.investigator ?? "unknown",
    },
    state: sanitizeSnapshotState(snap.state),
    evidence: {
      captures: snap.evidence?.captures ?? [],
      imports: snap.evidence?.imports ?? [],
    },
    counts: countFrom(sanitizeSnapshotState(snap.state), snap.evidence?.captures ?? [], snap.evidence?.imports ?? []),
  };
}

export interface PreparedImport {
  caseMeta: SnapshotCaseMeta;
  stateFiles: Array<{ filename: string; json: unknown }>;  // allowlisted only, caseId rewritten where embedded
  captures: unknown[];
  imports: unknown[];
}

// Re-point a validated snapshot at a (possibly renamed) target case id and produce the concrete
// artifacts to write. Pure: investigation.json's embedded caseId and every capture/import record's
// caseId are rewritten to the target so the imported case is internally consistent. Other state
// files are case-id-agnostic and carried through verbatim.
export function prepareImport(snapshot: CaseSnapshot, targetCaseId: string): PreparedImport {
  const state = sanitizeSnapshotState(snapshot.state);
  const stateFiles: Array<{ filename: string; json: unknown }> = [];
  for (const name of SNAPSHOT_STATE_FILES) {
    if (!ALLOWED.has(name) || state[name] === undefined) continue;
    let json = state[name];
    if (name === "investigation.json" && json && typeof json === "object") {
      json = { ...(json as Record<string, unknown>), caseId: targetCaseId };
    }
    stateFiles.push({ filename: name, json });
  }
  const rewriteCaseId = (rec: unknown): unknown =>
    rec && typeof rec === "object" ? { ...(rec as Record<string, unknown>), caseId: targetCaseId } : rec;
  return {
    caseMeta: {
      caseId: targetCaseId,
      name: snapshot.case.name,
      createdAt: snapshot.case.createdAt || new Date(0).toISOString(),
      investigator: snapshot.case.investigator,
    },
    stateFiles,
    captures: snapshot.evidence.captures.map(rewriteCaseId),
    imports: snapshot.evidence.imports.map(rewriteCaseId),
  };
}
