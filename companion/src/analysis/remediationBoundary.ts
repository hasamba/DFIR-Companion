import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { randomUUID } from "node:crypto";
import { z } from "zod";
import type { CaseStore } from "../storage/caseStore.js";
import { atomicWrite } from "../storage/atomicWrite.js";
import { StateLock } from "./stateLock.js";

// Post-remediation recurrence checks (#930 item 9 — #969): the analyst's REMEDIATION BOUNDARY, the
// immutable RECEIPTS a verify writes, and the residual-risk STATUS the analyst records against one.
//
// A boundary is an analyst statement — "on host H, artifact A was remediated at T; watch W hours".
// It establishes nothing by itself. A verify (remediationVerify.ts) reads the case and returns
// FACTS: what rows on H name A inside the window, what each row's shape says it IS, how much
// telemetry of each family the case holds for H in that window. It never emits a negative: "no
// rows" is a coverage fact, not "the foothold is gone". The status is the analyst's, and it names
// the receipt of the facts they read, so a report can show the status beside what was covered.
//
// Kept in a per-case side file beside the state (the finding-outcome pattern) so a re-synthesis
// never wipes it. Every field is bounded; the receipt a status names is pinned outside the
// rolling receipt bound so the facts behind a recorded status cannot be evicted.

export const ARTIFACT_KINDS = [
  "path",
  "hash",
  "account",
  "domain",
  "ip",
  "service",
  "task",
  "regkey",
] as const;
export type ArtifactKind = (typeof ARTIFACT_KINDS)[number];
export const RESIDUAL_RISK_STATUSES = [
  "unreviewed",
  "recurrence-observed",
  "checked-not-observed",
  "insufficient-coverage",
] as const;
export type ResidualRiskStatus = (typeof RESIDUAL_RISK_STATUSES)[number];

export const WINDOW_HOURS_MIN = 1;
export const WINDOW_HOURS_MAX = 720;
export const WINDOW_HOURS_DEFAULT = 168;
export const HOST_MAX = 200;
export const VALUE_MAX = 400;
export const NOTE_MAX = 2000;
export const BOUNDARIES_PER_CASE_MAX = 200;
export const RECEIPTS_PER_BOUNDARY_MAX = 20;
export const EVIDENCE_PER_BOUNDARY_MAX = 200;

const coverageStateSchema = z.enum(["absent", "partial", "covered"]);
export type CoverageState = z.infer<typeof coverageStateSchema>;

/** The telemetry families a recurrence check reads coverage for. */
export const TELEMETRY_FAMILIES = [
  "process",
  "authentication",
  "network",
  "file-listing",
  "defender",
] as const;
export type TelemetryFamily = (typeof TELEMETRY_FAMILIES)[number];

export const receiptSchema = z.object({
  id: z.string().min(1),
  at: z.string().min(1),
  boundary: z.object({
    host: z.string(),
    artifact: z.object({ kind: z.enum(ARTIFACT_KINDS), value: z.string() }),
    remediatedAt: z.string(),
    windowHours: z.number(),
  }),
  /** The raw host spellings the read covered, exactly as the stores hold them. */
  spellings: z.array(z.string()),
  window: z.object({ from: z.string(), to: z.string(), open: z.boolean() }),
  coverage: z.array(
    z.object({
      store: z.enum(["forensic", "super"]),
      source: z.string(),
      rows: z.number(),
      earliest: z.string(),
      latest: z.string(),
    }),
  ),
  families: z.array(
    z.object({
      family: z.enum(TELEMETRY_FAMILIES),
      relevant: z.boolean(),
      anyRowsOnHost: z.boolean(),
      rowsInWindow: z.number(),
      spanMs: z.number(),
      state: coverageStateSchema,
    }),
  ),
  hitTotal: z.number(),
  hitsByClass: z.record(z.number()),
  /** Ids of hits, so a status can be read against what the analyst saw — never a row's text. */
  hitIds: z.array(z.string()),
  truncated: z.boolean(),
  truncatedBy: z.string().optional(),
  undated: z.number(),
  coverageGapped: z.boolean(),
  retentionNote: z.string().optional(),
  lateImportNote: z.string(),
  clock: z.object({ alignment: z.enum(["on", "off"]), offsetMs: z.number().optional() }),
  highWater: z.object({
    forensic: z.object({ rows: z.number(), updatedAt: z.string() }),
    super: z.object({ rows: z.number(), generation: z.number() }),
  }),
  /** The stores changed while the read ran: the facts may mix two versions. */
  inconsistent: z.boolean(),
});
export type RemediationReceipt = z.infer<typeof receiptSchema>;

export const boundarySchema = z.object({
  id: z.string().min(1),
  host: z.string().min(1).max(HOST_MAX),
  artifact: z.object({ kind: z.enum(ARTIFACT_KINDS), value: z.string().min(1).max(VALUE_MAX) }),
  remediatedAt: z.string().min(1),
  windowHours: z.number().int().min(WINDOW_HOURS_MIN).max(WINDOW_HOURS_MAX),
  note: z.string().max(NOTE_MAX).optional(),
  task: z.object({ id: z.string(), sourceKey: z.string(), title: z.string() }).optional(),
  declaredAt: z.string().min(1),
  declaredBy: z.string().optional(),
  status: z.enum(RESIDUAL_RISK_STATUSES),
  statusSetAt: z.string().optional(),
  statusNote: z.string().max(NOTE_MAX).optional(),
  statusOverrideNote: z.string().max(NOTE_MAX).optional(),
  statusReceiptId: z.string().optional(),
  evidence: z.array(z.string()).max(EVIDENCE_PER_BOUNDARY_MAX),
  receipts: z.array(receiptSchema),
});
export type RemediationBoundary = z.infer<typeof boundarySchema>;
const fileSchema = z.array(boundarySchema);

export interface BoundaryInput {
  host: string;
  artifact: { kind: string; value: string };
  remediatedAt: string;
  windowHours?: number;
  note?: string;
  task?: { id: string; sourceKey: string; title: string };
  declaredBy?: string;
}

const HEX = /^[0-9a-f]+$/;
const IPV4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
const IPV6 = /^[0-9a-f:]+$/i;
const DOMAIN = /^(?=.{1,253}$)([a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z0-9-]{2,63}$/;

/** The artifact value as the store keeps it, or the reason it is refused. */
export function normaliseArtifact(
  kind: string,
  raw: string,
): { ok: true; kind: ArtifactKind; value: string } | { ok: false; error: string } {
  if (!(ARTIFACT_KINDS as readonly string[]).includes(kind))
    return { ok: false, error: `artifact.kind must be one of ${ARTIFACT_KINDS.join(", ")}` };
  const value = String(raw ?? "").trim();
  if (!value) return { ok: false, error: "artifact.value is required" };
  if (value.length > VALUE_MAX) return { ok: false, error: `artifact.value is longer than ${VALUE_MAX}` };
  if (kind === "hash") {
    const h = value.toLowerCase();
    if (!HEX.test(h) || ![32, 40, 64].includes(h.length))
      return { ok: false, error: "artifact.value must be an MD5, SHA-1 or SHA-256 hex digest" };
    return { ok: true, kind, value: h };
  }
  if (kind === "ip") {
    const v4 = IPV4.exec(value);
    if (v4 && v4.slice(1).every((o) => Number(o) <= 255)) return { ok: true, kind, value };
    if (value.includes(":") && IPV6.test(value)) return { ok: true, kind, value: value.toLowerCase() };
    return { ok: false, error: "artifact.value must be an IPv4 or IPv6 address" };
  }
  if (kind === "domain") {
    const d = value.toLowerCase().replace(/\.$/, "");
    if (!DOMAIN.test(d)) return { ok: false, error: "artifact.value must be a domain name" };
    return { ok: true, kind, value: d };
  }
  return { ok: true, kind: kind as ArtifactKind, value };
}

/** Validate a declaration; every failure is named. */
export function validateBoundaryInput(
  input: BoundaryInput,
  now: string,
): { ok: true; boundary: RemediationBoundary } | { ok: false; error: string } {
  const host = String(input.host ?? "").trim();
  if (!host) return { ok: false, error: "host is required" };
  if (host.length > HOST_MAX) return { ok: false, error: `host is longer than ${HOST_MAX}` };
  const artifact = normaliseArtifact(String(input.artifact?.kind ?? ""), String(input.artifact?.value ?? ""));
  if (!artifact.ok) return artifact;
  const remediatedMs = Date.parse(String(input.remediatedAt ?? ""));
  if (!Number.isFinite(remediatedMs)) return { ok: false, error: "remediatedAt must be an ISO-8601 time" };
  if (remediatedMs > Date.parse(now) + 60_000) return { ok: false, error: "remediatedAt is in the future" };
  const windowHours = input.windowHours === undefined ? WINDOW_HOURS_DEFAULT : Number(input.windowHours);
  if (!Number.isInteger(windowHours) || windowHours < WINDOW_HOURS_MIN || windowHours > WINDOW_HOURS_MAX)
    return {
      ok: false,
      error: `windowHours must be an integer between ${WINDOW_HOURS_MIN} and ${WINDOW_HOURS_MAX}`,
    };
  const note = input.note === undefined ? undefined : String(input.note);
  if (note !== undefined && note.length > NOTE_MAX)
    return { ok: false, error: `note is longer than ${NOTE_MAX}` };
  let task: RemediationBoundary["task"];
  if (input.task) {
    const id = String(input.task.id ?? "").trim();
    const sourceKey = String(input.task.sourceKey ?? "").trim();
    const title = String(input.task.title ?? "").slice(0, 300);
    if (!id || !sourceKey) return { ok: false, error: "task needs id and sourceKey" };
    task = { id, sourceKey, title };
  }
  return {
    ok: true,
    boundary: {
      id: `rb-${randomUUID().slice(0, 12)}`,
      host,
      artifact: { kind: artifact.kind, value: artifact.value },
      remediatedAt: new Date(remediatedMs).toISOString(),
      windowHours,
      ...(note ? { note } : {}),
      ...(task ? { task } : {}),
      declaredAt: now,
      ...(input.declaredBy ? { declaredBy: String(input.declaredBy).slice(0, 120) } : {}),
      status: "unreviewed",
      evidence: [],
      receipts: [],
    },
  };
}

/** The window a boundary watches, clipped at `now`. */
export function boundaryWindow(b: Pick<RemediationBoundary, "remediatedAt" | "windowHours">, now: string) {
  const from = Date.parse(b.remediatedAt);
  const end = from + b.windowHours * 3_600_000;
  const nowMs = Date.parse(now);
  return {
    fromMs: from,
    toMs: Math.min(end, nowMs),
    open: end > nowMs,
  };
}

/** A receipt against which `checked-not-observed` needs the analyst's override note. */
export function receiptNeedsOverride(r: RemediationReceipt): string[] {
  const reasons: string[] = [];
  if (r.truncated) reasons.push("the read was truncated");
  if (r.window.open) reasons.push("the window is still open");
  if (r.coverageGapped) reasons.push("a relevant telemetry family is not covered");
  if (r.inconsistent) reasons.push("the stores changed while the read ran");
  return reasons;
}

/** The task link as the current playbook sees it; identity is id + sourceKey, never the title. */
export function taskLinkState(
  task: RemediationBoundary["task"],
  tasks: readonly { id: string; sourceKey?: string; title: string }[],
): "none" | "linked" | "text-changed" | "orphaned" {
  if (!task) return "none";
  const current = tasks.find((t) => t.id === task.id);
  if (!current || (current.sourceKey ?? current.id) !== task.sourceKey) return "orphaned";
  return current.title === task.title ? "linked" : "text-changed";
}

const lock = new StateLock();

export class RemediationStore {
  constructor(private readonly cases: CaseStore) {}

  private path(caseId: string): string {
    return join(this.cases.stateDir(caseId), "remediation-boundaries.json");
  }

  async load(caseId: string): Promise<RemediationBoundary[]> {
    try {
      return fileSchema.parse(JSON.parse(await readFile(this.path(caseId), "utf8")));
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return [];
      throw err;
    }
  }

  private async save(caseId: string, boundaries: RemediationBoundary[]): Promise<void> {
    await atomicWrite(this.path(caseId), JSON.stringify(boundaries, null, 2));
  }

  /** Read-modify-write under the per-case lock; `fn` returns the new list or null to refuse. */
  async update<R>(
    caseId: string,
    fn: (boundaries: RemediationBoundary[]) => { boundaries: RemediationBoundary[]; result: R } | null,
  ): Promise<R | null> {
    return lock.runExclusive(caseId, async () => {
      const out = fn(await this.load(caseId));
      if (!out) return null;
      await this.save(caseId, out.boundaries);
      return out.result;
    });
  }

  async declare(caseId: string, boundary: RemediationBoundary): Promise<RemediationBoundary | "full"> {
    const r = await this.update<RemediationBoundary | "full">(caseId, (list) =>
      list.length >= BOUNDARIES_PER_CASE_MAX
        ? { boundaries: list, result: "full" }
        : { boundaries: [...list, boundary], result: boundary },
    );
    return r ?? "full";
  }

  async remove(caseId: string, id: string): Promise<boolean> {
    const r = await this.update(caseId, (list) =>
      list.some((b) => b.id === id) ? { boundaries: list.filter((b) => b.id !== id), result: true } : null,
    );
    return r === true;
  }

  /**
   * Append a receipt: immutable, newest RECEIPTS_PER_BOUNDARY_MAX kept, the one a status names
   * pinned outside that bound.
   */
  async addReceipt(caseId: string, id: string, receipt: RemediationReceipt): Promise<boolean> {
    const r = await this.update(caseId, (list) => {
      const b = list.find((x) => x.id === id);
      if (!b) return null;
      const all = [...b.receipts, receipt];
      const pinned = all.filter((x) => x.id === b.statusReceiptId);
      const rolling = all.filter((x) => x.id !== b.statusReceiptId).slice(-RECEIPTS_PER_BOUNDARY_MAX);
      const receipts = [...pinned, ...rolling].sort((x, y) => x.at.localeCompare(y.at));
      return { boundaries: list.map((x) => (x.id === id ? { ...x, receipts } : x)), result: true };
    });
    return r === true;
  }

  async setStatus(
    caseId: string,
    id: string,
    patch: {
      status: ResidualRiskStatus;
      note?: string;
      overrideNote?: string;
      receiptId?: string;
      at: string;
    },
  ): Promise<RemediationBoundary | null> {
    return this.update(caseId, (list) => {
      const b = list.find((x) => x.id === id);
      if (!b) return null;
      const next: RemediationBoundary = {
        ...b,
        status: patch.status,
        statusSetAt: patch.at,
        ...(patch.note !== undefined ? { statusNote: patch.note.slice(0, NOTE_MAX) } : {}),
        ...(patch.overrideNote !== undefined
          ? { statusOverrideNote: patch.overrideNote.slice(0, NOTE_MAX) }
          : {}),
        ...(patch.receiptId ? { statusReceiptId: patch.receiptId } : {}),
      };
      if (patch.status === "unreviewed") {
        delete next.statusReceiptId;
        delete next.statusOverrideNote;
      }
      return { boundaries: list.map((x) => (x.id === id ? next : x)), result: next };
    });
  }

  async attach(caseId: string, id: string, eventIds: string[]): Promise<RemediationBoundary | "full" | null> {
    return this.update<RemediationBoundary | "full">(caseId, (list) => {
      const b = list.find((x) => x.id === id);
      if (!b) return null;
      const evidence = [...new Set([...b.evidence, ...eventIds])];
      if (evidence.length > EVIDENCE_PER_BOUNDARY_MAX) return { boundaries: list, result: "full" };
      const next = { ...b, evidence };
      return { boundaries: list.map((x) => (x.id === id ? next : x)), result: next };
    });
  }
}
