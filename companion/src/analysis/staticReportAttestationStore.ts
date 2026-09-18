import { randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { z } from "zod";
import { atomicWrite } from "../storage/atomicWrite.js";
import type { CaseStore } from "../storage/caseStore.js";
import { filePath } from "./downloadExecution.js";
import { canonicalHostName } from "./hostAlias.js";

// An analyst's own attestation that a static-analysis report (olevba, capa, FLOSS) was produced
// against a copy taken from a named subject host, optionally from a named evidence volume and with
// the analyst's own digest of that copy (#1316, prerequisite filed by #1127's design review).
//
// THE BINDING IS AN ATTESTATION, NEVER A VERIFICATION — the same trust model as
// canonicalMobileBackupGeneration.ts. olevba's own result dict has no document hash (its source
// never imports hashlib), stamps no host and carries no time, so nothing derived from a report can
// be joined to victim-host evidence without a human saying which host the copy came from. Every
// row later derived from a record here carries that basis in its own text; the system never
// confirms the claim and cannot.
//
// Mirrors huntRequirementStore.ts: per-case append queue, fail-closed load, atomicWrite, revoke
// mutates only the one row. Every cross-row invariant (one active per fingerprint, one host per
// document digest, supersedes) runs INSIDE the queued mutation — a route-side check would let two
// concurrent creates both read "no active attestation" and both land (design review M-1).

export const STATIC_REPORT_TOOLS = ["olevba", "capa", "floss"] as const;
export type StaticReportTool = (typeof STATIC_REPORT_TOOLS)[number];

export const DIGEST_CROSS_CHECKS = ["tool-sha256", "md5-only-unchecked", "none"] as const;
export type DigestCrossCheck = (typeof DIGEST_CROSS_CHECKS)[number];

const SHA256 = /^[0-9a-f]{64}$/;
const MD5 = /^[0-9a-f]{32}$/;
const HOST_MAX = 120;

// A stored volume is the normalized token filePath() itself produces (`c`, `{guid}`,
// `harddiskvolume3`), never the analyst's raw spelling — a one-character typo ("C" for "C:") would
// otherwise parse as kind "none" and silently widen every later volume comparison to "not
// compared" (design review M-7).
const volumeSchema = z.object({
  volume: z.string().min(1),
  volumeKind: z.enum(["drive", "guid", "device"]),
});
export type AttestedVolume = z.infer<typeof volumeSchema>;

/** The volume a bare token names, using filePath()'s own grammar; null when it names none. */
export function volumeToken(raw: string): AttestedVolume | null {
  const trimmed = raw.trim().replace(/[\\/]+$/, "");
  if (!trimmed) return null;
  const parsed = filePath(`${trimmed}\\_`);
  if (!parsed || parsed.volumeKind === "none") return null;
  return { volume: parsed.volume, volumeKind: parsed.volumeKind };
}

const attestationSchema = z.object({
  id: z.string(),
  reportFingerprint: z.string().regex(SHA256),
  tool: z.enum(STATIC_REPORT_TOOLS),
  subjectHost: z.string().trim().min(1).max(HOST_MAX),
  evidenceVolume: z.object({ mountPoint: volumeSchema, originalVolume: volumeSchema.optional() }).optional(),
  documentSha256: z.string().regex(SHA256).optional(),
  documentMd5: z.string().regex(MD5).optional(),
  // What the report's own block said about the sample, copied onto the record at write time so
  // the one-host-per-document rule can run inside the store without loading the timeline.
  toolReportedSha256: z.string().regex(SHA256).optional(),
  toolReportedMd5: z.string().regex(MD5).optional(),
  digestCrossCheck: z.enum(DIGEST_CROSS_CHECKS),
  attestedBy: z.string().min(1),
  attestedAt: z.string().datetime({ offset: true }),
  supersedesId: z.string().min(1).max(200).optional(),
  revokedBy: z.string().optional(),
  revokedAt: z.string().optional(),
  revokedReason: z.string().optional(),
});

const fileSchema = z.object({
  version: z.literal(1),
  attestations: z.array(attestationSchema),
});

export type StaticReportAttestation = z.infer<typeof attestationSchema>;

export interface NewStaticReportAttestation {
  reportFingerprint: string;
  tool: StaticReportTool;
  subjectHost: string;
  evidenceVolume?: { mountPoint: string; originalVolume?: string };
  documentSha256?: string;
  documentMd5?: string;
  toolReportedSha256?: string;
  toolReportedMd5?: string;
  attestedBy: string;
  attestedAt: string;
  supersedesId?: string;
}

// A client-correctable rejection — a route maps it to 400, never 500.
export class InvalidStaticReportAttestationError extends Error {}

/** The digest this record binds to a host: the analyst's own, else the tool's. */
export function attestedDigest(
  a: Pick<StaticReportAttestation, "documentSha256" | "toolReportedSha256">,
): string | undefined {
  return a.documentSha256 ?? a.toolReportedSha256;
}

function normalizeVolumes(
  input: NewStaticReportAttestation["evidenceVolume"],
): StaticReportAttestation["evidenceVolume"] {
  if (!input) return undefined;
  const mountPoint = volumeToken(input.mountPoint);
  if (!mountPoint) {
    throw new InvalidStaticReportAttestationError(
      `evidenceVolume.mountPoint "${input.mountPoint}" names no volume — use a drive letter (E:), a \\VOLUME{guid} or a \\Device\\HarddiskVolumeN token`,
    );
  }
  const originalVolume = input.originalVolume === undefined ? undefined : volumeToken(input.originalVolume);
  if (input.originalVolume !== undefined && !originalVolume) {
    throw new InvalidStaticReportAttestationError(
      `evidenceVolume.originalVolume "${input.originalVolume}" names no volume — use a drive letter (C:), a \\VOLUME{guid} or a \\Device\\HarddiskVolumeN token`,
    );
  }
  return originalVolume ? { mountPoint, originalVolume } : { mountPoint };
}

function crossCheck(input: NewStaticReportAttestation): DigestCrossCheck {
  const sha = input.documentSha256?.toLowerCase();
  const tool = input.toolReportedSha256?.toLowerCase();
  if (!sha) return "none";
  if (tool) return "tool-sha256";
  if (input.toolReportedMd5) return "md5-only-unchecked";
  return "none";
}

export class StaticReportAttestationStore {
  constructor(private readonly cases: Pick<CaseStore, "stateDir">) {}

  private readonly appendQueue = new Map<string, Promise<unknown>>();

  private path(caseId: string): string {
    return join(this.cases.stateDir(caseId), "static-report-attestations.json");
  }

  private enqueue<T>(caseId: string, job: () => Promise<T>): Promise<T> {
    const prior = this.appendQueue.get(caseId) ?? Promise.resolve();
    const run = prior.then(job, job);
    this.appendQueue.set(
      caseId,
      run.catch(() => undefined),
    );
    return run;
  }

  async load(caseId: string): Promise<StaticReportAttestation[]> {
    let raw: string;
    try {
      raw = await readFile(this.path(caseId), "utf8");
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return [];
      throw err;
    }
    let json: unknown;
    try {
      json = JSON.parse(raw);
    } catch {
      throw new Error(
        `static-report-attestations.json for case ${caseId} is not valid JSON; it was left untouched so no attestation is lost`,
      );
    }
    const parsed = fileSchema.safeParse(json);
    if (!parsed.success) {
      throw new Error(
        `static-report-attestations.json for case ${caseId} does not match the attestation schema and was left untouched: ${parsed.error.message}`,
      );
    }
    return parsed.data.attestations;
  }

  async active(caseId: string): Promise<StaticReportAttestation[]> {
    return (await this.load(caseId)).filter((a) => !a.revokedAt);
  }

  async create(caseId: string, input: NewStaticReportAttestation): Promise<StaticReportAttestation> {
    const sha = input.documentSha256?.toLowerCase();
    const toolSha = input.toolReportedSha256?.toLowerCase();
    const md5 = input.documentMd5?.toLowerCase();
    const toolMd5 = input.toolReportedMd5?.toLowerCase();
    if (sha && sha === input.reportFingerprint.toLowerCase()) {
      throw new InvalidStaticReportAttestationError(
        "documentSha256 equals the report fingerprint — that is the hash of the report, not the document; hash the staged file itself",
      );
    }
    if (sha && toolSha && sha !== toolSha) {
      throw new InvalidStaticReportAttestationError(
        `documentSha256 ${sha} disagrees with the sha256 the tool itself reported for this sample (${toolSha}) — the attestation names a different file than the report analyzed`,
      );
    }
    if (md5 && toolMd5 && md5 !== toolMd5) {
      throw new InvalidStaticReportAttestationError(
        `documentMd5 ${md5} disagrees with the md5 the tool itself reported for this sample (${toolMd5})`,
      );
    }
    const validated = attestationSchema.parse({
      ...input,
      id: randomUUID(),
      reportFingerprint: input.reportFingerprint.toLowerCase(),
      evidenceVolume: normalizeVolumes(input.evidenceVolume),
      documentSha256: sha,
      documentMd5: md5,
      toolReportedSha256: toolSha,
      toolReportedMd5: toolMd5,
      digestCrossCheck: crossCheck(input),
    });

    return this.enqueue(caseId, async () => {
      const all = await this.load(caseId);
      const activeRows = all.filter((a) => !a.revokedAt);
      if (activeRows.some((a) => a.reportFingerprint === validated.reportFingerprint)) {
        throw new InvalidStaticReportAttestationError(
          `report ${validated.reportFingerprint.slice(0, 16)} already has an active attestation — revoke it first, then create the replacement with supersedesId`,
        );
      }
      const digest = attestedDigest(validated);
      if (digest) {
        const host = canonicalHostName(validated.subjectHost);
        const clash = activeRows.find(
          (a) => attestedDigest(a) === digest && canonicalHostName(a.subjectHost) !== host,
        );
        if (clash) {
          throw new InvalidStaticReportAttestationError(
            `document ${digest.slice(0, 16)} is already attested to a different subject host (${clash.subjectHost}) by attestation ${clash.id} — revoke that one first; two hosts cannot both be the source of one document`,
          );
        }
      }
      if (validated.supersedesId) {
        const target = all.find((a) => a.id === validated.supersedesId);
        if (!target) {
          throw new InvalidStaticReportAttestationError(
            `supersedesId ${validated.supersedesId} does not exist in case ${caseId}`,
          );
        }
        if (!target.revokedAt) {
          throw new InvalidStaticReportAttestationError(
            `supersedesId ${validated.supersedesId} must be revoked before it can be superseded`,
          );
        }
      }
      const attestations = [...all, validated];
      await atomicWrite(this.path(caseId), JSON.stringify({ version: 1, attestations }, null, 2));
      return validated;
    });
  }

  // Unlike huntRequirementStore.revoke(), an unknown id is an ERROR here (design review M-8): a
  // mistyped id that silently "succeeds" leaves a wrong-host binding active, and every match row
  // derived from it keeps reading as a live claim. Already-revoked known id stays a no-op.
  async revoke(
    caseId: string,
    id: string,
    revokedBy: string,
    revokedAt: string,
    revokedReason?: string,
  ): Promise<StaticReportAttestation[]> {
    return this.enqueue(caseId, async () => {
      const attestations = await this.load(caseId);
      const idx = attestations.findIndex((a) => a.id === id);
      if (idx === -1) {
        throw new InvalidStaticReportAttestationError(`attestation ${id} not found in case ${caseId}`);
      }
      if (attestations[idx].revokedAt) return attestations;
      const next = attestations.map((a, i) =>
        i === idx ? { ...a, revokedBy, revokedAt, revokedReason } : a,
      );
      await atomicWrite(this.path(caseId), JSON.stringify({ version: 1, attestations: next }, null, 2));
      return next;
    });
  }
}
