import { randomUUID } from "node:crypto";
import { z } from "zod";

/**
 * Client profiles for threat hunting (#2670, decisions D3/D5). A client is its OWN record: a name, an
 * optional default Velociraptor server set (it only pre-fills new hunt cases — it never decides which
 * hosts belong to the client), and the client's REVIEWED baseline. PURE: schema, normalisation, and the
 * immutable edits; persistence is clientProfileStore.ts.
 *
 * Integrity rules:
 *   - Seeing a program never approves it. Only an analyst's mark does, saved with who, when and the
 *     source ("client email 2026-11-20"); an approval can carry an expiry date.
 *   - Every edit is a numbered baseline VERSION, kept as a snapshot, so a case graded against v3 can
 *     be re-read exactly as it was. Every change is audit-logged and reversible (mark it Unknown).
 *   - Approvals are not false-positive marks and are never turned into one.
 */
export type BaselineVerdict = "approved" | "not-allowed" | "unknown";
export type BaselineFamily = "program" | "installed" | "autorun" | "download";

export interface BaselineMark {
  id: string;
  verdict: BaselineVerdict;
  family: BaselineFamily;
  program: string;
  /** Normalised directory pattern; `*` is one path segment, `**` any number. "" = any path (blocks only). */
  pathPattern: string;
  /** VERIFIED Authenticode signer the approval requires (never Amcache publisher text). */
  signer?: string;
  /** Approved SHA-256 hashes, for unsigned files. */
  sha256: string[];
  /**
   * Approved Amcache SHA1 hashes (#2731). Amcache hashes only the first 30 MiB, so a SHA1 covers only
   * a file whose recorded size is within that limit. Absent on marks saved before #2731.
   */
  sha1?: string[];
  note: string;
  source: string;
  recordedBy: string;
  recordedAt: string;
  expiresAt?: string;
}

export interface Baseline {
  marks: BaselineMark[];
  blockedDomains: string[];
  approvedDomains: string[];
  blockedCategories: string[];
}

export interface BaselineVersion {
  version: number;
  at: string;
  by: string;
  note: string;
  baseline: Baseline;
}

export interface ProfileAuditEntry {
  at: string;
  by: string;
  action: string;
  detail: string;
  version: number;
}

export interface ClientProfile {
  id: string;
  name: string;
  defaultServerSetId?: string;
  version: number;
  baseline: Baseline;
  versions: BaselineVersion[];
  audit: ProfileAuditEntry[];
  createdAt: string;
  updatedAt: string;
  /**
   * Set while the client is archived (#2941): hidden from the New Case and panel pickers, refused as
   * a new link target, but every byte kept — baseline, versions, audit trail — and linked cases keep
   * grading against it. Absent = active (every profile saved before #2941).
   */
  archivedAt?: string;
  archivedBy?: string;
}

export const MAX_VERSIONS_KEPT = 100;
export const MAX_AUDIT_KEPT = 2000;
export const MAX_MARKS = 20_000;

export const EMPTY_BASELINE: Baseline = {
  marks: [],
  blockedDomains: [],
  approvedDomains: [],
  blockedCategories: [],
};

const text = (max: number) => z.string().trim().max(max);
const domain = z
  .string()
  .trim()
  .toLowerCase()
  .regex(/^(?:[a-z0-9-]+\.)+[a-z]{2,63}$/, "not a domain name");

/**
 * Why an item with no path pattern can never be approved (#2747): an approval needs a path and a
 * verified signer or hash, and an Amcache installed-program record carries none of them. Shown on the
 * confirm list and when an approval with an empty path is refused.
 */
export const NO_PATH_APPROVAL =
  "no file path or hash; approve the program's files instead, or mark it Not allowed";

const markObjectSchema = z.object({
  verdict: z.enum(["approved", "not-allowed", "unknown"]),
  family: z.enum(["program", "installed", "autorun", "download"]),
  program: text(260).min(1).toLowerCase(),
  pathPattern: text(1024).toLowerCase().default(""),
  signer: text(260).optional(),
  sha256: z
    .array(
      z
        .string()
        .trim()
        .toLowerCase()
        .regex(/^[0-9a-f]{64}$/, "not a SHA-256"),
    )
    .max(50)
    .default([]),
  sha1: z
    .array(
      z
        .string()
        .trim()
        .toLowerCase()
        .regex(/^[0-9a-f]{40}$/, "not a SHA1"),
    )
    .max(50)
    .default([]),
  note: text(2000).default(""),
  expiresAt: z.string().datetime().optional(),
});

/**
 * A new APPROVAL with no path is refused (#2747): it could never match. Not allowed and Unknown marks
 * with no path stay valid (Not allowed matches by name). Stored marks are not re-validated here, so an
 * empty-path approval saved before #2747 still loads — and still fails closed in the matcher.
 */
export const markInputSchema = markObjectSchema.superRefine((m, ctx) => {
  if (m.verdict === "approved" && !m.pathPattern)
    ctx.addIssue({ code: "custom", path: ["pathPattern"], message: `"${m.program}": ${NO_PATH_APPROVAL}` });
});
export type MarkInput = z.infer<typeof markInputSchema>;

export const domainsInputSchema = z.object({
  blockedDomains: z.array(domain).max(5000).default([]),
  approvedDomains: z.array(domain).max(5000).default([]),
  blockedCategories: z.array(text(64).min(1)).max(100).default([]),
});

export const profileInputSchema = z.object({
  name: text(120).min(1),
  defaultServerSetId: text(120).optional(),
});

/** A url-safe id from a name, plus a short random suffix so two "Client A" profiles never collide. */
export function newProfileId(name: string): string {
  const slug = name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 40);
  return `${slug || "client"}-${randomUUID().slice(0, 8)}`;
}

export const PROFILE_ID_RE = /^[a-z0-9][a-z0-9-]{0,63}$/;

export function newProfile(input: z.infer<typeof profileInputSchema>, by: string, at: string): ClientProfile {
  return {
    id: newProfileId(input.name),
    name: input.name,
    ...(input.defaultServerSetId ? { defaultServerSetId: input.defaultServerSetId } : {}),
    version: 0,
    baseline: EMPTY_BASELINE,
    versions: [{ version: 0, at, by, note: "profile created", baseline: EMPTY_BASELINE }],
    audit: [{ at, by, action: "create", detail: `profile "${input.name}" created`, version: 0 }],
    createdAt: at,
    updatedAt: at,
  };
}

/** The identity two marks share when one replaces the other: family + program + path pattern. */
export const markIdentity = (m: Pick<BaselineMark, "family" | "program" | "pathPattern">): string =>
  `${m.family}|${m.program}|${m.pathPattern}`;

function withVersion(
  p: ClientProfile,
  baseline: Baseline,
  by: string,
  at: string,
  note: string,
  action: string,
  detail: string,
): ClientProfile {
  const version = p.version + 1;
  return {
    ...p,
    version,
    baseline,
    versions: [...p.versions, { version, at, by, note, baseline }].slice(-MAX_VERSIONS_KEPT),
    audit: [...p.audit, { at, by, action, detail, version }].slice(-MAX_AUDIT_KEPT),
    updatedAt: at,
  };
}

/**
 * Record marks (one new baseline version). A mark replaces any earlier mark with the same identity;
 * marking Unknown REMOVES the earlier verdict (the reversal), and is audit-logged like any change.
 */
export function applyMarks(
  p: ClientProfile,
  marks: readonly MarkInput[],
  meta: { by: string; at: string; source: string; note?: string },
): ClientProfile {
  const byIdentity = new Map(p.baseline.marks.map((m) => [markIdentity(m), m]));
  const counts = { approved: 0, "not-allowed": 0, unknown: 0 };
  for (const input of marks) {
    const key = markIdentity(input);
    counts[input.verdict]++;
    if (input.verdict === "unknown") {
      byIdentity.delete(key);
      continue;
    }
    byIdentity.set(key, {
      id: randomUUID(),
      verdict: input.verdict,
      family: input.family,
      program: input.program,
      pathPattern: input.pathPattern,
      ...(input.signer ? { signer: input.signer } : {}),
      sha256: input.sha256,
      ...(input.sha1.length ? { sha1: input.sha1 } : {}),
      note: input.note,
      source: meta.source,
      recordedBy: meta.by,
      recordedAt: meta.at,
      ...(input.expiresAt ? { expiresAt: input.expiresAt } : {}),
    });
  }
  const next = [...byIdentity.values()].slice(0, MAX_MARKS);
  const detail = `${counts.approved} approved, ${counts["not-allowed"]} not allowed, ${counts.unknown} reset to unknown — source: ${meta.source}`;
  return withVersion(p, { ...p.baseline, marks: next }, meta.by, meta.at, meta.note ?? "", "marks", detail);
}

export function applyDomains(
  p: ClientProfile,
  input: z.infer<typeof domainsInputSchema>,
  meta: { by: string; at: string; source: string },
): ClientProfile {
  const uniq = (xs: string[]) => [...new Set(xs)].sort();
  const baseline: Baseline = {
    ...p.baseline,
    blockedDomains: uniq(input.blockedDomains),
    approvedDomains: uniq(input.approvedDomains),
    blockedCategories: uniq(input.blockedCategories),
  };
  const detail = `${baseline.blockedDomains.length} blocked domain(s), ${baseline.approvedDomains.length} approved, categories: ${baseline.blockedCategories.join(", ") || "none"} — source: ${meta.source}`;
  return withVersion(p, baseline, meta.by, meta.at, "", "domains", detail);
}

/** The baseline as it was at `version` (the pinned one), or null when that version is no longer kept. */
export function baselineAt(p: ClientProfile, version: number): Baseline | null {
  return p.versions.find((v) => v.version === version)?.baseline ?? null;
}

export const isArchivedProfile = (p: Pick<ClientProfile, "archivedAt">): boolean => !!p.archivedAt;

function withAudit(p: ClientProfile, entry: Omit<ProfileAuditEntry, "version">): ClientProfile {
  return {
    ...p,
    audit: [...p.audit, { ...entry, version: p.version }].slice(-MAX_AUDIT_KEPT),
    updatedAt: entry.at,
  };
}

/** Rename / change the default server set (#2941). Not a baseline change, so no new version. */
export function editProfile(
  p: ClientProfile,
  input: z.infer<typeof profileInputSchema>,
  by: string,
  at: string,
): ClientProfile {
  const { defaultServerSetId: _old, ...rest } = p;
  const set = (id: string | undefined) => (id ? `"${id}"` : "none");
  const detail = `name "${p.name}" → "${input.name}"; default server set ${set(p.defaultServerSetId)} → ${set(input.defaultServerSetId)}`;
  return withAudit(
    {
      ...rest,
      name: input.name,
      ...(input.defaultServerSetId ? { defaultServerSetId: input.defaultServerSetId } : {}),
    },
    { at, by, action: "profile", detail },
  );
}

/** Archive (#2941). The same object back when the client is already archived: no second audit entry. */
export function archiveProfile(p: ClientProfile, by: string, at: string): ClientProfile {
  if (isArchivedProfile(p)) return p;
  return withAudit(
    { ...p, archivedAt: at, archivedBy: by },
    { at, by, action: "archive", detail: `client "${p.name}" archived` },
  );
}

/** Unarchive (#2941). The same object back when the client is not archived. */
export function unarchiveProfile(p: ClientProfile, by: string, at: string): ClientProfile {
  if (!isArchivedProfile(p)) return p;
  const { archivedAt: _at, archivedBy: _by, ...rest } = p;
  return withAudit(rest, { at, by, action: "unarchive", detail: `client "${p.name}" unarchived` });
}
