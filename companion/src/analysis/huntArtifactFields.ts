import type { ForensicEvent } from "./stateTypes.js";
import { sha1Unusable, usableSha1 } from "./fileIdentity.js";

/**
 * Normalised hunt fields of one imported row (#2670), derived at the import seam from the row the
 * Velociraptor importer already produced. PURE.
 *
 * Honest labels: what the artifact PROVES, not what it suggests.
 *   execution — the program ran (Prefetch, UserAssist).
 *   presence  — the file was on disk (ShimCache, Amcache InventoryApplicationFile). Not proof it ran.
 *   installed — an installed-program record (Amcache InventoryApplication).
 *   autorun   — a startup item, service or scheduled task.
 *   download  — a Zone.Identifier / browser download record.
 *
 * Signer vs publisher: Amcache "Publisher" and version-info strings are ATTACKER-CONTROLLED text. They
 * are kept as `publisher` with `publisherVerified: false` and may describe a candidate, but they never
 * approve anything. A VERIFIED signer can only come from an Authenticode check on the endpoint: today
 * only an Autoruns row whose Signer starts with "(Verified) " (#2731, veloAutorunsMap.ts).
 *
 * Amcache SHA1 (#2731): Windows hashes only the first 30 MiB of a file, so the SHA1 is a hunt field
 * only when Amcache also recorded a size within that limit. A larger or unsized file keeps the reason
 * (`sha1Unusable`) so the client-baseline panel can say why the hash cannot approve it.
 */
export type HuntEvidence = "execution" | "presence" | "installed" | "autorun" | "download";

export interface HuntFields {
  evidence: HuntEvidence;
  /** Lower-cased file name (or installed-program name) — the item's identity with its path. */
  program: string;
  /** Lower-cased directory with the drive and per-user folder generalised; "" when unknown. */
  pathPattern: string;
  /** The full lower-cased path the row named, "" when none. */
  path: string;
  publisher?: string;
  publisherVerified: false;
  /** Verified Authenticode signer — only from a "(Verified) " Autoruns Signer (see the header). */
  signer?: string;
  /** The endpoint checked the signature and did not verify it. */
  signatureUnverified?: true;
  sha256?: string;
  /** Amcache SHA1 of a file of known size within 30 MiB — the only SHA1 an approval may use. */
  sha1?: string;
  /** Amcache recorded a SHA1 an approval cannot use: no size, or a file over 30 MiB. */
  sha1Unusable?: "no-size" | "over-limit";
  md5?: string;
  /** Download source URL (Zone.Identifier HostUrl) when the row named one. */
  sourceUrl?: string;
  host: string;
}

const LABELS: { re: RegExp; evidence: HuntEvidence }[] = [
  { re: /: Executed \(prefetch\)/, evidence: "execution" },
  { re: /: Ran \(UserAssist\)/, evidence: "execution" },
  { re: /: Present in ShimCache/, evidence: "presence" },
  { re: /: Program file present \(Amcache\)/, evidence: "presence" },
  { re: /: Installed program \(Amcache\)/, evidence: "installed" },
  { re: /: Downloaded /, evidence: "download" },
];

const AUTORUN_ARTIFACT = /startup|autorun|taskscheduler|services|persistencesniper/i;

function evidenceOf(e: ForensicEvent): HuntEvidence | null {
  if (!/^Velociraptor\b/.test(e.description)) return null;
  for (const l of LABELS) if (l.re.test(e.description)) return l.evidence;
  if (
    AUTORUN_ARTIFACT.test(e.artifactName ?? "") ||
    /\[[^\]]*(?:Startup|Autorun|TaskScheduler)/i.test(e.description)
  )
    return "autorun";
  return null;
}

/** `c:\Users\Bob\AppData\x.exe` → `\users\*\appdata`; drive letters and device prefixes dropped. */
export function normalisePathPattern(path: string): string {
  const p = path
    .trim()
    .replace(/^\\\\\.\\/, "")
    .replace(/\//g, "\\")
    .toLowerCase();
  const dir = p.includes("\\") ? p.slice(0, p.lastIndexOf("\\")) : "";
  return dir.replace(/^[a-z]:/, "").replace(/\\users\\[^\\]+/, "\\users\\*");
}

const baseName = (p: string): string => p.replace(/\//g, "\\").split("\\").pop() ?? "";

const escapeRe = (v: string): string => v.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/**
 * The subject after the action label: "…: Installed program (Amcache): Name v1 (Pub) - @ host".
 * The importer's host suffix is " - @ host", or " @ host" when the text already holds " - "
 * (velociraptorTitle.withHostSuffix), so it is stripped by the row's own host, never by guessing.
 */
function subjectOf(description: string, host: string): string {
  const parts = description.split(/\): /);
  const tail = parts.length > 1 ? parts.slice(1).join("): ") : description;
  const suffix = host ? new RegExp(`\\s*(?:- )?@ ${escapeRe(host)}\\s*$`, "i") : /$^/;
  return tail.replace(suffix, "").trim();
}

function installedFields(e: ForensicEvent): { program: string; publisher?: string } {
  const subject = subjectOf(e.description, (e.asset ?? "").trim());
  const pub = /\(([^()]+)\)\s*$/.exec(subject);
  const name = subject
    .replace(/\s*\([^()]+\)\s*$/, "")
    .replace(/\s+v\S+$/, "")
    .trim()
    .toLowerCase();
  return { program: name, ...(pub ? { publisher: pub[1].trim() } : {}) };
}

function downloadUrl(description: string): string | undefined {
  const m = /: Downloaded .+? from (https?:\/\/\S+)/i.exec(description);
  return m ? m[1].replace(/[),.]+$/, "") : undefined;
}

/** The importer-recorded identity (#2731): a usable Amcache SHA1 or why not, and the signer verdict. */
function identityFields(
  e: ForensicEvent,
): Pick<HuntFields, "sha1" | "sha1Unusable" | "signer" | "signatureUnverified"> {
  const id = e.fileIdentity;
  const sha1 = usableSha1(id);
  const unusable = sha1Unusable(id);
  return {
    ...(sha1 ? { sha1 } : {}),
    ...(unusable ? { sha1Unusable: unusable } : {}),
    ...(id?.signer && !id.signatureUnverified ? { signer: id.signer } : {}),
    ...(id?.signatureUnverified ? { signatureUnverified: true as const } : {}),
  };
}

export function huntFieldsOf(e: ForensicEvent): HuntFields | null {
  const evidence = evidenceOf(e);
  const host = (e.asset ?? "").trim();
  if (!evidence || !host) return null;
  const path = (e.path ?? "").trim().toLowerCase();
  const base = {
    evidence,
    path,
    pathPattern: path ? normalisePathPattern(path) : "",
    publisherVerified: false as const,
    host,
    ...(e.sha256 ? { sha256: e.sha256.toLowerCase() } : {}),
    ...(e.md5 ? { md5: e.md5.toLowerCase() } : {}),
    ...identityFields(e),
  };
  if (evidence === "installed") {
    const f = installedFields(e);
    return f.program ? { ...base, ...f } : null;
  }
  const program = (path ? baseName(path) : (e.processName ?? "")).toLowerCase();
  if (!program) return null;
  const sourceUrl = evidence === "download" ? downloadUrl(e.description) : undefined;
  return { ...base, program, ...(sourceUrl ? { sourceUrl } : {}) };
}

/** The item identity: one entry per program + path pattern + evidence family. */
export function huntItemKey(f: Pick<HuntFields, "evidence" | "program" | "pathPattern">): string {
  const family = f.evidence === "execution" || f.evidence === "presence" ? "program" : f.evidence;
  return `${family}|${f.program}|${f.pathPattern}`;
}
