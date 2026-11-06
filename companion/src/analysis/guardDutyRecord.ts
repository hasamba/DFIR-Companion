// Amazon GuardDuty findings (#2361) — what a finding is, how an export is read into findings, the
// observation key, the severity bands and the MITRE table. Pure; guardDutyImport.ts maps the rows.
//
// A finding arrives as the `aws guardduty get-findings` CLI prints it ({"Findings":[...]},
// PascalCase), as a bare array or JSON lines of findings, as a page the live collector saved (the
// same {"Findings":[...]} shape), or in the camelCase spelling EventBridge's `detail` uses. Every key
// is read case-insensitively, so all of them map the same way.
//
// Security Hub's ASFF export is ALSO {"Findings":[...]}, with an object `Severity`, a `ProductArn`
// and a `Types` array — it is not a GuardDuty finding and is never claimed here.

import type { Severity } from "./stateTypes.js";
import { getCI, getPath, isObject, str } from "./siemFieldPick.js";
import { readCloudRecords } from "./cloudRecords.js";
import type { TolerantRecords } from "./tolerantJson.js";

type Row = Record<string, unknown>;

/** `ThreatPurpose:ResourceTypeAffected/ThreatFamilyName…` — the GuardDuty finding-type shape. */
const FINDING_TYPE = /^[A-Za-z]+:[A-Za-z0-9]+\/\S+$/;

const text = (rec: Row, path: string): string =>
  str(path.includes(".") ? getPath(rec, path) : getCI(rec, path)).trim();

function isAsff(rec: Row): boolean {
  return (
    getCI(rec, "ProductArn") !== undefined ||
    Array.isArray(getCI(rec, "Types")) ||
    isObject(getCI(rec, "Severity"))
  );
}

/** True for one GuardDuty finding: its type shape and GuardDuty's own service name or ARN. */
export function isGuardDutyFinding(rec: unknown): boolean {
  if (!isObject(rec) || isAsff(rec)) return false;
  if (!FINDING_TYPE.test(text(rec, "Type"))) return false;
  return /^guardduty$/i.test(text(rec, "Service.ServiceName")) || /:guardduty:/i.test(text(rec, "Arn"));
}

/** The findings of one parsed document: a `Findings` wrapper's elements, else the record itself. */
function findingsOf(rec: Row): Row[] {
  const wrapped = getCI(rec, "Findings");
  return Array.isArray(wrapped) ? wrapped.filter(isObject) : [rec];
}

/** True for an upload whose first finding is a GuardDuty finding (the detector's signature). */
export function isGuardDutyUpload(root: unknown, sample: Row | null): boolean {
  if (isObject(root) && !Array.isArray(root)) {
    const first = findingsOf(root)[0];
    if (first && isGuardDutyFinding(first)) return true;
  }
  return isGuardDutyFinding(sample);
}

/** The findings of a GuardDuty export, through the tolerant cloud reader (repairs counted). */
export function readGuardDutyRecords(textIn: string): TolerantRecords {
  const read = readCloudRecords(textIn);
  return { ...read, records: unwrapGuardDutyRecords(read.records) };
}

/** Records with every `{"Findings":[...]}` document replaced by its findings. Order kept. */
export function unwrapGuardDutyRecords(records: readonly Row[]): Row[] {
  return records.flatMap(findingsOf);
}

// The observation key (account + region + id + version) lives with the other providers' record ids.
export { guardDutyRecordId, guardDutyVersion } from "./cloudRecordIdentity.js";

/** GuardDuty's numeric severity, or null when it is missing or not a finite number. */
export function guardDutyScore(rec: Row): number | null {
  const raw = getCI(rec, "Severity");
  if (raw === null || raw === undefined || (typeof raw === "string" && !raw.trim())) return null;
  const n = typeof raw === "number" ? raw : typeof raw === "string" ? Number(raw) : NaN;
  return Number.isFinite(n) ? n : null;
}

/** True when the finding has been archived (suppressed or closed by someone in GuardDuty). */
export function isArchived(rec: Row): boolean {
  const v = getPath(rec, "Service.Archived");
  return v === true || (typeof v === "string" && v.toLowerCase() === "true");
}

/**
 * The issue's bands: 9.0 and above Critical, 7.0–8.9 High, 4.0–6.9 Medium, below 4.0 Low. An
 * archived finding stays Info. A missing score is Low — the caller counts it.
 */
export function guardDutySeverity(score: number | null, archived: boolean): Severity {
  if (archived) return "Info";
  if (score === null) return "Low";
  if (score >= 9) return "Critical";
  if (score >= 7) return "High";
  if (score >= 4) return "Medium";
  return "Low";
}

/**
 * Finding type → ATT&CK, only where the type itself establishes the technique (published in
 * mkdocs-docs/reference/importing.md). A family is mapped whole only when every type in it is the
 * same behaviour; anything else is listed by exact type, and an unlisted type maps to nothing.
 */
export const GUARDDUTY_MITRE: ReadonlyArray<readonly [RegExp, readonly string[]]> = [
  [/^CryptoCurrency:/, ["T1496"]],
  [/^Impact:EC2\/BitcoinDomainRequest\./, ["T1496"]],
  [/InstanceCredentialExfiltration\./, ["T1552.005"]],
  [/^UnauthorizedAccess:EC2\/MetadataDNSRebind$/, ["T1552.005"]],
  [/\/(?:SSH|RDP|WinRM)BruteForce$/, ["T1110"]],
  [/^Recon:EC2\/Portscan$/, ["T1046"]],
  [/^Backdoor:EC2\/DenialOfService\./, ["T1498"]],
  [/^Trojan:EC2\/DNSDataExfiltration(?:!DNS)?$/, ["T1048"]],
  [/^Stealth:IAMUser\/CloudTrailLoggingDisabled$/, ["T1562.008"]],
  [/^Stealth:S3\/ServerAccessLoggingDisabled$/, ["T1562.008"]],
  [/^Policy:IAMUser\/RootCredentialUsage$/, ["T1078.004"]],
  [/^Exfiltration:S3\//, ["T1530"]],
  [/^Discovery:S3\//, ["T1619"]],
  [/^Execution:Runtime\/ReverseShell$/, ["T1059"]],
];

export function guardDutyMitre(type: string): string[] {
  for (const [re, ids] of GUARDDUTY_MITRE) if (re.test(type)) return [...ids];
  return [];
}
