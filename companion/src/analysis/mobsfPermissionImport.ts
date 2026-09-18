// MobSF's (Mobile Security Framework) static-analysis `/api/v1/report_json` output for BOTH
// platforms (#932 item 9, "932.15" Android; widened to iOS by #1136): the "permissions" dict — a
// declared REQUEST for a capability, never a claim it was granted by the user/OS or ever actually
// invoked. Deliberately the requested-capability third only of the spec's own three-way ask
// (requested/granted/used); the Android granted/used cross-source correlation needs a new ALEAPP
// artifact (AppOps/usagestats) this codebase's registry doesn't carry yet — see #1136's own
// landed-comment disposition, not a dead end, just unbuilt.
//
// Schema verified live against MobSF's own real, current source (2026, `master` branch):
// Android — db_interaction.py (get_context_from_analysis), manifest_analysis.py,
// manifest_utils.py, and dvm_permissions.py's own status values. iOS — db_interaction.py's own
// get_context_from_analysis/get_context_from_db_entry (relevant top-level iOS report keys used
// here: bundle_id, app_name, md5/sha1/sha256, permissions, plus iOS-unique anchors
// bundle_url_types, ats_analysis, macho_analysis, sdk_name, min_os_version) and
// kb/permission_analysis.py's own
// check_permissions() (the exact per-entry shape: `{info, status, description}` keyed by an
// NS*UsageDescription plist constant — structurally identical to Android's own three-field shape,
// but `description` there is the APP'S OWN Info.plist string, never MobSF's own knowledge-base
// text the way Android's `description` is). See RECOMMENDATION-9.md and RECOMMENDATION-1136.md for
// the full research trail.

import { createHash } from "node:crypto";
import { boundedAggKey } from "./aggKey.js";
import { createCanonicalEvent } from "./canonicalEvent.js";
import {
  MAX_DESCRIPTION_LEN,
  MAX_FIELD_LEN,
  MOBILE_REQUESTED_PERMISSION_BASIS,
  mobilePermissionStatuses,
  type MobilePermissionStatus,
  type MobileRequestedPermissionPlatform,
} from "./canonicalMobileRequestedPermission.js";
import { MAX_PRODUCER_VERSION_LEN, type SampleHash } from "./canonicalMalwareSample.js";
import {
  addIoc,
  isObject,
  mergeRowIocs,
  type MappedEvent,
  type SiemEvent,
  type SiemIoc,
} from "./siemImport.js";
import { aggregateEvents } from "./eventAggregate.js";

export const MAX_PERMISSIONS_SCANNED = 2000; // report-wide

const HASH_RE = {
  md5: /^[a-f0-9]{32}$/i,
  sha1: /^[a-f0-9]{40}$/i,
  sha256: /^[a-f0-9]{64}$/i,
};

export interface MobsfPermissionOptions {
  aggregate?: boolean;
  maxEvents?: number;
}

export interface MobsfPermissionResult {
  events: SiemEvent[];
  iocs: SiemIoc[];
  total: number;
  kept: number;
  dropped: number;
  groups: number;
  format: string;
  malformedPermissions: number;
  permissionsTruncated: boolean;
}

function str(v: unknown): string | undefined {
  return typeof v === "string" ? v : undefined;
}

function clip(text: string, max: number): { text: string; truncated: boolean } {
  if (text.length <= max) return { text, truncated: false };
  return { text: text.slice(0, max), truncated: true };
}

/** Shared by both platform detectors: is this value a real object or array, never a bare
 * primitive (Codex code review finding on the original Android detector — a bare `"key" in root`
 * check would pass for ANY value including `null`). */
function isStructured(v: unknown): boolean {
  return isObject(v) || Array.isArray(v);
}

function parseSampleHash(root: Record<string, unknown>): SampleHash {
  const md5 = str(root.md5);
  const sha1 = str(root.sha1);
  const sha256 = str(root.sha256);
  const out: SampleHash = { hashUnavailable: false };
  if (md5 && HASH_RE.md5.test(md5)) out.md5 = md5.toLowerCase();
  if (sha1 && HASH_RE.sha1.test(sha1)) out.sha1 = sha1.toLowerCase();
  if (sha256 && HASH_RE.sha256.test(sha256)) out.sha256 = sha256.toLowerCase();
  out.hashUnavailable = !out.md5 && !out.sha1 && !out.sha256;
  return out;
}

/** Both anchors required: `permissions` (an object, possibly `{}`) plus `sha256`/`package_name`
 * (may be `""`), AND at least one of the MobSF-specific top-level keys no other tool in this
 * codebase's vocabulary emits — the same "two anchors, never one" rule every prior detector in
 * this loop used. Codex code review finding: a bare `"key" in root` check would pass for ANY
 * value including `null`/a primitive; every anchor's own real shape (object) is checked too, not
 * merely its presence. Real iOS reports never carry `package_name` at all, so this always rejects
 * them (verified directly, #1136's own design review — no field collision). */
export function isMobsfReport(root: unknown): boolean {
  if (!isObject(root)) return false;
  if (!isObject(root.permissions)) return false;
  if (typeof root.sha256 !== "string" || typeof root.package_name !== "string") return false;
  return isStructured(root.niap_analysis) || isStructured(root.sbom) || isStructured(root.apkid);
}

/** iOS analog of isMobsfReport(): `permissions` (an object) plus `bundle_id`/`md5` (real iOS
 * reports always carry both, verified against db_interaction.py's own real key list), AND at
 * least one of the real iOS-unique top-level keys (bundle_url_types, ats_analysis,
 * macho_analysis) no other tool in this codebase's vocabulary emits. Never satisfied by a real
 * Android MobSF report (no `bundle_id`) nor by any of the 7 detectors checked before this one in
 * `importDetect.ts` (isIntactMemoryFile, isRunEnvelopeUpload, isVolatilityMap, isPeSieveReport,
 * isFlossResult, isCapaResult, isOlevbaResult) — each requires its own anchor key an iOS MobSF
 * report never carries, verified directly against each one's real source (#1136's own design
 * review). */
export function isMobsfIosReport(root: unknown): boolean {
  if (!isObject(root)) return false;
  if (!isObject(root.permissions)) return false;
  // Requires all three hash fields as strings, mirroring isMobsfReport()'s own sha256 requirement
  // above — a real iOS report always carries all three (verified against db_interaction.py's own
  // key list); requiring them here (not just md5) reduces false-positive risk from a synthetic
  // object that happens to carry only md5 (Ollama code review finding).
  if (
    typeof root.bundle_id !== "string" ||
    typeof root.md5 !== "string" ||
    typeof root.sha1 !== "string" ||
    typeof root.sha256 !== "string"
  )
    return false;
  return (
    isStructured(root.bundle_url_types) ||
    isStructured(root.ats_analysis) ||
    isStructured(root.macho_analysis)
  );
}

function mapPermission(
  platform: MobileRequestedPermissionPlatform,
  name: string,
  entry: Record<string, unknown>,
  reportFingerprint: string,
  packageName: string,
  appName: string,
  sampleHash: SampleHash,
  producerVersion: string,
  sink: Map<string, SiemIoc>,
): MappedEvent | null {
  if (!name) return null;
  const statusRaw = str(entry.status);
  const infoRaw = str(entry.info);
  const descriptionRaw = str(entry.description);
  if (statusRaw === undefined || infoRaw === undefined || descriptionRaw === undefined) return null;

  // An unrecognized status (a future MobSF release) normalizes to "unknown" rather than dropping
  // the whole entry — the raw string still survives in the canonical `rawStatus` field, itself
  // bounded at MAX_FIELD_LEN like every other display field (a real permission status name is
  // always short; the bound is unreachable in practice, never a claim of unlimited length).
  const status: MobilePermissionStatus = (mobilePermissionStatuses as readonly string[]).includes(statusRaw)
    ? (statusRaw as MobilePermissionStatus)
    : "unknown";

  const permissionHash = createHash("sha256").update(name).digest("hex");
  const aggKey = boundedAggKey(`mobsf-permission|${reportFingerprint}|${permissionHash}`);

  const hashSink = new Map<string, SiemIoc>();
  for (const h of [sampleHash.sha256, sampleHash.sha1, sampleHash.md5]) if (h) addIoc(hashSink, "hash", h);
  mergeRowIocs(sink, hashSink, aggKey);

  const permissionClip = clip(name, MAX_FIELD_LEN);
  const infoClip = clip(infoRaw, MAX_FIELD_LEN);
  const descriptionClip = clip(descriptionRaw, MAX_DESCRIPTION_LEN);
  // Once aggKey is stripped at persistence, the description text is the only surviving identity
  // (item 8's own lesson) — two distinct permission names sharing the same clipped 300-char
  // prefix would otherwise read as identical text. A short permission-hash tag disambiguates
  // them, mirroring the existing report-fingerprint tag pattern (never spliced into the VALUE
  // itself, only appended alongside it).
  const permissionTag = permissionClip.truncated ? `; permission ${permissionHash.slice(0, 12)}` : "";
  const reportTag = `; report ${reportFingerprint.slice(0, 16)}`;
  // Platform-correct attribution of the `description` text — #1136's own real finding, verified
  // against MobSF's own live source: Android's `description` is a 100% static knowledge-base
  // lookup (manifest_utils.py's `DVM_PERMISSIONS['MANIFEST_PERMISSION'][prm]`, with an "Unknown
  // permission from android reference" fallback), so "MobSF's own reference text" is accurate.
  // iOS's own `description` (kb/permission_analysis.py's `check_permissions()`) is
  // `p_list.get(perm, '')` — the literal value the APP'S OWN developer wrote into Info.plist.
  // Reusing the Android prose for iOS would misattribute developer-authored text as MobSF's own
  // reference text, a real evidence-attribution defect this item's own design review caught.
  const attribution =
    platform === "android"
      ? `MobSF's own reference text (never a claim about this specific app): "${infoClip.text}: ${descriptionClip.text}"`
      : `MobSF's own classification info: "${infoClip.text}"; the app's own declared purpose text ` +
        `(developer-authored via Info.plist, never a claim about actual behavior): "${descriptionClip.text}"`;
  const idLabel = platform === "android" ? "package" : "bundle id";
  const body = clip(
    `MobSF requested-permission finding: ${permissionClip.text} (status: ${status}) — ${idLabel} ` +
      `${packageName || "(unknown)"}; ${attribution}; a declared request, never proof of grant or ` +
      `use; [undated: MobSF's report carries no event time]`,
    600 - reportTag.length - permissionTag.length,
  ).text;
  const description = `${body}${permissionTag}${reportTag}`;

  return {
    timestamp: "",
    description,
    severity: "Info",
    mitre: [],
    aggKey,
    sources: ["mobsf"],
    canonical: createCanonicalEvent({
      event: { category: "file", type: "mobile-requested-permission", action: "found" },
      time: { observed: "", normalized: "" },
      evidence: {
        rawRecords: [{ source: "mobsf-permission", locator: `permission:${permissionHash.slice(0, 16)}` }],
      },
      producer: {
        importer: "mobsf-permission",
        parserVersion: "1",
        mappingVersion: "mobile-requested-permission-v2",
      },
      mobileRequestedPermission: {
        tool: "mobsf",
        platform,
        permission: permissionClip.text,
        permissionTruncated: permissionClip.truncated,
        status,
        rawStatus: clip(statusRaw, MAX_FIELD_LEN).text,
        info: infoClip.text,
        permissionDescription: descriptionClip.text,
        packageName: clip(packageName, MAX_FIELD_LEN).text,
        appName: clip(appName, MAX_FIELD_LEN).text,
        sampleHash,
        reportFingerprint,
        producerVersion: clip(producerVersion, MAX_PRODUCER_VERSION_LEN).text,
        mappingVersion: "mobile-requested-permission-v2",
        basis: MOBILE_REQUESTED_PERMISSION_BASIS,
      },
    }),
  };
}

/** Shared scan/aggregate loop for both platforms — the only difference between the Android and
 * iOS entry points is which detector/id-field/format-label they use; the permission-entry scan,
 * truncation bound, and aggregation are platform-blind by construction. */
function parseMobsfPermissionsGeneric(
  root: Record<string, unknown>,
  text: string,
  platform: MobileRequestedPermissionPlatform,
  idFieldValue: string,
  format: string,
  opts: MobsfPermissionOptions,
): MobsfPermissionResult {
  const permissions = root.permissions as Record<string, unknown>;
  const reportFingerprint = createHash("sha256").update(text).digest("hex");
  const appName = str(root.app_name) ?? "";
  const producerVersion = str(root.version) ?? "";
  const sampleHash = parseSampleHash(root);

  const sink = new Map<string, SiemIoc>();
  const mapped: MappedEvent[] = [];
  let total = 0;
  let malformedPermissions = 0;
  let permissionsTruncated = false;
  let scanned = 0;

  for (const [name, entry] of Object.entries(permissions)) {
    // Report-wide bound checked INSIDE this loop, not only between calls — items 7/8's own
    // lesson applied from the start.
    if (scanned >= MAX_PERMISSIONS_SCANNED) {
      permissionsTruncated = true;
      break;
    }
    scanned += 1;
    total += 1;
    if (!isObject(entry)) {
      malformedPermissions += 1;
      continue;
    }
    const event = mapPermission(
      platform,
      name,
      entry,
      reportFingerprint,
      idFieldValue,
      appName,
      sampleHash,
      producerVersion,
      sink,
    );
    if (!event) {
      malformedPermissions += 1;
      continue;
    }
    mapped.push(event);
  }

  const { events, groups } = aggregateEvents(mapped, {
    aggregate: opts.aggregate,
    minSeverity: "Info",
    maxEvents: opts.maxEvents ?? MAX_PERMISSIONS_SCANNED,
  });

  return {
    events,
    iocs: [...sink.values()],
    total,
    kept: events.length,
    dropped: malformedPermissions,
    groups,
    format,
    malformedPermissions,
    permissionsTruncated,
  };
}

export function parseMobsfPermissions(
  text: string,
  opts: MobsfPermissionOptions = {},
): MobsfPermissionResult | null {
  let root: unknown;
  try {
    root = JSON.parse(text);
  } catch {
    return null;
  }
  if (!isMobsfReport(root)) return null;
  const obj = root as Record<string, unknown>;
  return parseMobsfPermissionsGeneric(
    obj,
    text,
    "android",
    str(obj.package_name) ?? "",
    "MobsfAndroidStaticReport",
    opts,
  );
}

export function parseMobsfIosPermissions(
  text: string,
  opts: MobsfPermissionOptions = {},
): MobsfPermissionResult | null {
  let root: unknown;
  try {
    root = JSON.parse(text);
  } catch {
    return null;
  }
  if (!isMobsfIosReport(root)) return null;
  const obj = root as Record<string, unknown>;
  return parseMobsfPermissionsGeneric(
    obj,
    text,
    "ios",
    str(obj.bundle_id) ?? "",
    "MobsfIosStaticReport",
    opts,
  );
}

/** Parses `text` exactly once and dispatches to whichever platform matches, avoiding the
 * double-JSON.parse a naive "try Android then try iOS" caller would otherwise pay (Ollama code
 * review finding) — the two single-platform functions above stay public for direct, focused unit
 * testing and any other caller that already knows the platform. */
export function parseMobsfPermissionsAnyPlatform(
  text: string,
  opts: MobsfPermissionOptions = {},
): MobsfPermissionResult | null {
  let root: unknown;
  try {
    root = JSON.parse(text);
  } catch {
    return null;
  }
  if (isMobsfReport(root)) {
    const obj = root as Record<string, unknown>;
    return parseMobsfPermissionsGeneric(
      obj,
      text,
      "android",
      str(obj.package_name) ?? "",
      "MobsfAndroidStaticReport",
      opts,
    );
  }
  if (isMobsfIosReport(root)) {
    const obj = root as Record<string, unknown>;
    return parseMobsfPermissionsGeneric(
      obj,
      text,
      "ios",
      str(obj.bundle_id) ?? "",
      "MobsfIosStaticReport",
      opts,
    );
  }
  return null;
}
