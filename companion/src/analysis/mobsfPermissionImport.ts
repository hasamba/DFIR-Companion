// MobSF's (Mobile Security Framework) Android static-analysis `/api/v1/report_json` output
// (#932 item 9, "932.15"): the "permissions" dict — a manifest-declared REQUEST for a capability,
// never a claim it was granted by the user/OS or ever actually invoked. Deliberately the
// requested-capability third only of the spec's own three-way ask (requested/granted/used); the
// granted/used cross-source correlation is a separate, larger follow-up, and iOS MobSF reports
// (a structurally different Info.plist-based shape) are out of scope for this item.
//
// Schema verified live against MobSF's own db_interaction.py (get_context_from_analysis),
// manifest_analysis.py and manifest_utils.py, and dvm_permissions.py's own status values — not
// invented. See RECOMMENDATION-9.md for the full research trail.

import { createHash } from "node:crypto";
import { boundedAggKey } from "./aggKey.js";
import { createCanonicalEvent } from "./canonicalEvent.js";
import {
  MAX_DESCRIPTION_LEN,
  MAX_FIELD_LEN,
  MOBILE_REQUESTED_PERMISSION_BASIS,
  mobilePermissionStatuses,
  type MobilePermissionStatus,
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
 * this loop used. */
export function isMobsfReport(root: unknown): boolean {
  if (!isObject(root)) return false;
  if (!isObject(root.permissions)) return false;
  if (typeof root.sha256 !== "string" || typeof root.package_name !== "string") return false;
  return "niap_analysis" in root || "sbom" in root || "apkid" in root;
}

function mapPermission(
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

  // An unrecognized status (a future MobSF release) normalizes to "unknown" rather than
  // dropping the whole entry — the raw string still survives in `rawStatus` (Codex design
  // review finding).
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
  const reportTag = `; report ${reportFingerprint.slice(0, 16)}`;
  // "MobSF's own reference text (never a claim about this specific app)" framing — Codex code
  // review finding: MobSF's own knowledge-base description text can contain phrases like "this
  // could allow a malicious application to...", which is generic reference prose about what the
  // PERMISSION allows in the abstract, never a claim about the app actually being analyzed.
  const body = clip(
    `MobSF requested-permission finding: ${permissionClip.text} (status: ${status}) — package ` +
      `${packageName || "(unknown)"}; MobSF's own reference text (never a claim about this specific ` +
      `app): "${infoClip.text}: ${descriptionClip.text}"; a manifest declaration, never proof of ` +
      `grant or use; [undated: MobSF's report carries no event time]`,
    600 - reportTag.length,
  ).text;
  const description = `${body}${reportTag}`;

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
        mappingVersion: "mobile-requested-permission-v1",
      },
      mobileRequestedPermission: {
        tool: "mobsf",
        platform: "android",
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
        mappingVersion: "mobile-requested-permission-v1",
        basis: MOBILE_REQUESTED_PERMISSION_BASIS,
      },
    }),
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
  const permissions = obj.permissions as Record<string, unknown>;
  const reportFingerprint = createHash("sha256").update(text).digest("hex");
  const packageName = str(obj.package_name) ?? "";
  const appName = str(obj.app_name) ?? "";
  const producerVersion = str(obj.version) ?? "";
  const sampleHash = parseSampleHash(obj);

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
      name,
      entry,
      reportFingerprint,
      packageName,
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
    format: "MobsfAndroidStaticReport",
    malformedPermissions,
    permissionsTruncated,
  };
}
