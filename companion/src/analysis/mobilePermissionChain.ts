import type { ForensicEvent } from "./stateTypes.js";
import type { HostAliasIndex } from "./hostAlias.js";
import { canonicalHostName, resolveHost } from "./hostAlias.js";

/** The fields of a static-report attestation this join reads (structural — a timeline module
 * never imports the store that owns the record; the route hands the real records over). */
export interface MobsfAttestationShape {
  id: string;
  reportFingerprint: string;
  tool: string;
  subjectHost: string;
  /** The analyst's own digest of the APK, when given; else the tool's reported one is the bound
   * digest — the same rule staticReportAttestationStore.ts's attestedDigest() states. */
  documentSha256?: string;
  toolReportedSha256?: string;
  attestedBy: string;
  attestedAt: string;
  revokedAt?: string;
}

// Android requested ↔ granted ↔ used permission correlation, by package on the analyst's subject
// device (#1363 — 932.15's second half). Read-time, pure, never persisted: the join depends on an
// analyst's attestation that can be revoked, and mergeDelta()'s window carries only synchronous
// timeline data (932.16's own correction), so this is the #993 / 932.16 / #1316 shape.
//
// THREE COLUMNS, KEPT APART. Requested is a manifest declaration (MobSF, per an ATTESTED report —
// a package name alone never binds a report to a device). Granted is a STORED STATE at collection
// time (Permission Store `Granted`, AppOps `Mode`), never a grant event. Used is a DATED AppOps
// access; a reject-dated row, a legacy per-mode clock and a proxied access are all listed but
// never count as use. Absence of a state row is a collection gap, never "not granted".
//
// TWO VOCABULARIES. Permission Store rows carry AOSP's full permission names
// (`android.permission.CAMERA`); AppOps rows carry op names from ALEAPP's own PERMISSION_OP /
// APP_OP_NAMES tables (`COARSE_LOCATION`, not `ACCESS_COARSE_LOCATION`). A row correlates at
// permission level only when its normalized name equals a requested permission's exactly; every
// other row stays at package level with VOCABULARY_SENTENCE. No op→permission table is invented
// here — a wrong-but-plausible match is the harm, and a table is where it would hide. There is
// therefore NO "used-not-requested" case: "this op is not in the manifest" cannot be told apart
// from "the names differ". The sha256 disagreement is the only "different build" signal made.

export const MAX_CHAINS = 500;
export const MAX_ROWS_PER_PERMISSION = 50;
export const MAX_PACKAGE_LEVEL_ROWS = 200;

export const VOCABULARY_SENTENCE =
  "AppOps op names and manifest permission names are different vocabularies; not correlated at permission level";
export const PACKAGE_LEVEL_NOTE: Record<PackageLevelReason, string> = {
  "different-vocabulary": VOCABULARY_SENTENCE,
  "not-requested": "a manifest-vocabulary permission the attested report(s) do not request",
  "no-attested-report": "no MobSF report is attested to this device for this package; nothing to join to",
};

export const MOBILE_PERMISSION_CHAIN_CAVEAT =
  "Presence only, never a verdict. An AppOps access timestamp is evidence the OS recorded a " +
  "permission operation for that package — never proof the user consciously granted it, never " +
  "proof of malicious use. A stored Granted/Mode value is a state at collection time, not a grant " +
  "event and not evidence of use. A proxied op is not the named package's own act. The requested " +
  "column's classification is MobSF's own knowledge-base label carried verbatim, never this pass's " +
  "grade. The device binding is the analyst's attestation, never verified; a matching package name " +
  "on an unattested report is not a binding. Pre-Android-15 devices keep grant state in " +
  "runtime-permissions.xml, which no landed artifact reads — a no-grant-record there is a " +
  "collection gap, not a state.";

export type GrantState = "granted" | "not-granted" | "conflicting" | "unrecognized" | "no-grant-record";
export type UsedOutcome = "accessed" | "rejected" | "legacy-clock" | "unknown";
export type ChainCase =
  | "requested-granted-used"
  | "requested-used"
  | "requested-granted"
  | "requested-not-granted"
  | "requested-state-conflict"
  | "requested-only";
export type HashAgreement = "agrees" | "disagrees" | "no-inventory-hash" | "no-report-hash";

export interface RequestedRow {
  asWritten: string;
  mobsfClassification: string;
  reportFingerprint: string;
  eventId: string;
}
export interface GrantedRow {
  artifact: string;
  column: string;
  value: string;
  read: "granted" | "not-granted" | "unrecognized";
  eventId: string;
  locator: string;
}
export interface UsedRow {
  artifact: string;
  at: string;
  outcome: UsedOutcome;
  /** `Op Mode` on a Recent Accesses row, verbatim: the op's CONFIGURED mode at collection time
   * (upstream reads the op element's `m`, written only when it differs from the default) — a
   * state, which is why the same row also lands in `granted`; carried here so a listed access is
   * read beside the mode the op now has. */
  mode?: string;
  proxied?: string;
  eventId: string;
  locator: string;
}
export interface PermissionChain {
  name: string;
  requested: RequestedRow[];
  granted: GrantedRow[];
  grantState: GrantState;
  used: UsedRow[];
  case: ChainCase;
}
export type PackageLevelReason = "different-vocabulary" | "not-requested" | "no-attested-report";
export interface PackageLevelRow {
  artifact: string;
  permissionAsWritten: string;
  /** Why the row is not on a permission chain: an AppOps op name (a different vocabulary from the
   * manifest's), a manifest-vocabulary name the attested report(s) do not request, or no attested
   * report at all for this package (code review F4). */
  permissionMatch: PackageLevelReason;
  kind: "state" | "dated";
  value?: string;
  at?: string;
  outcome?: UsedOutcome;
  proxied?: string;
  note: string;
  eventId: string;
  locator: string;
}
export interface BoundReport {
  fingerprint: string;
  attestationId: string;
  attestedBy: string;
  attestedAt: string;
  reportSha256?: string;
  hashAgreement: HashAgreement;
  note?: string;
  requested: number;
}
export interface PackageChain {
  package: string;
  reports: BoundReport[];
  permissions: PermissionChain[];
  packageLevel: PackageLevelRow[];
  usagePresence: number;
  proxiedRows: number;
  inventory?: { sha256: string };
  note?: string;
}
export interface MobilePermissionChains {
  device: string;
  chains: PackageChain[];
  unboundCandidates: { fingerprint: string; package: string; reason: string }[];
  boundButAbsent: { fingerprint: string; package: string; attestationId: string }[];
  diagnostics: {
    deviceRows: number;
    androidRows: number;
    attestations: number;
    truncated: ("chains" | "used" | "granted" | "packageLevel")[];
  };
  caveat: string;
}

export interface MobilePermissionChainInput {
  device: string;
  events: readonly ForensicEvent[];
  attestations: readonly MobsfAttestationShape[];
  aliasIndex?: HostAliasIndex;
}

const UNBOUND_REASON =
  "a report for this package name exists in the case but is not attested to this device — same name is not the same binary";
const ATTESTED_ELSEWHERE_REASON =
  "a report for this package name is attested to another device, not this one — same name is not the same binary";
const DISAGREE_NOTE = "the analyzed APK's sha256 differs from the installed build's inventory hash";

// The exact upstream vocabularies (design review F4). `Granted` is AOSP's isPermissionGranted
// port: Yes / No, else the raw flags. `Mode` / `Op Mode` is OP_MODES at android-15.0.0_r1:
// ALLOWED / IGNORED / ERRORED / DEFAULT / FOREGROUND, else the stored integer. FOREGROUND is an
// allow (foreground-only; the value stays visible). DEFAULT is no explicit mode — never granted.
function readState(column: string, value: string): GrantedRow["read"] {
  const v = value.trim();
  if (column === "Granted") return v === "Yes" ? "granted" : v === "No" ? "not-granted" : "unrecognized";
  if (v === "ALLOWED" || v === "FOREGROUND") return "granted";
  if (v === "IGNORED" || v === "ERRORED") return "not-granted";
  return "unrecognized";
}

const STATE_COLUMNS = new Set(["Granted", "Mode", "Op Mode"]);

function grantStateOf(rows: readonly GrantedRow[]): GrantState {
  if (rows.length === 0) return "no-grant-record";
  const reads = new Set(rows.map((r) => r.read));
  if (reads.has("granted") && reads.has("not-granted")) return "conflicting";
  if (reads.has("granted")) return "granted";
  if (reads.has("not-granted")) return "not-granted";
  return "unrecognized";
}

function caseOf(requested: boolean, state: GrantState, used: boolean): ChainCase {
  if (!requested) return "requested-only"; // unreachable by construction: chains are keyed on requested names
  if (state === "conflicting") return "requested-state-conflict";
  if (state === "not-granted") return "requested-not-granted";
  if (used) return state === "granted" ? "requested-granted-used" : "requested-used";
  return state === "granted" ? "requested-granted" : "requested-only";
}

function outcomeOf(clockColumn: string | undefined): UsedOutcome {
  if (!clockColumn) return "unknown";
  if (clockColumn === "Access Timestamp") return "accessed";
  if (clockColumn === "Reject Timestamp") return "rejected";
  if (/^Timestamp T[A-Z]+$/.test(clockColumn)) return "legacy-clock";
  return "unknown";
}

/** Prefix stripped, case-folded: the only normalization; equality is exact after it. */
function normalizeName(raw: string): string {
  return raw
    .trim()
    .replace(/^android\.permission\./i, "")
    .toUpperCase();
}

function locatorOf(e: ForensicEvent): string {
  return e.canonical?.evidence?.rawRecords?.[0]?.locator ?? "";
}

const evidenceOf = (e: ForensicEvent, facet: string) =>
  e.canonical?.mobile?.evidence.find((ev) => ev.facet === facet);

interface DeviceRow {
  event: ForensicEvent;
  pkg: string;
  record: string;
  artifact: string;
  permission?: string;
  proxy?: string;
  clock?: string;
  access?: { column: string; value: string };
  sha256?: string;
}

interface Group {
  display: string;
  rows: DeviceRow[];
}

/**
 * The chains for one subject device: every Android package the device's own rows name, joined to
 * the requested permissions of the MobSF reports the analyst attested to that device. Pure.
 */
export function mobilePermissionChains(input: MobilePermissionChainInput): MobilePermissionChains {
  const canon = (raw: string) =>
    input.aliasIndex ? resolveHost(input.aliasIndex, raw) : canonicalHostName(raw);
  const device = canon(input.device);
  const truncated = new Set<MobilePermissionChains["diagnostics"]["truncated"][number]>();

  // ── the device's own rows, by package ──
  const groups = new Map<string, Group>();
  let deviceRows = 0;
  let androidRows = 0;
  for (const e of input.events) {
    const m = e.canonical?.mobile;
    if (!m || !e.asset || canon(e.asset) !== device) continue;
    deviceRows++;
    if (m.platform !== "android") continue;
    androidRows++;
    const pkg = m.app?.package?.trim();
    if (!pkg) continue;
    const key = pkg.toLowerCase();
    let g = groups.get(key);
    if (!g) {
      g = { display: pkg, rows: [] };
      groups.set(key, g);
    }
    const access = evidenceOf(e, "access");
    g.rows.push({
      event: e,
      pkg,
      record: m.facets.record,
      artifact: m.artifact,
      ...(m.permission ? { permission: m.permission } : {}),
      ...(m.proxy?.package ? { proxy: m.proxy.package } : {}),
      ...(m.clock?.column ? { clock: m.clock.column } : {}),
      ...(access ? { access: { column: access.column, value: access.value } } : {}),
      ...(m.app?.sha256 ? { sha256: m.app.sha256.toLowerCase() } : {}),
    });
  }

  // ── the attested reports for this device, and every MobSF report in the case ──
  const active = input.attestations.filter(
    (a) => a.tool === "mobsf" && !a.revokedAt && canon(a.subjectHost) === device,
  );
  const attestationByFingerprint = new Map<string, MobsfAttestationShape>();
  for (const a of active) attestationByFingerprint.set(a.reportFingerprint.toLowerCase(), a);
  const attestedElsewhere = new Set(
    input.attestations
      .filter((a) => a.tool === "mobsf" && !a.revokedAt && canon(a.subjectHost) !== device)
      .map((a) => a.reportFingerprint.toLowerCase()),
  );

  interface Report {
    fingerprint: string;
    pkg: string;
    sha256?: string;
    rows: { event: ForensicEvent; asWritten: string; classification: string }[];
  }
  const reports = new Map<string, Report>();
  for (const e of input.events) {
    const b = e.canonical?.mobileRequestedPermission;
    if (!b || b.platform !== "android") continue;
    const fp = b.reportFingerprint.toLowerCase();
    let r = reports.get(fp);
    if (!r) {
      r = {
        fingerprint: fp,
        pkg: b.packageName.trim(),
        ...(b.sampleHash?.sha256 ? { sha256: b.sampleHash.sha256.toLowerCase() } : {}),
        rows: [],
      };
      reports.set(fp, r);
    }
    r.rows.push({ event: e, asWritten: b.permission, classification: b.status });
  }

  const unboundCandidates: MobilePermissionChains["unboundCandidates"] = [];
  const boundButAbsent: MobilePermissionChains["boundButAbsent"] = [];
  const boundByPackage = new Map<string, Report[]>();
  for (const r of reports.values()) {
    const key = r.pkg.toLowerCase();
    const att = attestationByFingerprint.get(r.fingerprint);
    if (!att) {
      if (groups.has(key))
        unboundCandidates.push({
          fingerprint: r.fingerprint,
          package: r.pkg,
          reason: attestedElsewhere.has(r.fingerprint) ? ATTESTED_ELSEWHERE_REASON : UNBOUND_REASON,
        });
      continue;
    }
    if (!groups.has(key)) {
      boundButAbsent.push({ fingerprint: r.fingerprint, package: r.pkg, attestationId: att.id });
      continue;
    }
    boundByPackage.set(key, [...(boundByPackage.get(key) ?? []), r]);
  }

  // ── chains ──
  const chains: PackageChain[] = [];
  const keys = [...groups.keys()].sort();
  if (keys.length > MAX_CHAINS) truncated.add("chains");
  for (const key of keys.slice(0, MAX_CHAINS)) {
    const g = groups.get(key)!;
    const inventorySha = g.rows.find((r) => r.record === "app-inventory" && r.sha256)?.sha256;
    const bound = boundByPackage.get(key) ?? [];

    const boundReports: BoundReport[] = bound.map((r) => {
      const att = attestationByFingerprint.get(r.fingerprint)!;
      const digest = att.documentSha256 ?? att.toolReportedSha256 ?? r.sha256;
      // "disagrees" only when two real sha256 values were compared (code review F3).
      const hashAgreement: HashAgreement = !inventorySha
        ? "no-inventory-hash"
        : !digest
          ? "no-report-hash"
          : digest.toLowerCase() === inventorySha
            ? "agrees"
            : "disagrees";
      return {
        fingerprint: r.fingerprint,
        attestationId: att.id,
        attestedBy: att.attestedBy,
        attestedAt: att.attestedAt,
        ...(digest ? { reportSha256: digest.toLowerCase() } : {}),
        hashAgreement,
        ...(hashAgreement === "disagrees" ? { note: DISAGREE_NOTE } : {}),
        requested: r.rows.length,
      };
    });

    // Requested names, per report (design review F5: every report listed, each name says which).
    const requestedByName = new Map<string, RequestedRow[]>();
    for (const r of bound) {
      for (const row of r.rows) {
        const name = normalizeName(row.asWritten);
        if (!name) continue;
        requestedByName.set(name, [
          ...(requestedByName.get(name) ?? []),
          {
            asWritten: row.asWritten,
            mobsfClassification: row.classification,
            reportFingerprint: r.fingerprint,
            eventId: row.event.id,
          },
        ]);
      }
    }

    const grantedByName = new Map<string, GrantedRow[]>();
    const usedByName = new Map<string, UsedRow[]>();
    const packageLevel: PackageLevelRow[] = [];
    let usagePresence = 0;
    let proxiedRows = 0;
    for (const r of g.rows) {
      if (r.record === "usage") {
        usagePresence++;
        continue;
      }
      if (r.record !== "permission" || !r.permission) continue;
      if (r.proxy) proxiedRows++;
      const name = normalizeName(r.permission);
      const locator = locatorOf(r.event);
      // A row is a USED row when it is dated, and a STATE row when its artifact declares a
      // state column (`Granted`, `Mode`, `Op Mode` — all configured/stored values, verified
      // against upstream: Recent Accesses' `Op Mode` is the op element's `m`, not the mode at
      // the access). Both are artifact facts from the registry, never the facet's name alone
      // (design review F9); one Recent Accesses row can be both (code review F2/F6).
      const dated = Boolean(r.clock);
      const isState = Boolean(r.access && STATE_COLUMNS.has(r.access.column));
      if (!requestedByName.has(name)) {
        if (packageLevel.length >= MAX_PACKAGE_LEVEL_ROWS) {
          truncated.add("packageLevel");
          continue;
        }
        // An op name never carries a dot; a manifest-vocabulary name always does.
        const reason: PackageLevelReason =
          bound.length === 0
            ? "no-attested-report"
            : r.permission.includes(".")
              ? "not-requested"
              : "different-vocabulary";
        packageLevel.push({
          artifact: r.artifact,
          permissionAsWritten: r.permission,
          permissionMatch: reason,
          kind: dated ? "dated" : "state",
          ...(!dated && r.access ? { value: r.access.value } : {}),
          ...(dated ? { at: r.event.timestamp, outcome: outcomeOf(r.clock) } : {}),
          ...(r.proxy ? { proxied: r.proxy } : {}),
          note: PACKAGE_LEVEL_NOTE[reason],
          eventId: r.event.id,
          locator,
        });
        continue;
      }
      if (isState) {
        const list = grantedByName.get(name) ?? [];
        if (list.length >= MAX_ROWS_PER_PERMISSION) truncated.add("granted");
        else {
          list.push({
            artifact: r.artifact,
            column: r.access!.column,
            value: r.access!.value,
            read: readState(r.access!.column, r.access!.value),
            eventId: r.event.id,
            locator,
          });
          grantedByName.set(name, list);
        }
      }
      if (dated) {
        const list = usedByName.get(name) ?? [];
        if (list.length >= MAX_ROWS_PER_PERMISSION) {
          truncated.add("used");
          continue;
        }
        list.push({
          artifact: r.artifact,
          at: r.event.timestamp,
          outcome: outcomeOf(r.clock),
          ...(r.access?.column === "Op Mode" ? { mode: r.access.value } : {}),
          ...(r.proxy ? { proxied: r.proxy } : {}),
          eventId: r.event.id,
          locator,
        });
        usedByName.set(name, list);
      }
    }

    const permissions: PermissionChain[] = [...requestedByName.keys()].sort().map((name) => {
      const granted = grantedByName.get(name) ?? [];
      const used = usedByName.get(name) ?? [];
      const grantState = grantStateOf(granted);
      // Only an un-proxied ACCESS is a use (design review F7; the reject/legacy rows are listed).
      const anyUse = used.some((u) => u.outcome === "accessed" && !u.proxied);
      return {
        name,
        requested: requestedByName.get(name)!,
        granted,
        grantState,
        used,
        case: caseOf(true, grantState, anyUse),
      };
    });

    chains.push({
      package: g.display,
      reports: boundReports,
      permissions,
      packageLevel,
      usagePresence,
      proxiedRows,
      ...(inventorySha ? { inventory: { sha256: inventorySha } } : {}),
      ...(boundReports.length > 1
        ? {
            note: `${boundReports.length} attested reports name this package (two attested reports or more); each requested permission says which report(s) requested it`,
          }
        : {}),
    });
  }

  return {
    device,
    chains,
    unboundCandidates,
    boundButAbsent,
    diagnostics: {
      deviceRows,
      androidRows,
      attestations: active.length,
      truncated: [...truncated],
    },
    caveat: MOBILE_PERMISSION_CHAIN_CAVEAT,
  };
}
