// Windows Error Reporting: Report.wer files and the Application Error event log (#909 item 5).
//
// A crash is a lead nobody collects. When a credential-dumping tool fails against a hardened LSASS,
// when an exploit lands on the wrong build, when an injected DLL faults inside a host process, the
// machine writes down the application path, the faulting module, and every module that was loaded
// at the time — and it does so even when process auditing is off entirely. On a host with no Sysmon
// and cleared security logs, a WER report can be the only record that a tool ran at all.
//
// ─────────────────────────── WHAT A CRASH DOES AND DOES NOT PROVE ───────────────────────────
//
// It proves an application was RUNNING and that it faulted. It does not prove exploitation, and it
// does not prove the crash was the attacker's — software crashes constantly. So these rows arrive
// as evidence, and the grade rises only on the location of the binary or its faulting module, never
// on the fact of the crash. Routine application failures must not escalate, or every Office hang on
// the estate becomes a finding.
//
// ─────────────────────────── READING THE FORMAT CORRECTLY ───────────────────────────
//
// Report.wer is an INI-ish list of `Key=Value` lines, usually UTF-16LE with a BOM. The trap is the
// signature block:
//
//   Sig[0].Name=Application Name      Sig[0].Value=rundll32.exe
//   Sig[3].Name=Fault Module Name     Sig[3].Value=evil.dll
//
// The INDEX is not stable. Microsoft assigns the parameters per EventType — APPCRASH, BEX,
// APPHANGB1 and the rest each order them differently, and a bucket can carry vendor-defined
// parameters. Reading Sig[3] as "the faulting module" is right for APPCRASH and wrong elsewhere, so
// every parameter here is resolved by its NAME.
//
// EventTime is a FILETIME — 100-nanosecond ticks since 1601 — parsed with BigInt because the value
// exceeds what a double holds exactly.

import type { Severity } from "./stateTypes.js";

export interface WerLoadedModule {
  path: string;
  name: string;
}

export interface WerReport {
  eventType: string; // APPCRASH, BEX, APPHANGB1, …
  appName: string;
  appPath: string;
  appVersion: string;
  faultModuleName: string;
  faultModulePath: string;
  exceptionCode: string;
  reportId: string; // shared with the Application Error event — the dedup key
  time: string; // ISO, from EventTime; "" when unreadable
  loadedModules: WerLoadedModule[];
  hashes: string[]; // only when the report actually carried one
  processId: string;
}

// Where each parameter sits, per EventType, when the NAMES are localized and unreadable.
// Microsoft assigns these orderings; they differ between bucket types, which is exactly why an
// index cannot be the primary lookup. Only the slots this module reads are listed.
const SIG_LAYOUTS = {
  APPCRASH: { appName: 0, appVersion: 1, modName: 3, exceptionCode: 6 },
  BEX: { appName: 0, appVersion: 1, modName: 3, exceptionCode: 7 },
  BEX64: { appName: 0, appVersion: 1, modName: 3, exceptionCode: 7 },
  APPHANGB1: { appName: 0, appVersion: 1, modName: undefined, exceptionCode: undefined },
  APPHANGXPROCB1: { appName: 0, appVersion: 1, modName: undefined, exceptionCode: undefined },
} as const;

const MAX_INPUT = 2 * 1024 * 1024;
const MAX_MODULES = 500;

// FILETIME epoch (1601-01-01) to Unix epoch, in milliseconds.
const FILETIME_EPOCH_OFFSET_MS = 11644473600000n;

/** Convert a FILETIME tick count to an ISO timestamp, or "" when it is not one. */
export function filetimeToIso(raw: string): string {
  const s = String(raw ?? "").trim();
  if (!/^\d{15,20}$/.test(s)) return "";
  try {
    const ms = BigInt(s) / 10000n - FILETIME_EPOCH_OFFSET_MS;
    // Reject the zero date and anything outside a plausible range rather than emitting 1601.
    if (ms <= 0n || ms > 4102444800000n) return "";
    // Milliseconds are KEPT: they order two crashes in the same second, and the fallback dedup
    // key uses the timestamp when no identifier was recorded.
    return new Date(Number(ms)).toISOString();
  } catch {
    return "";
  }
}

function baseName(p: string): string {
  return String(p ?? "")
    .trim()
    .replace(/[\\/]+$/, "")
    .split(/[\\/]/)
    .pop()!;
}

/** True when the text looks like a Report.wer rather than some other key=value file. */
export function isWerReport(text: string): boolean {
  const head = String(text ?? "").slice(0, 4096);
  // EventType plus either a signature block or the WER-specific report identifier. `Version=` and
  // `Consent=` alone appear in plenty of unrelated INI files.
  return /^\s*(?:﻿)?[\s\S]{0,2000}?\bEventType=/.test(head) && /\bSig\[\d+\]\.Name=|\bReportIdentifier=|\bConsent=/.test(head);
}

/**
 * Parse a Report.wer.
 *
 * Signature parameters are resolved by NAME, never by index — see the header for why.
 */
export function parseWerReport(text: string): WerReport | null {
  const src = String(text ?? "").slice(0, MAX_INPUT);
  if (!src.trim()) return null;

  const kv = new Map<string, string>();
  const sigNames = new Map<string, string>(); // index → parameter name
  const sigValues = new Map<string, string>(); // index → parameter value
  const loaded: WerLoadedModule[] = [];

  for (const rawLine of src.split(/\r?\n/)) {
    const line = rawLine.replace(/^﻿/, "").trim();
    if (!line || line.startsWith(";") || line.startsWith("[")) continue;
    const eq = line.indexOf("=");
    if (eq <= 0) continue;
    const key = line.slice(0, eq).trim();
    const value = line.slice(eq + 1).trim();

    let m: RegExpExecArray | null;
    if ((m = /^Sig\[(\d+)\]\.Name$/i.exec(key))) {
      sigNames.set(m[1], value);
      continue;
    }
    if ((m = /^Sig\[(\d+)\]\.Value$/i.exec(key))) {
      sigValues.set(m[1], value);
      continue;
    }
    if (/^LoadedModule\[\d+\]$/i.test(key)) {
      if (loaded.length < MAX_MODULES && value) loaded.push({ path: value, name: baseName(value) });
      continue;
    }
    if (!kv.has(key)) kv.set(key, value);
  }

  if (!kv.has("EventType") && sigNames.size === 0) return null;

  // Resolve a signature parameter by its declared NAME, then — only if that fails — by the
  // documented position for this EventType.
  //
  // The names are LOCALIZED. A German host writes `Anwendungsname`, not `Application Name`, so a
  // name-only lookup returns nothing at all on most of the world's Windows installs and the report
  // silently parses to empty fields. The positional fallback is what rescues those, and it is
  // scoped per EventType because the ordering differs between them — which is also why it cannot be
  // the primary strategy.
  const sig = (slot: keyof (typeof SIG_LAYOUTS)["APPCRASH"], ...names: string[]): string => {
    for (const [idx, n] of sigNames) {
      if (names.some((want) => n.toLowerCase() === want.toLowerCase())) {
        const v = sigValues.get(idx);
        if (v) return v;
      }
    }
    const layout = SIG_LAYOUTS[(kv.get("EventType") ?? "").toUpperCase() as keyof typeof SIG_LAYOUTS];
    const pos = layout?.[slot];
    return pos === undefined ? "" : (sigValues.get(String(pos)) ?? "");
  };

  const appName =
    sig("appName", "Application Name", "AppName") ||
    kv.get("NsAppName") ||
    kv.get("OriginalFilename") ||
    kv.get("AppName") ||
    "";
  // AppPath is the usual carrier; UI[2] holds the full path in reports that omit it.
  const appPath = kv.get("AppPath") || kv.get("TargetAppPath") || kv.get("UI[2]") || "";
  const faultModuleName = sig("modName", "Fault Module Name", "ModName");
  // The full path of the faulting module is not a signature parameter; it is whichever loaded
  // module carries that basename.
  const faultModulePath =
    faultModuleName
      ? (loaded.find((l) => l.name.toLowerCase() === faultModuleName.toLowerCase())?.path ?? "")
      : "";

  // Hashes appear only in some report shapes. Reporting one that is not there would invent evidence.
  const hashes: string[] = [];
  for (const [k, v] of kv) {
    if (/hash/i.test(k) && /^[a-f0-9]{32,128}$/i.test(v)) hashes.push(v.toLowerCase());
  }

  return {
    eventType: kv.get("EventType") ?? "",
    appName,
    appPath,
    appVersion: sig("appVersion", "Application Version", "AppVersion"),
    faultModuleName,
    faultModulePath,
    exceptionCode: sig("exceptionCode", "Exception Code", "ExceptionCode"),
    // The paired Application Error record's "Report Id" is the INTEGRATOR identifier, not the
    // report's own ReportIdentifier. Keying on the latter meant the file and its event log record
    // never matched and the crash appeared twice — the deduplication this item asks for.
    reportId:
      kv.get("IntegratorReportIdentifier") || kv.get("ReportIdentifier") || kv.get("ReportId") || "",
    time: filetimeToIso(kv.get("EventTime") ?? ""),
    loadedModules: loaded,
    hashes,
    // Most report types record a session GUID or a sequence number rather than a PID, so this is
    // usually empty. It is read where present and never inferred from TargetAsId, which Microsoft
    // documents as a sequence number.
    processId: kv.get("TargetProcessId") || kv.get("ProcessId") || "",
  };
}

// ─────────────────────────── grading ───────────────────────────

// Locations a legitimately-installed program does not run from.
//
// Deliberately NARROWER than the obvious list. `\ProgramData\` holds Windows Defender, most
// endpoint agents and many updaters — the repo's own fixtures treat a Defender path there as
// legitimate — and a bare `\temp\` matches every installer's scratch directory. Including either
// escalated routine crashes across an entire estate, which is precisely what the issue says not to
// do. What is left is user-writable space that an installed product does not execute from.
const SUSPICIOUS_LOCATION =
  /\\(?:users\\[^\\]+\\(?:downloads|desktop)|users\\[^\\]+\\appdata\\local\\temp|windows\\temp|windows\\tasks|users\\public|\$recycle\.bin|perflogs)\\/i;

export interface WerSignal {
  severity: Severity;
  mitre: string[];
  reason: string;
}

/**
 * What the case already knows, so a crash can be weighed against it.
 *
 * The issue asks for crashes to be correlated with execution evidence and activity already under
 * investigation. Without this the grade rests on a path heuristic alone, which is both noisier and
 * weaker than the evidence the case already holds.
 */
export interface WerCaseContext {
  processNames?: ReadonlySet<string>; // lowercased binary names already under investigation
  paths?: ReadonlySet<string>; // lowercased full paths already under investigation
}

/**
 * Grade a parsed report.
 *
 * Deliberately narrow. The FACT of a crash is never the finding — software crashes constantly, and
 * escalating that would bury the rare real one under every Office hang on the estate. Only the
 * LOCATION of the crashed binary or its faulting module raises the grade.
 */
export function werSignal(r: WerReport, ctx: WerCaseContext = {}): WerSignal | null {
  const known = (p: string, n: string): boolean =>
    (!!p && !!ctx.paths?.has(p.toLowerCase())) || (!!n && !!ctx.processNames?.has(n.toLowerCase()));

  // Already under investigation: the strongest reason to surface a crash, and it needs no path
  // heuristic at all.
  const appKnown = known(r.appPath, r.appName || baseName(r.appPath));
  const modKnown = known(r.faultModulePath, r.faultModuleName);
  if (appKnown || modKnown) {
    return {
      severity: "Medium",
      mitre: [],
      reason:
        `${appKnown ? "the crashed binary" : "the faulting module"} is already under investigation ` +
        "in this case. A crash shows the application was running and faulted — it does not show " +
        "exploitation, and it does not show the crash was hostile.",
    };
  }

  const appSuspicious = SUSPICIOUS_LOCATION.test(r.appPath);
  const modSuspicious = SUSPICIOUS_LOCATION.test(r.faultModulePath);
  if (!appSuspicious && !modSuspicious) return null;

  const where = appSuspicious ? r.appPath : r.faultModulePath;
  return {
    severity: "Medium",
    // No ATT&CK technique. A binary's LOCATION is not a technique: T1204 is user execution, which
    // describes how something was launched, and a crash report says nothing about that. Tagging it
    // would put an unsupported technique in the case's MITRE table.
    mitre: [],
    reason:
      `${appSuspicious ? "the crashed binary" : "the faulting module"} ran from ${where}, which is a ` +
      "user-writable location rather than an install directory. A crash shows the application was " +
      "running and faulted — it does not show exploitation, and it does not show the crash was hostile.",
  };
}

/** The one-line description a report becomes. */
export function werDescription(r: WerReport): string {
  const what = r.appName || baseName(r.appPath) || "(unknown application)";
  const parts = [`WER ${r.eventType || "crash"}: ${what}`];
  if (r.appPath) parts.push(`(${r.appPath})`);
  if (r.faultModuleName) parts.push(`faulted in ${r.faultModuleName}`);
  if (r.exceptionCode) parts.push(`exception ${r.exceptionCode}`);
  if (r.loadedModules.length) parts.push(`${r.loadedModules.length} loaded module(s) recorded`);
  return parts.join(" ").slice(0, 600);
}

/**
 * The key that identifies one crash across its several records.
 *
 * Windows writes the same crash more than once: Application Error event 1000, the Windows Error
 * Reporting event 1001, and the Report.wer on disk. They share the report identifier, so importing
 * a triage collection that contains all three produces one row rather than three.
 */
export function werDedupKey(r: { reportId?: string; appName?: string; time?: string }): string {
  if (r.reportId) return `wer|${r.reportId.toLowerCase()}`;
  return `wer|${(r.appName ?? "").toLowerCase()}|${r.time ?? ""}`;
}
