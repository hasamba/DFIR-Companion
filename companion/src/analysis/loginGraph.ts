import type { ForensicEvent } from "./stateTypes.js";
import { LOGON_TYPES, logonRisk } from "./siemImport.js";

// Builds the Login Graph (Timesketch-style directed account → host logon graph) from the
// super-timeline. PARSES the deterministic descriptions mapWindows() rendered at import time
// ("{tool} Successful logon (EID 4624) - DOMAIN\\user - LogonType=N - IpAddress=… @ host") —
// no new import-time field, so existing stored cases get the graph with no re-import.
// Pure + deterministic, no AI, no I/O. Sibling of assetGraph.ts.

const LOGON_MARKER = /(Successful|Failed) logon \(EID (?:4624|4625)\)/;

export interface ParsedLogon {
  account: string;                  // full form as rendered, e.g. "CORP\\jdoe", "NT AUTHORITY\\SYSTEM"
  host: string;                     // the event's asset (the machine logged ONTO)
  logonType?: number;
  typeName: string;                 // decoded LOGON_TYPES name, "type N", or "Unknown"
  outcome: "success" | "failed";
  sourceIp?: string;
  workstation?: string;
}

// Parse one super-timeline row. Returns null when the row is not a 4624/4625 logon, carries no
// account segment, or has no asset — malformed rows are skipped, never fatal.
export function parseLoginEvent(e: ForensicEvent): ParsedLogon | null {
  const m = LOGON_MARKER.exec(e.description);
  if (!m) return null;
  const host = (e.asset ?? "").trim();
  if (!host) return null;
  // Accounts segment: everything after the marker up to the first `Key=value` field, the ` @ host`
  // suffix, or the 4624 ` [TypeName …]` overlay. mapWindows renders accounts (when present) as the
  // first ` - `-joined segment, comma-separated, TARGET account first (winAccounts pair order).
  const rest = e.description.slice(m.index + m[0].length);
  const seg = rest.replace(/^ - /, "").split(/ - (?=[A-Za-z]+=)| @ | \[/)[0]?.trim() ?? "";
  const account = seg.split(", ")[0]?.trim();
  if (!account || account.includes("=")) return null;   // no accounts rendered on this row
  const lt = /\bLogonType=(\d+)\b/.exec(e.description);
  const logonType = lt ? Number(lt[1]) : undefined;
  const ip = /\bIpAddress=(\S+)/.exec(e.description)?.[1];
  const ws = /\bWorkstationName=(\S+)/.exec(e.description)?.[1];
  return {
    account,
    host,
    ...(logonType !== undefined ? { logonType } : {}),
    typeName: logonType !== undefined ? (LOGON_TYPES[logonType] ?? `type ${logonType}`) : "Unknown",
    outcome: m[1] === "Successful" ? "success" : "failed",
    ...(ip ? { sourceIp: ip } : {}),
    ...(ws ? { workstation: ws } : {}),
  };
}

// Service/virtual domains whose prefix adds no signal — display "SYSTEM", not "NT AUTHORITY\SYSTEM"
// (matches the Timesketch reference UI). Node IDs keep the full form; only display shortens.
const SERVICE_DOMAINS = /^(NT AUTHORITY|Window Manager|Font Driver Host)\\/i;
export function displayAccountName(account: string): string {
  return account.replace(SERVICE_DOMAINS, "");
}

// Noise accounts for the one-click filter: machine accounts (name$), window-manager /
// font-driver session accounts, ANONYMOUS LOGON. SYSTEM / LOCAL SERVICE / NETWORK SERVICE are
// NOT noise — service-logon edges are meaningful (see the Timesketch reference graph).
export function isNoiseAccount(account: string): boolean {
  const user = account.split("\\").pop() ?? account;
  return /\$$/.test(user) || /^(DWM|UMFD)-\d+$/i.test(user) || /^ANONYMOUS LOGON$/i.test(user);
}
