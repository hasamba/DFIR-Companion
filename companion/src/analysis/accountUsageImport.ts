// Windows.EventLogs.CondensedAccountUsage — one row per authentication event, already condensed by
// the artifact into flat columns (EventID, UserName, LogonType, IpAddress, ClientName …) with no
// parsed `System`/`EventData` block underneath.
//
// That missing block is the whole problem. velociraptorImport's classify() finds no Windows record,
// so the row falls through to the generic key=value mapper, which keeps only the artifact's own
// `Description` verb and drops every column that identifies WHO. The result on a benchmark
// collection: 46 rows became 7 events, each reading "ACCOUNT_LOGGED_ON @ DESKTOP-LAB01" — no
// account, no logon type, no source. Worse than unreadable, it is wrong: because the agg key was
// (artifact, host, verb), every logon by every user on a host folded into a single event, so a
// service logon and an administrator's RDP session were indistinguishable from each other.
//
// This mapper reads the columns the artifact actually ships and renders them in the SAME grammar a
// parsed 4624 uses ("Successful logon (EID 4624) - DOMAIN\\user - LogonType=2 - IpAddress=…"), which
// is the form canonicalEvent's legacy upgrader already parses — so these rows join the Login Graph
// instead of sitting outside it.
//
// Kept out of velociraptorImport.ts, which is frozen at its current size by the file-size ledger
// (#384) — see check-file-size.mjs.
import {
  str,
  getCI,
  worst,
  logonRisk,
  WIN_EVENTS,
  type MappedEvent,
  type SiemIoc,
  addIoc,
  cleanIp,
  normalizeTime,
} from "./siemImport.js";
import type { Severity } from "./stateTypes.js";
import { isNoiseAccount } from "./loginGraph.js";
import { withHostSuffix } from "./velociraptorTitle.js";

type Row = Record<string, unknown>;

// The artifact writes "-" for every field an event did not carry. Treated as absent everywhere.
function field(row: Row, key: string): string {
  const v = str(getCI(row, key)).trim();
  return v === "-" ? "" : v;
}

/**
 * Is this a CondensedAccountUsage row?
 *
 * `CredentialsUsedFor4648` is the artifact's own invented column name and appears in no other
 * Velociraptor artifact, which makes it a safe signature even on an export that lost its `_Source`
 * marker. EventID is required alongside it so a hand-built row carrying the name alone cannot
 * reach a mapper that assumes an event id.
 */
export function isAccountUsageRow(row: Row): boolean {
  return getCI(row, "CredentialsUsedFor4648") != null && getCI(row, "EventID") != null;
}

// The artifact's own verb, for an EID the shared table does not cover. ACCOUNT_INITITATED_LOGOFF is
// the artifact's spelling, typo included — normalising it here keeps the display readable without
// pretending the source said something else.
function fallbackLabel(description: string): string {
  const words = description.trim().replace(/_/g, " ").toLowerCase();
  return words ? words.charAt(0).toUpperCase() + words.slice(1) : "Account usage";
}

/** DOMAIN\user when the row carries both, else whichever it has. */
function accountName(row: Row): string {
  const user = field(row, "UserName");
  const domain = field(row, "DomainName");
  if (!user) return domain;
  return domain && domain.toLowerCase() !== user.toLowerCase() ? `${domain}\\${user}` : user;
}

/**
 * Map one condensed account-usage row.
 *
 * SEVERITY comes from the shared per-EID table, so a condensed event is graded the way a parsed one
 * is, with two overlays: logonRisk for a successful logon's type and source, and one narrow floor on
 * 4648 (see below). A human running `runas`, or an operator moving laterally with stolen
 * credentials, appears as `DOMAIN\user`, never as `HOST$`.
 */
export function mapAccountUsage(row: Row, artifact: string, host: string, sink: Map<string, SiemIoc>) {
  const eid = Number(str(getCI(row, "EventID")).trim());
  const def = Number.isInteger(eid) ? WIN_EVENTS[eid] : undefined;
  const label = def?.label ?? fallbackLabel(str(getCI(row, "Description")));
  const account = accountName(row);
  const target = field(row, "CredentialsUsedFor4648"); // 4648 only: whose credentials were presented
  // Two readings of the same column. `rawIp` is what the log recorded and belongs in the
  // description — "IpAddress=127.0.0.1" tells the analyst the logon was local, which is a finding in
  // itself. `ip` is cleanIp's version, which drops loopback and other non-routable noise, and is the
  // only one allowed to become an indicator or to feed logonRisk.
  const rawIp = field(row, "IpAddress");
  const ip = cleanIp(rawIp);
  const client = field(row, "ClientName");
  const authPackage = field(row, "AuthenticationPackageName");
  const rawType = field(row, "LogonType");
  const logonType = /^\d+$/.test(rawType) ? Number(rawType) : undefined;

  let severity: Severity = def?.severity ?? "Info";
  let mitre = [...(def?.mitre ?? [])];
  // A successful logon's real signal is its TYPE and source — RDP, cleartext, runas /netonly — which
  // logonRisk already grades for every other importer. Reuse it rather than re-deciding here.
  if (eid === 4624 && logonType !== undefined) {
    const risk = logonRisk(logonType, ip);
    if (risk.severity) severity = worst(severity, risk.severity);
    for (const id of risk.mitre) if (!mitre.includes(id)) mitre.push(id);
  }
  // Windows raises 4648 on every boot as the local session starts: the machine account presents
  // credentials for the font-driver and window-manager session principals. The shared table's Medium
  // is written for the PARSED event, where the subject process and target server justify it; on a
  // condensed row those are absent and the boot pattern dominates, so a 4648 whose principal is not
  // a real user drops to Info. Scoped to 4648 on purpose — the same account on a 4625 is a failed
  // authentication and keeps its Medium/T1110, which is evidence in its own right.
  if (eid === 4648 && isNoiseAccount(account)) {
    severity = "Info";
    mitre = [];
  }

  // Same key=value grammar a parsed Windows logon uses, so canonicalEvent's legacy upgrader can
  // recover the account, logon type and source from it and the Login Graph picks these rows up.
  const parts = [`${label} (EID ${eid || "?"})`];
  if (account) parts.push(account);
  if (target) parts.push(`TargetAccount=${target}`);
  if (logonType !== undefined) parts.push(`LogonType=${logonType}`);
  if (rawIp) parts.push(`IpAddress=${rawIp}`);
  if (client && client.toLowerCase() !== host.toLowerCase()) parts.push(`WorkstationName=${client}`);
  if (authPackage) parts.push(`AuthenticationPackage=${authPackage}`);
  // LogonId is deliberately NOT rendered. It is unique per session, so it is not in the agg key
  // either — and printing one member's session id on an event that folds thirteen of them would
  // read as a specific fact about all thirteen when it is true of exactly one.
  let description = `Velociraptor${artifact ? ` [${artifact}]` : ""}: ${parts.join(" - ")}`;
  description = withHostSuffix(description, host);
  const typeName = logonType !== undefined ? logonRisk(logonType, ip).typeName : "";
  if (typeName) description += ` [${typeName}]`;

  if (ip) addIoc(sink, "ip", ip);

  // Every field the description RENDERS is in the key. The old key was (artifact, host, verb), which
  // is why 46 rows collapsed to 7 — repeats of the SAME logon should fold and be counted, two
  // different accounts should not. The authentication package is in here for the same reason it is
  // in the description: NTLM where Kerberos is expected is a finding, and folding an NTLM logon into
  // a Negotiate one would print the surviving row's package over every occurrence.
  const aggKey =
    `vr|acctusage|${host.toLowerCase()}|${eid}|${account.toLowerCase()}|${target.toLowerCase()}|${rawType.toLowerCase()}|${rawIp.toLowerCase()}|${client.toLowerCase()}|${authPackage.toLowerCase()}`.slice(
      0,
      400,
    );

  const event: MappedEvent = {
    timestamp: normalizeTime(str(getCI(row, "EventTime"))),
    description: description.slice(0, 600),
    severity,
    mitre,
    aggKey,
    sources: ["Velociraptor"],
    ...(host ? { asset: host } : {}),
    ...(ip ? { srcIp: ip } : {}),
  };
  return event;
}
