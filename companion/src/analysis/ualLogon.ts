// The two sign-in shapes an m365 export can hold, read into typed facts for the mailbox chain
// (#931 item 2, chain half — #975): the UAL STS logon (`UserLoggedIn`, RecordType 15) and the Entra
// interactive sign-in (`signIns`). Neither is a mailbox record; the chain joins them to one only by
// the identifiers the records carry, and says which.

import { cleanIp, getCI, isObject, str } from "./siemImport.js";

type Row = Record<string, unknown>;

export interface UalLogon {
  user: string;
  ip: string;
  tenant: string;
  /** The session id the logon names (DeviceProperties[SessionId] or top-level), "" when it names none. */
  session: string;
  userAgent: string;
  requestType: string;
  /** `ErrorNumber` / `ErrorCode` as the record states it; "" when absent. */
  errorNumber: string;
  logonError: string;
  resultStatus: string;
  /** True only when every outcome field the record carries says success (design round finding 2). */
  established: boolean;
  recordId: string;
  observed: string;
}

const namedValues = (rec: Row, key: string): Map<string, string> => {
  const out = new Map<string, string>();
  const list = getCI(rec, key);
  if (!Array.isArray(list)) return out;
  for (const e of list) {
    if (!isObject(e)) continue;
    const name = str(getCI(e, "Name")).trim().toLowerCase();
    if (name) out.set(name, str(getCI(e, "Value")).trim());
  }
  return out;
};

/** True for a UAL STS logon record — a sign-in, never a directory change and never a mailbox record. */
export function isUalLogon(rec: Row): boolean {
  const op = str(getCI(rec, "Operation")).trim().toLowerCase();
  return op === "userloggedin" || op === "userloginfailed";
}

/**
 * Read a UAL logon. `ResultStatus` reports the operation, not the authentication: the sign-in is
 * ESTABLISHED only for `UserLoggedIn` with no error number (or 0), no `LogonError`, and a success
 * word in `ResultStatus`; anything else is a logon record whose outcome the chain does not read as
 * a sign-in.
 */
export function readUalLogon(rec: Row): UalLogon {
  const ext = namedValues(rec, "ExtendedProperties");
  const dev = namedValues(rec, "DeviceProperties");
  const op = str(getCI(rec, "Operation")).trim().toLowerCase();
  const errorNumber = str(getCI(rec, "ErrorNumber") ?? getCI(rec, "ErrorCode")).trim();
  const logonError = str(getCI(rec, "LogonError")).trim();
  const resultStatus = str(getCI(rec, "ResultStatus")).trim();
  const established =
    op === "userloggedin" &&
    (errorNumber === "" || /^0+$/.test(errorNumber)) &&
    !logonError &&
    /^(succeeded|success|true)$/i.test(resultStatus);
  return {
    user: str(getCI(rec, "UserId")).trim(),
    ip: cleanIp(str(getCI(rec, "ClientIP")).trim() || str(getCI(rec, "ActorIpAddress")).trim()),
    tenant: str(getCI(rec, "OrganizationId")).trim(),
    session: dev.get("sessionid") || str(getCI(rec, "SessionId")).trim(),
    userAgent: ext.get("useragent") ?? "",
    requestType: ext.get("requesttype") ?? "",
    errorNumber,
    logonError,
    resultStatus,
    established,
    recordId: str(getCI(rec, "Id")).trim(),
    observed: str(getCI(rec, "CreationTime")).trim(),
  };
}

export interface EntraSignIn {
  user: string;
  ip: string;
  /** The tenants the record names — home and resource — lower-cased; "" when it names none. */
  homeTenant: string;
  resourceTenant: string;
  clientApp: string;
  appName: string;
  riskState: string;
  riskLevel: string;
  /** False only when the record says `isInteractive: false`. */
  interactive: boolean;
  success: boolean;
  observed: string;
}

/** True for an Entra interactive/user sign-in record of the `signIns` export. */
export function isEntraSignIn(rec: Row): boolean {
  return (
    !!str(getCI(rec, "userPrincipalName")).trim() &&
    !getCI(rec, "servicePrincipalId") &&
    !!(getCI(rec, "status") || getCI(rec, "riskState") || getCI(rec, "riskLevelDuringSignIn"))
  );
}

export function readEntraSignIn(rec: Row): EntraSignIn {
  const status = getCI(rec, "status");
  const rawCode = isObject(status) ? getCI(status, "errorCode") : getCI(rec, "errorCode");
  const code =
    typeof rawCode === "number" ? rawCode : /^\d+$/.test(str(rawCode).trim()) ? Number(str(rawCode)) : null;
  const interactive = getCI(rec, "isInteractive");
  return {
    user: str(getCI(rec, "userPrincipalName")).trim(),
    ip: cleanIp(str(getCI(rec, "ipAddress")).trim()),
    homeTenant: str(getCI(rec, "homeTenantId")).trim().toLowerCase(),
    resourceTenant: str(getCI(rec, "resourceTenantId")).trim().toLowerCase(),
    clientApp: str(getCI(rec, "clientAppUsed")).trim(),
    appName: str(getCI(rec, "appDisplayName")).trim(),
    riskState: str(getCI(rec, "riskState")).trim(),
    riskLevel:
      str(getCI(rec, "riskLevelDuringSignIn")).trim() || str(getCI(rec, "riskLevelAggregated")).trim(),
    interactive: !(interactive === false || /^false$/i.test(str(interactive))),
    success: code === 0,
    observed: str(getCI(rec, "createdDateTime")).trim(),
  };
}

/** An Entra sign-in's category as the row shows it (#2483); "" when the record does not say. */
export type EntraSignInCategory =
  "interactive" | "non-interactive" | "service-principal" | "managed-identity" | "";

const SIGN_IN_EVENT_TYPES: Readonly<Record<string, EntraSignInCategory>> = {
  interactiveuser: "interactive",
  noninteractiveuser: "non-interactive",
  serviceprincipal: "service-principal",
  managedidentity: "managed-identity",
};

/** How a sign-in row shows its category; the tagger's HTTP-library rules read "[non-interactive]". */
export const ENTRA_SIGN_IN_CATEGORY_MARKER: Readonly<Record<Exclude<EntraSignInCategory, "">, string>> = {
  interactive: "[interactive]",
  "non-interactive": "[non-interactive]",
  "service-principal": "[service principal]",
  "managed-identity": "[managed identity]",
};

/**
 * The sign-in category: Graph beta's `signInEventTypes` first, then `isInteractive` (true / false),
 * else "" — a v1.0 or hand-made export that says neither is not guessed at.
 */
export function entraSignInCategory(rec: Row): EntraSignInCategory {
  const types = getCI(rec, "signInEventTypes");
  for (const t of Array.isArray(types) ? types : [types]) {
    const category = SIGN_IN_EVENT_TYPES[str(t).trim().toLowerCase()];
    if (category) return category;
  }
  const interactive = str(getCI(rec, "isInteractive")).trim().toLowerCase();
  if (interactive === "true") return "interactive";
  if (interactive === "false") return "non-interactive";
  return "";
}
