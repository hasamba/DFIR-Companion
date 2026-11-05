// Azure diagnostic-settings records (PT1H.json in a storage account, or an Event Hub) → the shapes
// the M365/Entra and Azure Activity importers read (#2304).
//
// The diagnostic schema is `time, resourceId, operationName, category, resultType,
// callerIpAddress, identity, properties` for every category, which is not the REST Activity Log's
// (`eventTimestamp, caller, operationName.value, httpRequest.clientIpAddress`) nor Graph's:
//   • An Entra category carries the Graph `signIn` / `directoryAudit` record under `properties`.
//     Mapped as an Azure operation it became one generic "Azure Sign-in activity" row and the
//     sign-in itself — user, outcome, error code — was never read. It is unwrapped here, so it
//     grades exactly like the Graph record it carries.
//   • An Activity Log category names its caller in `identity.claims` (the UPN claim, or the app id
//     for an application), where REST has `caller`.

import { getCI, isObject, str } from "./siemFieldPick.js";

type Row = Record<string, unknown>;

const SIGN_IN_CATEGORIES = new Set([
  "signinlogs",
  "noninteractiveusersigninlogs",
  "serviceprincipalsigninlogs",
  "managedidentitysigninlogs",
]);
const AUDIT_CATEGORY = "auditlogs";

const UPN_CLAIM = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn";

const present = (v: unknown): boolean => v !== undefined && v !== null && str(v).trim() !== "";
const category = (rec: Row): string => str(getCI(rec, "category")).trim().toLowerCase();

function propertiesOf(rec: Row): Row | null {
  const p = getCI(rec, "properties");
  if (isObject(p)) return p;
  if (typeof p !== "string" || !p.trim().startsWith("{")) return null;
  try {
    const parsed: unknown = JSON.parse(p);
    return isObject(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

/**
 * An Entra record exported by diagnostic settings: an Entra (`microsoft.aadiam`) resource, a
 * category the M365 importer reads, and the Graph record as a `properties` object. All three — a
 * Key Vault or Activity record also has `category` and `properties`.
 */
export function isAzureDiagnosticEntra(rec: Row): boolean {
  const cat = category(rec);
  return (
    (SIGN_IN_CATEGORIES.has(cat) || cat === AUDIT_CATEGORY) &&
    /\/providers\/microsoft\.aadiam\b/i.test(str(getCI(rec, "resourceId"))) &&
    propertiesOf(rec) !== null
  );
}

// The sign-in outcome the envelope states, in Graph's `status` shape.
function envelopeStatus(rec: Row): Row | undefined {
  const code = str(getCI(rec, "resultType")).trim();
  if (!code) return undefined;
  return {
    errorCode: /^\d+$/.test(code) ? Number(code) : code,
    failureReason: str(getCI(rec, "resultDescription")),
  };
}

// The outcome the record states for itself, in either spelling the sign-in mapper reads
// (`status.errorCode` or a top-level `errorCode`), always beats the envelope's resultType. Only a
// record with no code at all takes the envelope's; a `status` without a code takes the envelope's
// fields only where it has none of its own.
function signInStatus(rec: Row, own: Row): Row | undefined {
  const status = getCI(own, "status");
  const ownStatus = isObject(status) ? status : undefined;
  if (present(getCI(own, "errorCode")) || present(ownStatus && getCI(ownStatus, "errorCode")))
    return ownStatus;
  const envelope = envelopeStatus(rec);
  if (!envelope) return ownStatus;
  return ownStatus ? { ...envelope, ...ownStatus } : envelope;
}

function signInFill(rec: Row): Row {
  return {
    createdDateTime: getCI(rec, "time"),
    ipAddress: getCI(rec, "callerIpAddress"),
    correlationId: getCI(rec, "correlationId"),
  };
}

function auditFill(rec: Row): Row {
  return { activityDateTime: getCI(rec, "time"), correlationId: getCI(rec, "correlationId") };
}

/** The envelope fills: each only when present, and never under a key `own` already has in ANY case. */
function gapsOnly(fill: Row, own: Row): Row {
  return Object.fromEntries(
    Object.entries(fill).filter(([k, v]) => present(v) && getCI(own, k) === undefined),
  );
}

/** The Graph record under `properties`; the envelope only fills the fields it leaves out. */
export function adaptAzureDiagnosticEntra(rec: Row): Row {
  const signIn = SIGN_IN_CATEGORIES.has(category(rec));
  const own = Object.fromEntries(
    Object.entries(propertiesOf(rec) ?? {}).filter(([, v]) => v !== null && v !== ""),
  );
  // The envelope's tenant stands in only when the record states neither its home nor resource tenant.
  const tenant = getCI(rec, "tenantId");
  const needsTenant =
    signIn &&
    present(tenant) &&
    !present(getCI(own, "resourceTenantId")) &&
    !present(getCI(own, "homeTenantId"));
  const status = signIn ? signInStatus(rec, own) : undefined;
  // `own` keys spelled differently from Graph's (e.g. `Status`) are dropped where the merged
  // status replaces them, so the mapper cannot read a stale copy.
  const rest = status
    ? Object.fromEntries(Object.entries(own).filter(([k]) => k.toLowerCase() !== "status"))
    : own;
  return {
    ...gapsOnly(signIn ? signInFill(rec) : auditFill(rec), own),
    ...(needsTenant ? { resourceTenantId: tenant } : {}),
    ...rest,
    ...(status ? { status } : {}),
  };
}

/** The caller an Activity Log diagnostic record names in `identity.claims`: the UPN, else the app id. */
function claimsCaller(rec: Row): string {
  const claims = getCI(isObject(rec.identity) ? rec.identity : {}, "claims");
  if (!isObject(claims)) return "";
  for (const key of [UPN_CLAIM, "upn", "appid"]) {
    const v = str(getCI(claims, key)).trim();
    if (v) return v;
  }
  return "";
}

/** An Activity Log diagnostic record with REST's `caller` filled from its claims; any other row as is. */
export function adaptAzureDiagnosticActivity(rec: Row): Row {
  if (present(getCI(rec, "caller")) || !present(getCI(rec, "operationName"))) return rec;
  const caller = claimsCaller(rec);
  return caller ? { ...rec, caller } : rec;
}
