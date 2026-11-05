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

function signInFill(rec: Row): Row {
  const pairs: Array<[string, unknown]> = [
    ["createdDateTime", getCI(rec, "time")],
    ["ipAddress", getCI(rec, "callerIpAddress")],
    ["status", envelopeStatus(rec)],
    ["correlationId", getCI(rec, "correlationId")],
  ];
  return Object.fromEntries(pairs.filter(([, v]) => present(v) || isObject(v)));
}

function auditFill(rec: Row): Row {
  const pairs: Array<[string, unknown]> = [
    ["activityDateTime", getCI(rec, "time")],
    ["correlationId", getCI(rec, "correlationId")],
  ];
  return Object.fromEntries(pairs.filter(([, v]) => present(v)));
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
  return {
    ...(signIn ? signInFill(rec) : auditFill(rec)),
    ...(needsTenant ? { resourceTenantId: tenant } : {}),
    ...own,
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
