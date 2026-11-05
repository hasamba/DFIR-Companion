// One Entra sign-in as the sign-in observation store keeps it (#2301) — the input MFA-fatigue
// detection (#2306) reads, so it keeps what a fatigue sequence is made of: the result code, the
// MFA step (required / denied / timed out / approved), the auth method, the session and
// correlation ids, the app, the source IP and the tenant.
//
// Unlike the password-spray candidates (m365Import.ts), an MFA interruption is KEPT here: an
// interruption is exactly the event a fatigue sequence repeats. This feeds only the internal store,
// never the forensic timeline — a successful or interrupted sign-in stays whatever severity
// m365Import.ts graded it, so Info rows still never reach the forensic timeline (CLAUDE.md §7). Pure.

import { getCI, getPath, isObject, str } from "./siemFieldPick.js";
import { normalizeTime } from "./siemImport.js";
import type { SprayOutcome } from "./passwordSprayFanout.js";
import type { AuthObservationOutcome, MfaDetail, StoredAuthObservation } from "./authObservationStore.js";

type Row = Record<string, unknown>;

// Entra result codes that mean "a second factor is needed": strong auth required (50074, 50076),
// MFA registration required (50079), an external security challenge not yet satisfied (50158).
const MFA_REQUIRED_CODES = new Set([50074, 50076, 50079, 50158]);
// 500121: the strong-authentication request failed — the step detail says whether it was denied
// or never answered. Without that detail the code alone is "unconfirmed" (#2306): it never counts
// as a rejected prompt.
const MFA_FAILED_CODE = 500121;

const text = (rec: Row, path: string): string =>
  str(path.includes(".") ? getPath(rec, path) : getCI(rec, path)).trim();

function stepDetails(rec: Row): Row[] {
  const details = getCI(rec, "authenticationDetails");
  return Array.isArray(details) ? details.filter(isObject) : [];
}

function resultCode(rec: Row): string {
  return text(rec, "status.errorCode") || text(rec, "errorCode") || text(rec, "ResultType");
}

/** The MFA step a sign-in record describes, or undefined when it says nothing about MFA. */
export function mfaDetailOf(rec: Row): MfaDetail | undefined {
  const detailText = [
    text(rec, "status.additionalDetails"),
    text(rec, "status.failureReason"),
    text(rec, "mfaDetail.authDetail"), // Graph beta / Log Analytics MfaDetail column
    ...stepDetails(rec).map((d) => text(d, "authenticationStepResultDetail")),
  ].join(" | ");
  if (/did not respond|timed? ?out|timeout/i.test(detailText)) return "timed out";
  if (/denied|declined|rejected|fraud/i.test(detailText)) return "denied";
  if (
    /mfa (successfully )?completed|completed in the cloud|satisfied by|successfully completed/i.test(
      detailText,
    )
  )
    return "approved";
  const code = Number(resultCode(rec));
  if (code === MFA_FAILED_CODE) return "unconfirmed";
  if (MFA_REQUIRED_CODES.has(code) || /mfa required|strong auth/i.test(detailText)) return "required";
  if (code === 0 && /multiFactor/i.test(text(rec, "authenticationRequirement"))) return "approved";
  return undefined;
}

function authMethodOf(rec: Row): string {
  for (const d of stepDetails(rec)) {
    const method = text(d, "authenticationMethod");
    if (method && !/^previously satisfied$/i.test(method)) return method;
  }
  const used = getCI(rec, "authenticationMethodsUsed");
  return Array.isArray(used) ? str(used[0]).trim() : "";
}

function outcomeOf(spray: SprayOutcome | null, mfa: MfaDetail | undefined): AuthObservationOutcome {
  if (mfa === "required" || mfa === "denied" || mfa === "timed out" || mfa === "unconfirmed")
    return "interrupted";
  return spray ?? "other";
}

export interface SignInObservationInput {
  rec: Row;
  account: string;
  sourceIp: string; // may be empty: an observation without an IP is still a sign-in
  tenant: string;
  observed: string;
  locator: string;
  recordId?: string; // the record's cloud identity key (cloudRecordIdentity.ts)
  sprayOutcome: SprayOutcome | null; // the spray classification m365Import.ts already made
}

/** The stored observation for one Entra sign-in. `importBatch` is stamped by the ingest layer. */
export function signInObservation(i: SignInObservationInput): Omit<StoredAuthObservation, "importBatch"> {
  const mfa = mfaDetailOf(i.rec);
  const optional: Partial<StoredAuthObservation> = {
    resultCode: resultCode(i.rec) || undefined,
    mfaDetail: mfa,
    // denied / timed out are only ever read from detail text (a bare 500121 is "unconfirmed").
    mfaConfirmed: mfa === "denied" || mfa === "timed out" ? true : undefined,
    authMethod: authMethodOf(i.rec) || undefined,
    sessionId: text(i.rec, "sessionId") || undefined,
    correlationId: text(i.rec, "correlationId") || undefined,
    app: text(i.rec, "appDisplayName") || undefined,
    recordId: i.recordId,
  };
  return {
    timestamp: normalizeTime(i.observed),
    account: i.account,
    sourceIp: i.sourceIp,
    hostOrTenant: i.tenant,
    outcome: outcomeOf(i.sprayOutcome, mfa),
    locator: i.locator,
    importer: "m365",
    ...Object.fromEntries(Object.entries(optional).filter(([, v]) => v !== undefined)),
  };
}
