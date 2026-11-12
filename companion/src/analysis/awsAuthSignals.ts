import type { Severity } from "./stateTypes.js";
import type { AwsIdentity } from "./awsIdentity.js";

// CloudTrail calls graded by a parameter the record itself carries (#2604). The Suzaku rules for
// both only label (below the critical floor), and the GetParameters one fires on every read:
//   - ConsoleLogin that succeeded with `additionalEventData.MFAUsed = "No"`, by an IAM user: a
//     password-only console sign-in — Medium, T1078.004. Root is graded High elsewhere; an
//     assumed-role or federated (SSO) session signs in through its provider and is not graded.
//   - ssm GetParameter / GetParameters / GetParametersByPath with `requestParameters.withDecryption`
//     true that succeeded, by an IAM user or an assumed-role session: stored values read in clear —
//     Medium, T1552. Not when an AWS service made the call (invokedBy, an AWS-service identity or
//     source, a service-linked role), nor for workload credentials (inScopeOf, an EC2 instance-role
//     session, a delegate provider). The row names the principal TYPE, never "a person".
// The decoded signal joins the key, so a graded call never folds with a routine one. Pure.

const SSM_READS = new Set(["getparameter", "getparameters", "getparametersbypath"]);
const SERVICE_ROLE = /:role\/aws-service-role\//i;
const SERVICE_SOURCE = /(?:\.amazonaws\.com$|^AWS Internal$)/i;
const NAMES_SHOWN = 3;
const NAME_MAX = 60;

export interface AwsAuthSignal {
  severity: Severity;
  mitre: string[];
  posture: string;
  object: string;
  keySegment: string;
}

type Row = Record<string, unknown>;

const isObject = (v: unknown): v is Row => typeof v === "object" && v !== null && !Array.isArray(v);
const text = (v: unknown): string => (typeof v === "string" ? v.trim() : "");
const isTrue = (v: unknown): boolean => v === true || /^true$/i.test(text(v));
const clip = (s: string): string => (s.length > NAME_MAX ? `${s.slice(0, NAME_MAX)}…` : s);

function consoleWithoutMfa(rec: Row, who: AwsIdentity): AwsAuthSignal | null {
  const response = rec.responseElements;
  const extra = rec.additionalEventData;
  if (!isObject(response) || !/^success$/i.test(text(response.ConsoleLogin))) return null;
  if (!isObject(extra) || !/^no$/i.test(text(extra.MFAUsed)) || who.kind !== "IAMUser") return null;
  return {
    severity: "Medium",
    mitre: ["T1078.004"],
    posture: "console sign-in without MFA (by IAMUser)",
    object: "",
    keySegment: "|mfaused:no",
  };
}

/** True when an AWS service or a workload, not a principal holding the session, made the call. */
function serviceOrWorkload(rec: Row, who: AwsIdentity): boolean {
  return (
    !!who.invokedBy ||
    !!who.inScopeOf ||
    !!who.session.ec2RoleDelivery ||
    !!who.delegateAccountId ||
    SERVICE_ROLE.test(who.issuer?.arn ?? "") ||
    SERVICE_SOURCE.test(text(rec.sourceIPAddress))
  );
}

function parameterNames(req: Row): string {
  const names = Array.isArray(req.names) ? req.names.map(text).filter(Boolean) : [];
  const one = text(req.name) || text(req.path);
  const all = names.length ? names : one ? [one] : [];
  const shown = all.slice(0, NAMES_SHOWN).map(clip).join(", ");
  return all.length > NAMES_SHOWN ? `${shown} +${all.length - NAMES_SHOWN} more` : shown;
}

function decryptedRead(name: string, rec: Row, who: AwsIdentity): AwsAuthSignal | null {
  const req = rec.requestParameters;
  if (!SSM_READS.has(name.toLowerCase()) || !isObject(req) || !isTrue(req.withDecryption)) return null;
  if (who.kind !== "IAMUser" && who.kind !== "AssumedRole") return null;
  if (serviceOrWorkload(rec, who)) return null;
  const names = parameterNames(req);
  return {
    severity: "Medium",
    mitre: ["T1552"],
    posture: `reads parameters with decryption (by ${who.kind === "AssumedRole" ? "AssumedRole session" : "IAMUser"})`,
    object: names,
    keySegment: "|withdecryption",
  };
}

/**
 * The grade a ConsoleLogin or SSM parameter read earns from its own parameters, or null. `failed`
 * is the importer's computed outcome (an errorCode, a failed console sign-in): never graded.
 */
export function readAwsAuthSignal(
  source: string,
  name: string,
  rec: Row,
  who: AwsIdentity,
  failed: boolean,
): AwsAuthSignal | null {
  if (failed) return null;
  const src = source.toLowerCase();
  if (src === "signin.amazonaws.com" && /^consolelogin$/i.test(name)) return consoleWithoutMfa(rec, who);
  if (src === "ssm.amazonaws.com") return decryptedRead(name, rec, who);
  return null;
}
