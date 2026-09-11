import type { Severity } from "./stateTypes.js";

// Who made a CloudTrail call, in the record's own words (#931 item 5).
//
// A record's `userIdentity` says which KIND of principal called, which credential signed the call
// (`accessKeyId`), which identity issued the session (`sessionContext.sessionIssuer`), the
// session's own attributes (creation date, CloudTrail's own `mfaAuthenticated` claim, source
// identity, instance-role delivery, federation), and which account the call was delivered to
// (`recipientAccountId`) against which account the caller belongs to. Every clause below is one
// of those fields, rendered literally: `issuer IAMUser arn:…` when the issuer is an IAM user,
// `CloudTrail mfaAuthenticated=false` (the record's claim, not a verdict on a provider's MFA),
// `request made by AWS service ec2.amazonaws.com`. Nothing is inferred from a key prefix or a
// type label alone: a `Role` is a persistent identity whose temporary use shows only in the
// sessionContext; `SAMLUser` names the external caller of an issuance, not a credential in use.
//
// The STS issuance rows (AssumeRole, AssumeRoleWithSAML, AssumeRoleWithWebIdentity,
// GetFederationToken, GetSessionToken, AssumeRoot) each read their own documented request and
// response paths; the issued key id is the row's identity, so a later call can be matched to the
// row that minted its credential by eye or by the chain spec — never by a role's display name.

type Row = Record<string, unknown>;

export type AwsIdentityKind =
  | "IAMUser"
  | "Root"
  | "AssumedRole"
  | "Role"
  | "FederatedUser"
  | "SAMLUser"
  | "WebIdentityUser"
  | "AWSService"
  | "AWSAccount"
  | "Directory"
  | "IdentityCenterUser"
  | "Unknown";

export type CredentialClass =
  | "temporary"
  | "long-term"
  | "persistent identity, credential class unknown"
  | "not a credential in use"
  | "unknown";

export interface AwsIdentity {
  kind: AwsIdentityKind;
  /** The record's own type string when it is not one of the documented kinds. */
  rawType: string;
  principalId: string;
  arn: string;
  credential: { accessKeyId: string; credentialId: string; class: CredentialClass };
  /** The FIRST present of accessKeyId, Identity Center credentialId, signInSessionArn, principalId@creationDate, principalId. */
  credentialIdentity: string;
  issuer: { type: string; arn: string; accountId: string; principalId: string; userName: string } | null;
  session: {
    name: string;
    creationDate: string;
    mfa: string;
    sourceIdentity: string;
    fromConsole: boolean;
    ec2RoleDelivery: string;
    federatedProvider: string;
    signInSessionArn: string;
  };
  assumedRoot: boolean;
  invokedBy: string;
  /** `userIdentity.invokedByDelegate.accountId` — an external provider acting with delegated permissions. */
  delegateAccountId: string;
  identityProvider: string;
  accounts: { caller: string; recipient: string; crossAccount: boolean };
  /** "IMDSv1" | "IMDSv2" | "SAML" | "WebIdentity" | "console" | "" — the protocol the record names. */
  protocol: string;
  words: string;
  keySegment: string;
  /** CloudTrail's sharedEventID — the two records of one cross-account action share it. */
  replicaId: string;
}

const KINDS = new Set<string>([
  "IAMUser",
  "Root",
  "AssumedRole",
  "Role",
  "FederatedUser",
  "SAMLUser",
  "WebIdentityUser",
  "AWSService",
  "AWSAccount",
  "Directory",
  "IdentityCenterUser",
  "Unknown",
]);
const NOT_IN_USE = new Set<AwsIdentityKind>(["SAMLUser", "WebIdentityUser", "AWSService", "AWSAccount"]);
const WORD_MAX = 120;

const isObject = (v: unknown): v is Row => typeof v === "object" && v !== null && !Array.isArray(v);
const str = (v: unknown): string =>
  typeof v === "string" ? v.trim() : typeof v === "number" ? String(v) : "";
const get = (o: unknown, key: string): unknown => (isObject(o) ? o[key] : undefined);
const path = (o: unknown, keys: string[]): unknown => keys.reduce<unknown>((cur, k) => get(cur, k), o);
const bounded = (v: string, max = WORD_MAX): string => (v.length > max ? `${v.slice(0, max)}…` : v);

function credentialClass(kind: AwsIdentityKind, hasSession: boolean): CredentialClass {
  if (kind === "AssumedRole" || kind === "FederatedUser" || kind === "IdentityCenterUser") return "temporary";
  if (kind === "IAMUser" || kind === "Root") return hasSession ? "temporary" : "long-term";
  if (kind === "Role") return hasSession ? "temporary" : "persistent identity, credential class unknown";
  if (NOT_IN_USE.has(kind)) return "not a credential in use";
  return "unknown";
}

/** Read `userIdentity` (and the record's top-level session and account fields). Never throws. */
export function readAwsIdentity(rec: Row): AwsIdentity {
  const ui = get(rec, "userIdentity");
  const rawType = str(get(ui, "type"));
  const hasOnBehalfOf = isObject(get(ui, "onBehalfOf"));
  // An Identity Center user is recognised by `onBehalfOf`: AWS documents such records with the
  // type absent OR literally `Unknown` (and `IdentityCenterUser`); the onBehalfOf.userId is the
  // immutable identity either way.
  const kind: AwsIdentityKind =
    hasOnBehalfOf && (!rawType || rawType === "Unknown" || rawType === "IdentityCenterUser")
      ? "IdentityCenterUser"
      : KINDS.has(rawType)
        ? (rawType as AwsIdentityKind)
        : "Unknown";
  const sc = get(ui, "sessionContext");
  const hasSession = isObject(sc);
  const issuerRaw = get(sc, "sessionIssuer");
  const issuer = isObject(issuerRaw)
    ? {
        type: str(get(issuerRaw, "type")),
        arn: str(get(issuerRaw, "arn")),
        accountId: str(get(issuerRaw, "accountId")),
        principalId: str(get(issuerRaw, "principalId")),
        userName: str(get(issuerRaw, "userName")),
      }
    : null;
  const principalId = str(get(ui, "principalId"));
  const sessionName =
    kind === "AssumedRole" && principalId.includes(":")
      ? principalId.slice(principalId.lastIndexOf(":") + 1)
      : kind === "FederatedUser" && principalId.includes(":")
        ? principalId.slice(principalId.indexOf(":") + 1)
        : "";
  const attributes = get(sc, "attributes");
  const ec2RoleDelivery = str(get(sc, "ec2RoleDelivery"));
  const federatedProvider = str(path(sc, ["webIdFederationData", "federatedProvider"]));
  const session = {
    name: sessionName,
    creationDate: str(get(attributes, "creationDate")),
    mfa: str(get(attributes, "mfaAuthenticated")),
    sourceIdentity: str(get(sc, "sourceIdentity")),
    fromConsole: /^true$/i.test(str(get(rec, "sessionCredentialFromConsole"))),
    ec2RoleDelivery,
    federatedProvider,
    signInSessionArn: str(get(sc, "signInSessionArn")) || str(get(ui, "signInSessionArn")),
  };
  const assumedRoot = str(get(sc, "assumedRoot")) === "true";
  const accessKeyId = str(get(ui, "accessKeyId"));
  const credentialId = str(get(ui, "credentialId"));
  const cls = credentialClass(kind, hasSession);
  const caller = str(get(ui, "accountId"));
  const recipient = str(get(rec, "recipientAccountId"));
  const invokedBy = str(get(ui, "invokedBy"));
  const delegateAccountId = str(path(ui, ["invokedByDelegate", "accountId"]));
  const identityProvider = str(get(ui, "identityProvider"));
  const credentialIdentity =
    accessKeyId ||
    credentialId ||
    session.signInSessionArn ||
    (principalId && session.creationDate ? `${principalId}@${session.creationDate}` : principalId);
  const protocol =
    ec2RoleDelivery === "1.0"
      ? "IMDSv1"
      : ec2RoleDelivery === "2.0"
        ? "IMDSv2"
        : kind === "SAMLUser"
          ? "SAML"
          : kind === "WebIdentityUser" || federatedProvider
            ? "WebIdentity"
            : session.fromConsole
              ? "console"
              : "";
  // Ordered by how often a clause decides something; the issuer ARN is the longest and the least
  // often decisive, so it is last — what a tight identity budget clips.
  const clauses: string[] = [
    kind === "Unknown" && rawType ? `Unknown type ${bounded(rawType, 40)}` : kind,
    NOT_IN_USE.has(kind)
      ? "(not a credential in use)"
      : accessKeyId || credentialId
        ? `key ${bounded(accessKeyId || credentialId, 60)} (${cls})`
        : cls === "unknown"
          ? ""
          : `(${cls})`,
    assumedRoot ? "assumed-root session" : "",
    delegateAccountId
      ? `invoked by delegate provider account ${bounded(delegateAccountId, 20)} (delegated permissions)`
      : "",
    caller && recipient && caller !== recipient
      ? `cross-account: caller ${caller}, recipient ${recipient}`
      : "",
    session.name ? `session ${bounded(session.name, 80)}` : "",
    session.creationDate ? `since ${session.creationDate}` : "",
    session.mfa ? `CloudTrail mfaAuthenticated=${bounded(session.mfa, 10)}` : "",
    session.sourceIdentity ? `source identity ${bounded(session.sourceIdentity, 64)}` : "",
    session.fromConsole ? "credential originated from a console session" : "",
    ec2RoleDelivery === "1.0"
      ? "instance-role credentials delivered via IMDSv1"
      : ec2RoleDelivery === "2.0"
        ? "instance-role credentials delivered via IMDSv2"
        : ec2RoleDelivery
          ? `ec2RoleDelivery=${bounded(ec2RoleDelivery, 10)}`
          : "",
    federatedProvider ? `federated via ${bounded(federatedProvider)}` : "",
    identityProvider ? `provider ${bounded(identityProvider)}` : "",
    invokedBy ? `request made by AWS service ${bounded(invokedBy, 60)}` : "",
    issuer && issuer.arn ? `issuer ${issuer.type || "unknown"} ${bounded(issuer.arn)}` : "",
  ];
  return {
    kind,
    rawType: KINDS.has(rawType) ? "" : rawType,
    principalId,
    arn: str(get(ui, "arn")),
    credential: { accessKeyId, credentialId, class: cls },
    credentialIdentity,
    issuer,
    session,
    assumedRoot,
    invokedBy,
    delegateAccountId,
    identityProvider,
    accounts: { caller, recipient, crossAccount: !!caller && !!recipient && caller !== recipient },
    protocol,
    words: clauses.filter(Boolean).join(" "),
    keySegment: `|id:${credentialIdentity || "-"}|${issuer?.arn || "-"}`.toLowerCase(),
    replicaId: str(get(rec, "sharedEventID")),
  };
}

// ───────────────────────────── STS issuance ─────────────────────────────

export interface CredentialIssuance {
  action:
    | "AssumeRole"
    | "AssumeRoleWithSAML"
    | "AssumeRoleWithWebIdentity"
    | "GetFederationToken"
    | "GetSessionToken"
    | "AssumeRoot";
  attempted: boolean;
  /** `issued` (positive response evidence), `denied` (an error code), `unknown` (neither — a request only). */
  result: "issued" | "denied" | "unknown";
  /** The ISSUED credential's key id; "" when denied or when the response is unavailable. */
  issuedKey: string;
  expiration: string;
  role: { arn: string; assumedArn: string; assumedRoleId: string } | null;
  sessionName: string;
  sourceIdentity: string;
  mfaSerial: string;
  federatedUser: { arn: string; id: string } | null;
  targetPrincipal: string;
  words: string;
  /** The verb phrase — `issues temporary credentials`, `attempted to assume role …` — for the posture slot. */
  posture: string;
  /** Everything after the verb phrase on a success, for the object slot; "" on an attempt. */
  detail: string;
  /** `denied (<code>)` on an attempt, for the outcome slot; "" otherwise. */
  outcome: string;
  severity: Severity | null;
  mitre: string[];
  keySegment: string;
}

const ACTIONS: Record<string, CredentialIssuance["action"]> = {
  assumerole: "AssumeRole",
  assumerolewithsaml: "AssumeRoleWithSAML",
  assumerolewithwebidentity: "AssumeRoleWithWebIdentity",
  getfederationtoken: "GetFederationToken",
  getsessiontoken: "GetSessionToken",
  assumeroot: "AssumeRoot",
};
const ISSUANCE = new Set(Object.keys(ACTIONS));
// An identifier is a string or nothing — a number where a key id belongs is not a key id.
const sid = (v: unknown): string => (typeof v === "string" ? v.trim() : "");

/**
 * Read one STS issuance record. `rec` supplies requestID/eventID for the discriminator ladder and
 * `index` the record's position; every request/response field is optional and none is invented.
 */
export function readCredentialIssuance(
  name: string,
  request: unknown,
  response: unknown,
  errorCode: string,
  rec: Row,
  index: number,
): CredentialIssuance | null {
  const lower = name.trim().toLowerCase();
  if (!ISSUANCE.has(lower)) return null;
  const action = ACTIONS[lower];
  const req = isObject(request) ? request : {};
  const res = isObject(response) ? response : null;
  const attempted = !!errorCode.trim();
  const creds = res && isObject(get(res, "credentials")) ? (get(res, "credentials") as Row) : null;
  // The secret and the session token are never in CloudTrail; if a value ever is, it is dropped here.
  const issuedKey = !attempted && creds ? sid(get(creds, "accessKeyId")) : "";
  const expiration = !attempted && creds ? sid(get(creds, "expiration")) : "";
  const roleArn = str(get(req, "roleArn"));
  const assumedUser =
    res && isObject(get(res, "assumedRoleUser")) ? (get(res, "assumedRoleUser") as Row) : null;
  const role = roleArn
    ? {
        arn: roleArn,
        assumedArn: str(get(assumedUser, "arn")),
        assumedRoleId: str(get(assumedUser, "assumedRoleId")),
      }
    : null;
  const sessionName = str(get(req, "roleSessionName"));
  const sourceIdentity = str(get(req, "sourceIdentity")) || str(get(res, "sourceIdentity"));
  const mfaSerial = str(get(req, "serialNumber"));
  const fedRaw = res && isObject(get(res, "federatedUser")) ? (get(res, "federatedUser") as Row) : null;
  const federatedUser = fedRaw
    ? { arn: str(get(fedRaw, "arn")), id: str(get(fedRaw, "federatedUserId")) }
    : null;
  const targetPrincipal = str(get(req, "targetPrincipal"));
  const taskPolicy = str(path(req, ["taskPolicyArn", "arn"])) || str(get(req, "taskPolicyArn"));
  const tail = [
    issuedKey ? `→ key ${bounded(issuedKey, 60)}` : "",
    expiration ? `expires ${bounded(expiration, 40)}` : "",
    mfaSerial ? `MFA device ${bounded(mfaSerial, 80)}` : "",
    sourceIdentity ? `source identity ${bounded(sourceIdentity, 64)}` : "",
    get(req, "externalId") !== undefined && get(req, "externalId") !== null ? "external id supplied" : "",
    lower === "getfederationtoken" && get(req, "policy") !== undefined ? "policy supplied" : "",
  ].filter(Boolean);
  // A successful issuance always returns an access key id; without one the response is unusable.
  // Without positive response evidence a successful-looking record establishes only a REQUEST:
  // the outcome is unknown, the verb is not affirmative, and no grade for a success applies.
  const responseMissing = !attempted && !issuedKey;
  const result: CredentialIssuance["result"] = attempted ? "denied" : responseMissing ? "unknown" : "issued";
  const denied = attempted ? ` — denied (${bounded(errorCode.trim(), 30)})` : "";
  let head: string;
  let infinitive: string;
  switch (action) {
    case "AssumeRole":
      head = `issues temporary credentials: role ${bounded(roleArn)}${sessionName ? ` session ${bounded(sessionName, 80)}` : ""}`;
      infinitive = `assume role ${bounded(roleArn)}${sessionName ? ` session ${bounded(sessionName, 80)}` : ""}`;
      break;
    case "AssumeRoleWithSAML": {
      const subject = str(get(res, "subject"));
      const subjectType = str(get(res, "subjectType"));
      head = `issues temporary credentials via SAML: provider ${bounded(str(get(req, "principalArn")))}${subject ? ` subject ${bounded(subject, 80)}${subjectType ? ` (${bounded(subjectType, 20)})` : ""}` : ""} role ${bounded(roleArn)}${sessionName ? ` session ${bounded(sessionName, 80)}` : ""}`;
      infinitive = `assume role ${bounded(roleArn)} via SAML`;
      break;
    }
    case "AssumeRoleWithWebIdentity": {
      const subject = str(get(res, "subjectFromWebIdentityToken"));
      const provider = str(get(res, "provider")) || str(get(req, "providerId"));
      const audience = str(get(res, "audience"));
      head = `issues temporary credentials via web identity: provider ${bounded(provider)}${subject ? ` subject ${bounded(subject, 80)}` : ""}${audience ? ` audience ${bounded(audience, 60)}` : ""} role ${bounded(roleArn)}${sessionName ? ` session ${bounded(sessionName, 80)}` : ""}`;
      infinitive = `assume role ${bounded(roleArn)} via web identity`;
      break;
    }
    case "GetFederationToken": {
      const user = str(get(req, "name"));
      head = `issues federated credentials: user ${bounded(user, 60)}${federatedUser?.arn ? ` → ${bounded(federatedUser.arn)}` : ""}`;
      infinitive = `issue federated credentials for user ${bounded(user, 60)}`;
      break;
    }
    case "GetSessionToken":
      head = "issues session credentials for the caller";
      infinitive = "issue session credentials for the caller";
      break;
    case "AssumeRoot":
      head = `issues ROOT session credentials for account ${bounded(targetPrincipal, 40)}${taskPolicy ? ` under task policy ${bounded(taskPolicy)}` : ""}`;
      infinitive = `issue ROOT session credentials for account ${bounded(targetPrincipal, 40)}${taskPolicy ? ` under task policy ${bounded(taskPolicy)}` : ""}`;
      break;
  }
  const keyTail = issuedKey ? `${head.includes("→ ") ? "key" : "→ key"} ${bounded(issuedKey, 60)}` : "";
  const words = attempted
    ? `attempted to ${infinitive}${denied}`
    : responseMissing
      ? `requested to ${infinitive} — outcome unknown (response details unavailable)`
      : `${head} ${[keyTail, ...tail.filter((t) => !t.startsWith("→ key"))].filter(Boolean).join(" ")}`.trim();
  const discriminator =
    issuedKey || str(get(rec, "requestID")) || str(get(rec, "eventID")) || `record:${index}`;
  const severity: Severity | null =
    action === "AssumeRoot" ? (result === "issued" ? "High" : "Medium") : null;
  // The verb phrase is what the posture slot holds; the role, session, key and expiration are
  // the object slot's, so a long role ARN never clips the verb or the outcome.
  const colon = head.indexOf(": ");
  const posture = attempted
    ? `attempted to ${infinitive}`
    : responseMissing
      ? `requested to ${infinitive}`
      : colon >= 0
        ? head.slice(0, colon)
        : head;
  const detail =
    attempted || responseMissing
      ? ""
      : [colon >= 0 ? head.slice(colon + 2) : "", keyTail, ...tail.filter((t) => !t.startsWith("→ key"))]
          .filter(Boolean)
          .join(" ");
  const outcome = attempted
    ? `denied (${bounded(errorCode.trim(), 30)})`
    : responseMissing
      ? "outcome unknown (response details unavailable)"
      : "";
  return {
    action,
    attempted,
    result,
    issuedKey,
    expiration,
    role,
    sessionName,
    sourceIdentity,
    mfaSerial,
    federatedUser,
    targetPrincipal,
    words,
    posture,
    detail,
    outcome,
    severity,
    mitre: action === "AssumeRoot" && result === "issued" ? ["T1078.004"] : [],
    keySegment: `|issued:${discriminator}|${(roleArn || targetPrincipal || "-").toLowerCase()}`,
  };
}
