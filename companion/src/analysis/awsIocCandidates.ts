// The AWS caller, read from a CloudTrail `userIdentity`, and the identity IOCs a graded row yields
// (#2543 part 1a). Until #2543 the CloudTrail importer recorded only the caller's address: the IAM
// user that granted itself `*:*`, its long-term key, the key it minted and the policy it wrote
// never reached the IOC list, so the analyst re-typed them from row descriptions.
//
// What becomes an IOC, and why it is narrow:
//   - only from a row graded High or above (the FINAL grade, after Sigma and the precursor raise),
//     or from a successful `CreateAccessKey` (a credential issuance is worth recording at any grade);
//   - only when the caller is an IAM user or an assumed role. Root and AWS-service callers yield
//     nothing: the account root is the victim's own account (in the SANS 504 lab, the responder),
//     and an AWS service acting on its own behalf is not an indicator of anything;
//   - the principal is keyed on its FULL ARN, never a bare user name. AWS descriptions say
//     `by <user>`, and the behavioural-corroboration check substring-matches IOC values against
//     descriptions — a bare `dev` would corroborate itself on every unrelated row;
//   - an access key only when it is a long-term `AKIA…` key. Session keys (`ASIA…`) change every
//     console session and would flood the list;
//   - created object names only on a successful call: a denied PutUserPolicy created nothing.
//
// Every value is typed `other` — the "recorded, not accused" type (iocSink.ts, #1530). `other` is
// never enriched (enrichment/provider.ts `iocKind`), so no ARN or key id goes to a threat-intel
// service, and it is not a block-list type. The note is short, one line and bounded; the value and
// any user-chosen name in the note are attacker-controlled and are escaped by every renderer.

import { getCI, getPath, isObject, str } from "./siemFieldPick.js";
import { oneLine, mergeRowIocs, addIoc, type MappedEvent, type SiemIoc } from "./siemImport.js";
import { readAccessKeyIssuance } from "./awsAccessKeyIssuance.js";
import type { Severity } from "./stateTypes.js";

type Row = Record<string, unknown>;

export interface AwsPrincipal {
  name: string;
  isRoot: boolean;
  id?: string;
  type?: string;
  arn?: string;
  accountId?: string;
}

// The acting principal: IAM user name, the assumed-role's issuer, the ARN, or the type.
export function awsPrincipal(ui: unknown): AwsPrincipal {
  if (!isObject(ui)) return { name: str(ui), isRoot: false };
  const type = str(getCI(ui, "type"));
  const arn = str(getCI(ui, "arn"));
  // IAM Identity Center users carry NO principalId/userName at the root: the immutable identity is
  // onBehalfOf.userId inside identityStoreArn. Without it every Identity Center user in an account
  // keyed as the literal type string and merged into one principal.
  const id =
    str(getCI(ui, "principalId")) ||
    str(getCI(ui, "userId")) ||
    (str(getPath(ui, "onBehalfOf.userId"))
      ? `${str(getPath(ui, "onBehalfOf.identityStoreArn"))}#${str(getPath(ui, "onBehalfOf.userId"))}`
      : "");
  const accountId = str(getCI(ui, "accountId"));
  const name =
    str(getCI(ui, "userName")) ||
    str(getPath(ui, "sessionContext.sessionIssuer.userName")) ||
    arn ||
    str(getCI(ui, "invokedBy")) ||
    type;
  return {
    name,
    isRoot: /^root$/i.test(type),
    ...(id ? { id } : {}),
    ...(type ? { type } : {}),
    ...(arn ? { arn } : {}),
    ...(accountId ? { accountId } : {}),
  };
}

export interface AwsIocCandidate {
  type: "other";
  value: string;
  note: string;
}

const LONG_TERM_KEY = /^AKIA[A-Z0-9]{12,124}$/;
const IAM_USER_ARN = /^arn:aws[a-z-]*:iam::\d{12}:user\/\S+$/;
const IAM_ROLE_ARN = /^arn:aws[a-z-]*:iam::\d{12}:role\/\S+$/;
// A service-linked role is AWS acting on its own behalf, whatever the record's type says.
const SERVICE_ROLE = /:role\/aws-service-role\//;
const NAME_MAX = 64;
const NOTE_MAX = 200;

// The object a successful call created, by the request field that names it.
const CREATED_NAME_FIELD: Readonly<Record<string, { field: string; kind: string }>> = {
  PutUserPolicy: { field: "policyName", kind: "AWS IAM policy" },
  PutRolePolicy: { field: "policyName", kind: "AWS IAM policy" },
  PutGroupPolicy: { field: "policyName", kind: "AWS IAM policy" },
  CreatePolicy: { field: "policyName", kind: "AWS IAM policy" },
  CreateUser: { field: "userName", kind: "AWS IAM user" },
  CreateRole: { field: "roleName", kind: "AWS IAM role" },
  CreateLoginProfile: { field: "userName", kind: "AWS console password for IAM user" },
};

const HIGH_PLUS: ReadonlySet<Severity> = new Set<Severity>(["High", "Critical"]);

const bounded = (s: string, max: number): string => oneLine(s).slice(0, max);

/** The caller's stable ARN when it may be an indicator: an IAM user, or an assumed role's role. */
function callerArn(ui: Row): string {
  const type = str(getCI(ui, "type")).trim();
  if (type === "IAMUser") {
    const arn = str(getCI(ui, "arn")).trim();
    return IAM_USER_ARN.test(arn) ? arn : "";
  }
  if (type === "AssumedRole") {
    // The session ARN changes per session; the role it was issued from is the stable identity.
    const arn = str(getPath(ui, "sessionContext.sessionIssuer.arn")).trim();
    return IAM_ROLE_ARN.test(arn) && !SERVICE_ROLE.test(arn) ? arn : "";
  }
  return "";
}

/**
 * The identity IOCs one CloudTrail record yields at its final grade. Pure. Empty for a row below
 * High that issued no access key, and for every root, AWS-service or unrecognised caller.
 */
export function awsIocCandidates(rec: Row, severity: Severity): AwsIocCandidate[] {
  const ui = getCI(rec, "userIdentity");
  if (!isObject(ui) || str(getCI(ui, "invokedBy")).trim()) return [];
  const arn = callerArn(ui);
  if (!arn) return [];
  const issued = readAccessKeyIssuance(rec);
  if (!HIGH_PLUS.has(severity) && !issued) return [];
  const action = bounded(str(getCI(rec, "eventName")), NAME_MAX);
  const at = bounded(str(getCI(rec, "eventTime")), 40);
  const when = at ? ` at ${at}` : "";
  const out: AwsIocCandidate[] = [
    { type: "other", value: arn, note: `AWS IAM principal — acted in ${action}${when}` },
  ];
  const key = str(getCI(ui, "accessKeyId")).trim();
  if (LONG_TERM_KEY.test(key))
    out.push({ type: "other", value: key, note: `AWS access key — used for ${action}${when}` });
  if (issued && LONG_TERM_KEY.test(issued.issuedKey)) {
    const forUser = issued.userName ? ` for ${bounded(issued.userName, NAME_MAX)}` : "";
    out.push({
      type: "other",
      value: issued.issuedKey,
      note: `AWS access key — issued by CreateAccessKey${forUser}${when}`,
    });
  }
  const created = Object.hasOwn(CREATED_NAME_FIELD, action) ? CREATED_NAME_FIELD[action] : undefined;
  const request = getCI(rec, "requestParameters");
  if (created && !str(getCI(rec, "errorCode")).trim() && isObject(request)) {
    const name = oneLine(str(getCI(request, created.field))).trim();
    if (name) out.push({ type: "other", value: name, note: `${created.kind} — created by ${action}${when}` });
  }
  return out.map((c) => ({ ...c, note: c.note.slice(0, NOTE_MAX) }));
}

/**
 * Add every row's identity IOCs to the file sink, each linked to the row that produced it (its
 * aggKey), so the case IOC carries `extractedFrom`. `rows[i]` was mapped from `records[i]`.
 */
export function addAwsIdentityIocs(
  sink: Map<string, SiemIoc>,
  rows: readonly MappedEvent[],
  records: readonly Row[],
): void {
  rows.forEach((row, i) => {
    const rec = records[i];
    if (!rec) return;
    const candidates = awsIocCandidates(rec, row.severity);
    if (!candidates.length) return;
    const rowSink = new Map<string, SiemIoc>();
    for (const c of candidates) addIoc(rowSink, c.type, c.value, undefined, c.note);
    mergeRowIocs(sink, rowSink, row.aggKey);
  });
}
