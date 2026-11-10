// Who a resource policy lets in, read positively (#2542). Pure.
//
// One question, asked of a bucket policy or a KMS key policy: does EVERY Allow statement name only
// AWS service principals (`Service: "*.amazonaws.com"`) or the account that owns the resource (its
// 12-digit id, or an IAM ARN in that account)? Anything this reader does not positively understand
// answers "no": an unparseable document, no Allow statement at all, `NotPrincipal`, a `Federated` or
// `CanonicalUser` principal, any other account, an empty owner account — and `*`, unless the caller
// opts in to a `*` that a condition holds to the owner account (a KMS key policy's
// `kms:CallerAccount`). A Deny statement only takes access away, so it never makes the answer "no".

import { getCI, isObject, str } from "./siemImport.js";

type Row = Record<string, unknown>;

/** The conditions that hold a `*` principal to one account (`StringEquals`, every value that account). */
const ACCOUNT_CONDITION_KEYS = ["kms:calleraccount", "aws:principalaccount"];
const SERVICE_PRINCIPAL = /^[a-z0-9][a-z0-9.-]*\.amazonaws\.com(\.cn)?$/i;
const ACCOUNT_ID = /^\d{12}$/;

const asList = (v: unknown): unknown[] => (Array.isArray(v) ? v : v === undefined || v === null ? [] : [v]);

/** A policy document from an object or its JSON text; null when neither. */
export function policyDoc(v: unknown): Row | null {
  if (isObject(v)) return v;
  if (typeof v !== "string") return null;
  try {
    const parsed: unknown = JSON.parse(v);
    return isObject(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

/** The document's Allow statements; null when a statement is not an object (unreadable). */
function allowStatements(doc: Row): Row[] | null {
  const all = asList(getCI(doc, "Statement"));
  if (!all.every(isObject)) return null;
  return (all as Row[]).filter((s) => /^allow$/i.test(str(getCI(s, "Effect")).trim()));
}

const isOwnAccount = (p: string, owner: string): boolean =>
  p === owner || new RegExp(`^arn:aws[a-z-]*:iam::${owner}:`).test(p);

/** True when a statement's conditions hold the caller to the owner account. */
function heldToAccount(statement: Row, owner: string): boolean {
  const condition = getCI(statement, "Condition");
  const equals = isObject(condition) ? getCI(condition, "StringEquals") : undefined;
  if (!isObject(equals)) return false;
  return Object.entries(equals).some(([k, v]) => {
    const values = asList(v).map((x) => str(x).trim());
    return (
      ACCOUNT_CONDITION_KEYS.includes(k.toLowerCase()) &&
      values.length > 0 &&
      values.every((x) => x === owner)
    );
  });
}

function principalIsTrusted(statement: Row, owner: string, starHeld: boolean): boolean {
  if (getCI(statement, "NotPrincipal") !== undefined) return false;
  const principal = getCI(statement, "Principal");
  const star = starHeld && heldToAccount(statement, owner);
  if (principal === "*") return star;
  if (!isObject(principal)) return false;
  const entries = Object.entries(principal);
  if (!entries.length) return false;
  return entries.every(([kind, v]) => {
    const values = asList(v).map((x) => str(x).trim());
    if (!values.length) return false;
    if (/^service$/i.test(kind)) return values.every((x) => SERVICE_PRINCIPAL.test(x));
    if (/^aws$/i.test(kind)) return values.every((x) => (x === "*" ? star : isOwnAccount(x, owner)));
    return false;
  });
}

/**
 * The service principals a policy grants when every Allow statement names only AWS services or the
 * owner account; null otherwise (including an unreadable document or no owner account).
 * `starHeldToAccount` lets a `*` principal count when a condition holds the caller to the owner.
 */
export function trustedOnlyGrant(
  policy: unknown,
  ownerAccount: string,
  opts: { starHeldToAccount?: boolean } = {},
): { services: string[]; ownAccount: boolean } | null {
  const owner = ownerAccount.trim();
  const doc = policyDoc(policy);
  if (!doc || !ACCOUNT_ID.test(owner)) return null;
  const allows = allowStatements(doc);
  if (!allows?.length) return null;
  if (!allows.every((s) => principalIsTrusted(s, owner, opts.starHeldToAccount === true))) return null;
  const services = new Set<string>();
  let ownAccount = false;
  for (const s of allows) {
    const principal = getCI(s, "Principal");
    if (!isObject(principal)) {
      ownAccount = true; // a `*` held to the owner account
      continue;
    }
    for (const x of asList(getCI(principal, "Service"))) services.add(str(x).trim().toLowerCase());
    if (getCI(principal, "AWS") !== undefined) ownAccount = true;
  }
  return { services: [...services].sort(), ownAccount };
}
