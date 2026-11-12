// RDS snapshot sharing and Lambda resource-policy grants, as one CloudTrail request states them
// (#2605). Before this, both calls rendered only their event name, so the tags.yaml rules could not
// tell a public share from an account-scoped one, or a public function from routine trigger wiring.
//
// What a reading establishes, and what it never says:
//   - the REQUESTED change, as the call's own parameters state it — never whether it took effect,
//     nor what the snapshot or function allowed before;
//   - "publicly" for an RDS restore attribute value of "all", and "any principal" for a Lambda
//     principal of "*" with none of the condition keys (sourceArn / sourceAccount / principalOrgID).
//     A conditional "*" is said as conditional, never as public; the condition is not evaluated.
// Every value is attacker-controlled and bounded through `show`. Pure.

import { getCI, isObject, str } from "./siemImport.js";
import { show } from "./loggingChange.js";

type Row = Record<string, unknown>;
const LIST_MAX = 5;
const RDS_CALLS: Record<string, { idKey: string; noun: string }> = {
  modifydbsnapshotattribute: { idKey: "dBSnapshotIdentifier", noun: "DB snapshot" },
  modifydbclustersnapshotattribute: { idKey: "dBClusterSnapshotIdentifier", noun: "DB cluster snapshot" },
};
const LAMBDA_ADD_PERMISSION = /^addpermission(?:\d{8}(?:v\d+)?)?$/;
const CONDITION_KEYS = ["sourceArn", "sourceAccount", "principalOrgID"];

const serviceOf = (eventSource: string): string => eventSource.trim().toLowerCase().split(".")[0] ?? "";
/** A set as CloudTrail records it: a bare array, `{ items: [...] }` or a single value — its strings. */
const values = (v: unknown): string[] => {
  const list = Array.isArray(v) ? v : isObject(v) ? getCI(v, "items") : v;
  const all = Array.isArray(list) ? list : list === undefined || list === null ? [] : [list];
  return all.map((x) => str(x).trim()).filter(Boolean);
};
const listed = (names: string[]): string =>
  names
    .slice(0, LIST_MAX)
    .map((n) => show(n, 60))
    .join(", ") + (names.length > LIST_MAX ? ` (+${names.length - LIST_MAX} more)` : "");

function rdsReading(call: { idKey: string; noun: string }, request: Row): string {
  if (str(getCI(request, "attributeName")).trim().toLowerCase() !== "restore") return "";
  const what = `${call.noun} ${show(str(getCI(request, call.idKey)) || "?", 60)}`;
  const describe = (v: unknown) => {
    const all = values(v);
    return { world: all.some((x) => /^all$/i.test(x)), accounts: all.filter((x) => !/^all$/i.test(x)) };
  };
  const add = describe(getCI(request, "valuesToAdd"));
  const remove = describe(getCI(request, "valuesToRemove"));
  if (add.world) return `shares ${what} publicly (restore attribute "all")`;
  if (add.accounts.length) return `shares ${what} with account ${listed(add.accounts)}`;
  if (remove.world || remove.accounts.length)
    return `removes sharing of ${what}${remove.world ? " (public)" : ` from account ${listed(remove.accounts)}`}`;
  return "";
}

function principalWords(principal: string, request: Row, recipient: string): string {
  if (principal === "*") {
    const keys = CONDITION_KEYS.filter((k) => str(getCI(request, k)).trim());
    return keys.length
      ? `to any principal ("*") under a condition (${keys.join(", ")} set; not evaluated)`
      : 'to any principal ("*")';
  }
  // A bare account id, or the account of an IAM / STS ARN (root, a role, a user).
  const account = /^(?:(\d{12})|arn:aws[\w-]*:(?:iam|sts)::(\d{12}):.+)$/
    .exec(principal)
    ?.slice(1)
    .find(Boolean);
  if (account) {
    const side = !recipient ? "" : account === recipient ? " (this account)" : " (another account)";
    return `to account ${show(principal, 60)}${side}`;
  }
  if (/\.amazonaws\.com(?:\.cn)?$/i.test(principal)) return `to service ${show(principal, 60)}`;
  return `to principal ${show(principal, 60)}`;
}

function lambdaReading(request: Row, recipient: string): string {
  const principal = str(getCI(request, "principal")).trim();
  if (!principal) return "";
  const action = show(str(getCI(request, "action")) || "?", 40);
  const fn = show(str(getCI(request, "functionName")) || "?", 60);
  const url = /^none$/i.test(str(getCI(request, "functionUrlAuthType")).trim())
    ? "; function URL with no authentication (FunctionUrlAuthType NONE)"
    : "";
  // The principal before the function name: it is the deciding value, and the name is attacker-chosen.
  return `grants ${action} ${principalWords(principal, request, recipient)} on function ${fn}${url}`;
}

/** The sharing an RDS snapshot-attribute or Lambda AddPermission request states, or "" for any other call. */
export function resourceSharingReading(
  eventName: string,
  eventSource: string,
  request: Row,
  recipient: string,
): string {
  const n = eventName.toLowerCase();
  const service = serviceOf(eventSource);
  const rds = Object.hasOwn(RDS_CALLS, n) ? RDS_CALLS[n] : undefined;
  if (rds && service === "rds") return rdsReading(rds, request);
  if (LAMBDA_ADD_PERMISSION.test(n) && service === "lambda") return lambdaReading(request, recipient);
  return "";
}
