import type { Severity } from "./stateTypes.js";
import {
  domainClass,
  falsy,
  FOLDER_MAX,
  list,
  NAME_MAX,
  quote,
  truthy,
  values,
  withClass,
} from "./exchangeAuditValues.js";

// Inbox-rule parameters read into words (#931 item 2): the actions a rule was given (forward,
// redirect, delete, move, mark read), the conditions, and — for Set-InboxRule — only the DELTAS
// supplied, since an absent parameter on a Set is unchanged, never absent. A forwarding address is
// classed against the mailbox owner's domain; a value that is not an SMTP address gets no class.

export interface RuleReading {
  actions: string[];
  conditions: string[];
  /** Condition or exception parameters the reader does not decode — supplied, not read. */
  undecoded: string[];
  forwardsOutside: boolean;
  forwardsInside: boolean;
  forwardsUnclassed: boolean;
  hides: boolean;
  any: boolean;
  deltas: string[];
}

export const ACTION_ADDRESS: Array<[string, string]> = [
  ["forwardto", "forwards to"],
  ["forwardasattachmentto", "forwards as attachment to"],
  ["redirectto", "redirects to"],
];
const ACTION_FLAG: Array<[string, string]> = [
  ["deletemessage", "deletes the message"],
  ["markasread", "marks as read"],
  ["stopprocessingrules", "stops processing more rules"],
  ["softdeletemessage", "soft-deletes the message"],
];
const CONDITION_WORDS: Array<[string, string]> = [
  ["subjectcontainswords", "when subject contains"],
  ["subjectorbodycontainswords", "when subject or body contains"],
  ["bodycontainswords", "when body contains"],
  ["from", "from"],
  ["fromaddresscontainswords", "when the sender address contains"],
  ["sentto", "sent to"],
  ["headercontainswords", "when a header contains"],
  ["recipientaddresscontainswords", "when a recipient address contains"],
];
const CONDITION_FLAG_WORDS: Record<string, string> = {
  mynameintobox: "my name is in the To box",
  mynameinccbox: "my name is in the Cc box",
  hasattachment: "the message has an attachment",
  myselfonly: "I am the only recipient",
  sentonlytome: "sent only to me",
  withimportance: "marked with importance",
  withsensitivity: "marked with sensitivity",
};
const CONDITION_FLAGS = [
  "mynameintobox",
  "mynameinccbox",
  "hasattachment",
  "myselfonly",
  "sentonlytome",
  "withimportance",
  "withsensitivity",
];

// Every parameter that is neither an action nor rule metadata narrows the rule: a condition the
// reader does not decode is still a condition, and an ExceptIf* parameter is an exception.
const META_PARAMS = new Set([
  "name",
  "identity",
  "mailbox",
  "enabled",
  "priority",
  "confirm",
  "whatif",
  "force",
  "alwaysdeleteoutlookrulesblob",
  "stopprocessingrules",
  "applycategory",
  "copytofolder",
  "sendtextmessagenotificationto",
  "movetofolder",
  "deletemessage",
  "markasread",
  "softdeletemessage",
  "markimportance",
  "pinmessage",
  "forwardto",
  "forwardasattachmentto",
  "redirectto",
]);

export function readRuleParams(p: Map<string, string>, ownerDomain: string, isSet: boolean): RuleReading {
  const r: RuleReading = {
    actions: [],
    conditions: [],
    undecoded: [],
    forwardsOutside: false,
    forwardsInside: false,
    forwardsUnclassed: false,
    hides: false,
    any: false,
    deltas: [],
  };
  const prefix = isSet ? "now " : "";
  for (const [param, verb] of ACTION_ADDRESS) {
    const raw = p.get(param);
    if (raw === undefined) continue;
    const addrs = values(raw);
    if (!addrs.length) continue;
    r.any = true;
    r.actions.push(`${prefix}${verb} ${addrs.map((a) => withClass(a, ownerDomain)).join(", ")}`);
    for (const a of addrs) {
      const cls = domainClass(a, ownerDomain);
      if (cls.startsWith("outside")) r.forwardsOutside = true;
      else if (cls.startsWith("inside")) r.forwardsInside = true;
      else r.forwardsUnclassed = true;
    }
  }
  for (const [param, words] of ACTION_FLAG) {
    const raw = p.get(param);
    if (raw === undefined) continue;
    if (truthy(raw)) {
      r.any = true;
      // Stopping later rules conceals nothing by itself; only delete / move / mark-read do.
      if (param !== "stopprocessingrules") r.hides = true;
      r.actions.push(`${prefix}${words}`);
    } else if (isSet && falsy(raw)) {
      // `-DeleteMessage $false` on a Set is a delta too: the action is switched off.
      r.any = true;
      r.deltas.push(`no longer ${words}`);
    }
  }
  const move = p.get("movetofolder");
  if (move) {
    r.any = true;
    r.hides = true;
    r.actions.push(`${prefix}moves to ${quote(move, FOLDER_MAX)}`);
  }
  for (const other of ["applycategory", "copytofolder", "sendtextmessagenotificationto"]) {
    const raw = p.get(other);
    if (raw) {
      r.any = true;
      r.actions.push(
        `${prefix}${other === "applycategory" ? "applies category" : other === "copytofolder" ? "copies to" : "sends a text notification to"} ${quote(raw, FOLDER_MAX)}`,
      );
    }
  }
  for (const [param, words] of CONDITION_WORDS) {
    const raw = p.get(param);
    if (raw) r.conditions.push(`${words} ${list(values(raw))}`);
  }
  for (const flag of CONDITION_FLAGS) {
    const raw = p.get(flag);
    if (raw === undefined) continue;
    const words = CONDITION_FLAG_WORDS[flag] ?? flag;
    if (truthy(raw)) r.conditions.push(`when ${words}`);
    // Switching a condition OFF on a Set broadens the rule — a delta the row must show.
    else if (isSet && falsy(raw)) r.deltas.push(`no longer only when ${words}`);
  }
  const known = new Set([...CONDITION_WORDS.map(([k]) => k), ...CONDITION_FLAGS]);
  for (const [name, raw] of p) {
    if (META_PARAMS.has(name) || known.has(name) || !raw.trim()) continue;
    r.undecoded.push(name.startsWith("exceptif") ? `except ${name.slice(8)}` : name);
  }
  if (isSet) {
    const name = p.get("name");
    if (name) r.deltas.push(`renamed to ${quote(name, NAME_MAX)}`);
    const enabled = p.get("enabled");
    if (enabled !== undefined)
      r.deltas.push(
        truthy(enabled) ? "now enabled" : falsy(enabled) ? "now disabled" : `enabled=${enabled.slice(0, 10)}`,
      );
  }
  return r;
}

export function ruleGrade(r: RuleReading): { severity: Severity; mitre: string[] } {
  if (r.forwardsOutside)
    return { severity: "High", mitre: r.hides ? ["T1114.003", "T1564.008"] : ["T1114.003"] };
  if (r.forwardsInside || r.forwardsUnclassed) return { severity: "Medium", mitre: ["T1114.003"] };
  if (r.hides) return { severity: "Medium", mitre: ["T1564.008"] };
  return { severity: "Low", mitre: [] };
}
