// Inbox-rule and transport-rule snapshots (#2305) → observed state. The rule's actions are read with
// the same reader the UAL action path uses (exchangeInboxRules.readRuleParams), so a snapshot row and
// a New-InboxRule record word the same rule the same way. What differs is the GRADE.
//
// ruleGrade (the action path) grades every move-to-folder and every mark-as-read Medium: a NEW rule
// that hides mail is a tradecraft event. A snapshot is the whole tenant's standing rules, so the same
// grade would put every "move newsletters to Newsletters" rule into the forensic timeline. Here:
//   High   — forwards or redirects to an address outside the tenant's domains (T1114.003);
//   Medium — deletes mail, or moves it to a folder used to hide it (T1564.008); a transport rule that
//            redirects or copies mail where the export cannot say whether the address is external;
//   Low    — forwards inside the tenant, or to an address that is not an SMTP address;
//   Info   — everything else (kept in the super-timeline, searchable, out of the forensic timeline).
//
// "Outside the tenant": the export names no tenant domain list, so the tenant's domains are the
// domains of the mailboxes in the same file (inbox rules) or of the rules' CreatedBy accounts
// (transport rules). The UAL path compares against the one mailbox owner's domain; a set is the same
// decision made with more of the tenant's domains, so a rule forwarding to a sibling accepted domain
// is not called external.

import { readRuleParams } from "./exchangeInboxRules.js";
import { truthy } from "./exchangeAuditValues.js";
import {
  clean,
  col,
  domainOfEmail,
  emailsIn,
  historyDetail,
  identityKey,
  quoted,
  stateOf,
  type MappedSnapshot,
  type SnapRow,
} from "./cloudSnapshotModel.js";

const NAME_MAX = 60;
const FOLDER_MAX = 40;
const DESCRIPTION_MAX = 300;

/** Folders BEC actors move mail into so the mailbox owner does not see it. Kept short on purpose. */
export const HIDE_FOLDERS = new Set([
  "rss feeds",
  "rss subscriptions",
  "conversation history",
  "archive",
  "deleted items",
  "junk email",
]);

const OUTSIDE = "outside the tenant's domains in this export";
const INSIDE = "inside the tenant";

type AddressClass = "outside" | "inside" | "unclassed";

function classify(addr: string, tenantDomains: ReadonlySet<string>): AddressClass {
  if (!tenantDomains.size) return "unclassed";
  return tenantDomains.has(domainOfEmail(addr)) ? "inside" : "outside";
}

interface AddressActions {
  words: string[];
  classes: Set<AddressClass>;
}

function addressActions(
  pairs: ReadonlyArray<[string, string]>,
  tenantDomains: ReadonlySet<string>,
): AddressActions {
  const words: string[] = [];
  const classes = new Set<AddressClass>();
  for (const [verb, raw] of pairs) {
    const addrs = emailsIn(raw);
    if (!addrs.length && raw.trim()) {
      words.push(`${verb} ${quoted(raw, NAME_MAX)} (not an SMTP address)`);
      classes.add("unclassed");
    }
    if (!addrs.length) continue;
    // Every recipient is classified, not only the ones shown: an external address in fourth place
    // still grades the rule, and outside addresses are listed first so the summary names them.
    const classed = addrs.map((a) => ({ a, c: classify(a, tenantDomains) }));
    for (const { c } of classed) classes.add(c);
    const ordered = [
      ...classed.filter((x) => x.c === "outside"),
      ...classed.filter((x) => x.c !== "outside"),
    ];
    words.push(`${verb} ${recipientList(ordered)}`);
  }
  return { words, classes };
}

const SHOWN = 3;
const label = ({ a, c }: { a: string; c: AddressClass }): string =>
  c === "unclassed" ? a : `${a} (${c === "outside" ? OUTSIDE : INSIDE})`;

/** Up to SHOWN recipients, then a count that still names any omitted outside address. */
function recipientList(ordered: ReadonlyArray<{ a: string; c: AddressClass }>): string {
  const shown = ordered.slice(0, SHOWN).map(label).join(", ");
  const rest = ordered.slice(SHOWN);
  if (!rest.length) return shown;
  const outside = rest.filter((x) => x.c === "outside");
  const extra = outside.length
    ? `, of which ${outside.length} ${outside.slice(0, SHOWN).map(label).join(", ")}${outside.length > SHOWN ? ", …" : ""}`
    : "";
  return `${shown} (+${rest.length} more${extra})`;
}

/** The last segment of a folder path: `user@x:\RSS Feeds` → `RSS Feeds`. */
const folderName = (v: string): string =>
  v
    .split(/[\\/:]/)
    .pop()
    ?.trim() ?? "";

// ───────────────────────────── inbox rules ─────────────────────────────

const INBOX_PASSTHROUGH = [
  "deletemessage",
  "softdeletemessage",
  "markasread",
  "stopprocessingrules",
  "copytofolder",
  "applycategory",
  "subjectcontainswords",
  "subjectorbodycontainswords",
  "bodycontainswords",
  "from",
  "fromaddresscontainswords",
  "sentto",
  "headercontainswords",
  "recipientaddresscontainswords",
  "hasattachment",
];

/** The cmdlet-parameter map readRuleParams reads, from either the Exchange or the Graph columns. */
function ruleParams(row: SnapRow): Map<string, string> {
  const p = new Map<string, string>();
  for (const k of INBOX_PASSTHROUGH) if (row[k]?.trim()) p.set(k, row[k]);
  // Graph shape (Get-MailboxRulesGraph): Delete / PermanentDelete / SubjectContains / BodyContains.
  if (truthy(row.delete ?? "") || truthy(row.permanentdelete ?? "")) p.set("deletemessage", "True");
  if (row.subjectcontains?.trim()) p.set("subjectcontainswords", row.subjectcontains);
  if (row.bodycontains?.trim()) p.set("bodycontainswords", row.bodycontains);
  if (row.hasattachments?.trim()) p.set("hasattachment", row.hasattachments);
  const folder = folderName(row.movetofolder ?? "");
  if (folder) p.set("movetofolder", clean(folder, FOLDER_MAX));
  return p;
}

const INBOX_IDENTITY = [
  "username",
  "mailboxownerid",
  "userprincipalname",
  "ruleidentity",
  "ruleid",
  "identity",
];

function inboxGrade(a: AddressActions, hides: boolean): Pick<MappedSnapshot, "severity" | "mitre"> {
  if (a.classes.has("outside"))
    return { severity: "High", mitre: hides ? ["T1114.003", "T1564.008"] : ["T1114.003"] };
  if (hides) return { severity: "Medium", mitre: ["T1564.008"] };
  if (a.classes.size) return { severity: "Low", mitre: ["T1114.003"] };
  return { severity: "Info", mitre: [] };
}

/** One inbox-rule row. `tenantDomains`: the domains of every mailbox in the same file. */
export function mapInboxRule(row: SnapRow, tenantDomains: ReadonlySet<string>): MappedSnapshot | null {
  const mailbox = col(row, "username", "mailboxownerid", "userprincipalname").toLowerCase();
  const name = col(row, "rulename", "name");
  const ruleId = col(row, "ruleidentity", "ruleid") || `name:${name}`;
  if (!mailbox || (!name && ruleId === "name:")) return null;
  const addresses = addressActions(
    [
      ["forwards to", col(row, "forwardto")],
      ["forwards as attachment to", col(row, "forwardasattachmentto", "forwardasattachment")],
      ["redirects to", col(row, "redirectto")],
    ],
    tenantDomains,
  );
  const reading = readRuleParams(ruleParams(row), "", false);
  const folder = folderName(row.movetofolder ?? "").toLowerCase();
  const deletes = ["deletemessage", "delete", "permanentdelete", "softdeletemessage"].some((k) =>
    truthy(row[k] ?? ""),
  );
  const hides = deletes || HIDE_FOLDERS.has(folder);
  const actions = [...addresses.words, ...reading.actions];
  const disabled = /^(false|0)$/i.test(col(row, "enabled"));
  const summary = [
    (disabled ? "disabled; " : "") + (actions.length ? actions.join(", ") : "no action decoded"),
    ...(reading.conditions.length ? [reading.conditions.join(", ")] : []),
    `rule ${quoted(name, NAME_MAX)}`,
  ].join("; ");
  return {
    identityKey: identityKey("m365", "", "inbox-rule", `${mailbox}|${ruleId}`),
    state: stateOf(row, [...INBOX_IDENTITY, "description"]),
    subject: `inbox rule on ${clean(mailbox, NAME_MAX)}`,
    summary,
    details: historyDetail(row),
    ...inboxGrade(addresses, hides),
  };
}

/** The tenant's domains as an inbox-rule file shows them: the domain of every mailbox in it. */
export function mailboxDomains(rows: readonly SnapRow[]): Set<string> {
  const out = new Set<string>();
  for (const r of rows) {
    const m = col(r, "username", "mailboxownerid", "userprincipalname");
    if (m.includes("@")) out.add(domainOfEmail(m));
  }
  return out;
}

// ───────────────────────────── transport rules ─────────────────────────────

// MES's own TransportRules.csv carries only Name, Description, CreatedBy, WhenChanged, State,
// Priority, Mode: the actions live in the Description text. A raw Get-TransportRule export has
// dedicated columns. A dedicated column wins; the Description is read only when it is absent.
const TRANSPORT_ADDRESS: ReadonlyArray<[string, string, RegExp]> = [
  ["redirectmessageto", "redirects to", /redirect the message to/i],
  ["blindcopyto", "blind-copies to", /blind carbon copy|\bbcc\b/i],
  ["copyto", "copies to", /carbon copy \(cc\) the message to/i],
  ["addtorecipients", "adds as recipient", /add recipients? to the to box/i],
];

function transportAddressPairs(row: SnapRow): Array<[string, string]> {
  const lines = (row.description ?? "").split(/[\r\n]+|(?<=[.'"])\s+(?=[A-Z])/);
  return TRANSPORT_ADDRESS.map(([column, verb, re]) => {
    if (column in row) return [verb, row[column] ?? ""] as [string, string];
    return [verb, lines.filter((l) => re.test(l)).join(" ")] as [string, string];
  });
}

function transportGrade(a: AddressActions, deletes: boolean): Pick<MappedSnapshot, "severity" | "mitre"> {
  if (a.classes.has("outside")) return { severity: "High", mitre: ["T1114.003"] };
  if (a.classes.has("unclassed")) return { severity: "Medium", mitre: ["T1114.003"] };
  if (deletes) return { severity: "Medium", mitre: ["T1564.008"] };
  if (a.classes.has("inside")) return { severity: "Low", mitre: ["T1114.003"] };
  return { severity: "Info", mitre: [] };
}

const UNDECIDED = "whether the address is outside the tenant is not decidable from this export";

/** One transport-rule row. `tenantDomains`: the domains of the CreatedBy accounts in the same file. */
export function mapTransportRule(row: SnapRow, tenantDomains: ReadonlySet<string>): MappedSnapshot | null {
  const name = col(row, "identity", "name");
  if (!name) return null;
  const addresses = addressActions(transportAddressPairs(row), tenantDomains);
  const deletes =
    "deletemessage" in row
      ? truthy(row.deletemessage ?? "")
      : /delete the message without notifying/i.test(row.description ?? "");
  const scl =
    "setscl" in row
      ? col(row, "setscl")
      : (/spam confidence level \(SCL\) to '?(-?\d+)/i.exec(row.description ?? "")?.[1] ?? "");
  const actions = [
    ...addresses.words,
    ...(deletes ? ["deletes the message"] : []),
    ...(scl === "-1" ? ["sets SCL -1 (the message skips spam filtering)"] : []),
  ];
  const state = col(row, "state");
  const mode = col(row, "mode");
  const status = [state && `state ${clean(state, 20)}`, mode && `mode ${clean(mode, 20)}`].filter(Boolean);
  const undecided = !tenantDomains.size && addresses.classes.has("unclassed") ? [UNDECIDED] : [];
  const summary = [
    actions.length ? actions.join(", ") : "no redirect, copy or delete action read",
    ...undecided,
    ...(status.length ? [status.join(", ")] : []),
    `rule ${quoted(name, NAME_MAX)}`,
  ].join("; ");
  const description = col(row, "description");
  return {
    identityKey: identityKey("m365", "", "transport-rule", name),
    state: stateOf(row, ["identity", "name"]),
    subject: "transport rule",
    summary,
    details: [
      ...historyDetail(row),
      ...(description ? [`rule description ${quoted(description, DESCRIPTION_MAX)}`] : []),
    ],
    ...transportGrade(addresses, deletes),
  };
}

/** The tenant's domains as a transport-rule file shows them: the domains of its CreatedBy accounts. */
export function creatorDomains(rows: readonly SnapRow[]): Set<string> {
  const out = new Set<string>();
  for (const r of rows) for (const a of emailsIn(col(r, "createdby"))) out.add(domainOfEmail(a));
  return out;
}
