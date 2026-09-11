import type { Severity } from "./stateTypes.js";
import {
  ACCESS_NOTE,
  APP_USER_TYPES,
  CLIENT_MAX,
  digest,
  domainClass,
  domainOf,
  ipOf,
  falsy,
  FOLDER_MAX,
  getCI,
  isObject,
  list,
  NAME_MAX,
  pairs,
  plural,
  quote,
  SESSION_MAX,
  SET_FORWARD_NOTE,
  SET_RULE_NOTE,
  str,
  SUBJECT_MAX,
  SYNC_NOTE,
  THROTTLED_NOTE,
  truthy,
  values,
  withClass,
} from "./exchangeAuditValues.js";
import { ACTION_ADDRESS, readRuleParams, ruleGrade, type RuleReading } from "./exchangeInboxRules.js";
import type { Pairs } from "./exchangeAuditValues.js";

const TRUNCATED_NOTE = "parameters truncated — the complete values are in the raw record";

// Exchange Online audit records, read one at a time (#931 item 2).
//
// A Unified Audit Log record establishes: the parameters a cmdlet was given (New-InboxRule carries
// the whole rule; Set-* carries ONLY what changed — an absent parameter is unchanged, never
// absent), the items a MailItemsAccessed record LISTS (OperationCount counts operations, not
// messages), who reached which mailbox in which session and through which client, and whether the
// command succeeded. It does not establish that a forwarded message was delivered, that a bound
// item was read by a person, or the tenant's verified domains — so an address is classed against
// the MAILBOX OWNER's domain, never "external to the tenant". A failed or unknown result is an
// attempt: "attempted to create inbox rule", no completed verb, no success-only technique.
//
// Record types (Microsoft's): 1 ExchangeAdmin (cmdlets, `Parameters[]`), 2 ExchangeItem (one
// `Item`; also the Outlook-created UpdateInboxRules), 3 ExchangeItemGroup (`AffectedItems[]`),
// 19 ExchangeAggregatedOperation (counts, no items), 50 ExchangeItemAggregated (MailItemsAccessed:
// `OperationProperties[]`, `Folders[].FolderItems[]`).

type Row = Record<string, unknown>;

export interface ExchangeChange {
  kind: "rule" | "forwarding" | "permission" | "access" | "aggregate" | "item";
  recordType: number;
  operation: string;
  posture: string;
  attempted: boolean;
  outcome: "success" | "partial" | "failure" | "unknown";
  /** `on <mailbox> as <logon type> via <client> session <id>` — "" for a cmdlet row. */
  object: string;
  /** The scope words: actions and conditions, counts, the subject. */
  words: string;
  qualifiers: string[];
  severity: Severity;
  mitre: string[];
  /** The WHOLE aggregation key — the importer bounds it. */
  key: string;
  mailbox: string;
  mailboxId: string;
  actor: string;
  actorIsApp: boolean;
  appId: string;
  ip: string;
  session: string;
  /** A forwarding address, a trustee, a destination mailbox or the recipients — the envelope's target. */
  target: string;
  /** The identity a SendAs / SendOnBehalf acted as — the envelope's subject; "" otherwise. */
  sentAs: string;
  tenant: string;
  recordId: string;
  time: string;
}

function outcomeOf(rec: Row): ExchangeChange["outcome"] {
  const r = str(getCI(rec, "ResultStatus")).trim().toLowerCase();
  if (/^(succeeded|success|true)$/.test(r)) return "success";
  if (r === "partiallysucceeded") return "partial";
  if (/^(failed|failure|false)$/.test(r)) return "failure";
  return "unknown";
}
const PARTIAL_NOTE = "partially succeeded — which actions completed is not in this record";

function clientOf(info: string): string {
  const client = /client=([^;]+)/i.exec(info)?.[1]?.trim() ?? "";
  const protocol = /protocol=([^;]+)/i.exec(info)?.[1]?.trim() ?? "";
  if (!client) return info.trim().slice(0, CLIENT_MAX);
  return `${client.slice(0, CLIENT_MAX)}${protocol && protocol.toLowerCase() !== client.toLowerCase() ? ` (${protocol.slice(0, 16)})` : ""}`;
}

const LOGON = ["owner", "admin", "delegate"];
const logonWord = (t: string): string => (/^[0-2]$/.test(t) ? LOGON[Number(t)] : t ? `logon type ${t}` : "");

interface Common {
  rec: Row;
  index: number;
  recordType: number;
  operation: string;
  outcome: ExchangeChange["outcome"];
  attempted: boolean;
  tenant: string;
  recordId: string;
  actor: string;
  actorIsApp: boolean;
  appId: string;
  ip: string;
  session: string;
  mailbox: string;
  mailboxId: string;
  ownerDomain: string;
  logon: string;
  client: string;
}

function common(rec: Row, index: number): Common {
  const userType = Number(str(getCI(rec, "UserType")));
  const actor = str(getCI(rec, "UserId")).trim();
  // ObjectId on a cmdlet record is `mailbox\Rule name` for a rule and the mailbox alone otherwise;
  // the mailbox may be an alias, a name or a DN, not only a UPN — it is the identity either way,
  // and only a UPN yields a domain to class addresses against.
  const objectId = str(getCI(rec, "ObjectId")).trim().split("\\")[0];
  const mailbox = str(getCI(rec, "MailboxOwnerUPN")).trim() || objectId;
  return {
    rec,
    index,
    recordType: Number(str(getCI(rec, "RecordType"))) || 0,
    operation: str(getCI(rec, "Operation")).trim(),
    outcome: outcomeOf(rec),
    // A partial success changed something — it is not an attempt, and the row says it is partial.
    attempted: outcomeOf(rec) === "failure" || outcomeOf(rec) === "unknown",
    tenant: str(getCI(rec, "OrganizationId")).trim(),
    recordId: str(getCI(rec, "Id")).trim(),
    actor,
    actorIsApp: APP_USER_TYPES.has(userType),
    appId: str(getCI(rec, "AppId")).trim() || str(getCI(rec, "ClientAppId")).trim(),
    ip: ipOf(str(getCI(rec, "ClientIPAddress")).trim() || str(getCI(rec, "ClientIP")).trim()),
    session: str(getCI(rec, "SessionId")).trim(),
    mailbox,
    mailboxId: str(getCI(rec, "MailboxGuid")).trim(),
    ownerDomain: mailbox.includes("@") ? domainOf(mailbox) : "",
    logon: logonWord(str(getCI(rec, "LogonType")).trim()),
    client: clientOf(str(getCI(rec, "ClientInfoString"))),
  };
}

function objectOf(c: Common): string {
  const apps = [
    str(getCI(c.rec, "ClientAppId")).trim(),
    str(getCI(c.rec, "AppId")).trim(),
    str(getCI(c.rec, "HostAppId")).trim(),
  ].filter(Boolean);
  return [
    c.mailbox ? `on ${c.mailbox}` : "",
    c.logon ? `as ${c.logon}` : "",
    c.client ? `via ${c.client}` : "",
    c.session ? `session ${c.session.slice(0, SESSION_MAX)}` : "",
    apps.length ? `client app ${[...new Set(apps)].join(", ").slice(0, 80)}` : "",
  ]
    .filter(Boolean)
    .join(" ");
}

function finish(
  c: Common,
  o: {
    kind: ExchangeChange["kind"];
    verb: string;
    infinitive: string;
    words?: string;
    qualifiers?: string[];
    severity: Severity;
    mitre?: string[];
    scope: string;
    target?: string;
    sentAs?: string;
    object?: string;
    incompleteScope?: boolean;
  },
): ExchangeChange {
  const posture = c.attempted
    ? `attempted to ${o.infinitive}`
    : c.outcome === "partial"
      ? `partly ${o.verb}`
      : o.verb;
  const incomplete = o.incompleteScope || !c.mailbox || !c.actor;
  const scopeId = incomplete ? `${o.scope}|${c.recordId || `record:${c.index}`}` : o.scope;
  const key = [
    "exchange",
    c.tenant,
    c.recordType,
    c.operation,
    c.outcome,
    c.mailboxId || c.mailbox,
    c.actor,
    c.ip,
    str(getCI(c.rec, "AppId")),
    str(getCI(c.rec, "ClientAppId")),
    str(getCI(c.rec, "HostAppId")),
    str(getCI(c.rec, "LogonType")),
    c.session,
    str(getCI(c.rec, "ClientInfoString")),
    digest(scopeId),
  ]
    .join("|")
    .toLowerCase();
  return {
    kind: o.kind,
    recordType: c.recordType,
    operation: c.operation,
    posture,
    attempted: c.attempted,
    outcome: c.outcome,
    object: o.object ?? objectOf(c),
    words: o.words ?? "",
    qualifiers: [...(c.outcome === "partial" ? [PARTIAL_NOTE] : []), ...(o.qualifiers ?? [])],
    severity: c.attempted ? (o.severity === "Info" ? "Info" : "Medium") : o.severity,
    mitre: c.attempted ? [] : (o.mitre ?? []),
    key,
    mailbox: c.mailbox,
    mailboxId: c.mailboxId,
    actor: c.actor,
    actorIsApp: c.actorIsApp,
    appId: c.appId,
    ip: c.ip,
    session: c.session,
    target: o.target ?? "",
    sentAs: o.sentAs ?? "",
    tenant: c.tenant,
    recordId: c.recordId,
    time: str(getCI(c.rec, "CreationTime")),
  };
}

// ───────────────────────────── rules ─────────────────────────────

// `-WhatIf` and `-ValidateOnly` make no change: a successful record of either is a simulation.
const isDryRun = (p: Map<string, string>): boolean =>
  ["whatif", "validateonly"].some((k) => p.has(k) && (truthy(p.get(k) ?? "") || p.get(k) === ""));
const DRY_RUN_NOTE = "dry run (WhatIf/ValidateOnly) — no change was made";

function ruleCmdlet(c: Common, pp: Pairs): ExchangeChange | null {
  const p = pp.map;
  const op = c.operation.toLowerCase();
  const m = /^(new|set|enable|disable|remove)-inboxrule$/.exec(op);
  // A record with no parameters at all cannot be read: the plain row (the table's grade) stands.
  if (!m || p.size === 0) return null;
  if (isDryRun(p)) {
    const label = quote(p.get("name") ?? (p.get("identity") ?? "").split("\\").pop() ?? "", NAME_MAX);
    return finish(c, {
      kind: "rule",
      verb: `simulates ${m[1] === "new" ? "creating" : m[1] === "set" ? "changing" : `${m[1] === "remove" ? "removing" : m[1] === "enable" ? "enabling" : "disabling"}`} inbox rule ${label}`,
      infinitive: `simulate a change to inbox rule ${label}`,
      words: "",
      qualifiers: [DRY_RUN_NOTE],
      severity: "Low",
      scope: `rule:dryrun:${pp.digest}`,
      incompleteScope: pp.truncated,
    });
  }
  const verb = m[1];
  const name = p.get("name") ?? "";
  const identity = p.get("identity") ?? "";
  const shown = verb === "new" ? name : identity.split("\\").pop() || identity || name;
  const label = quote(shown, NAME_MAX);
  const scope = `rule:${verb}:${shown}:${pp.digest}`;
  if (verb === "enable" || verb === "disable" || verb === "remove") {
    return finish(c, {
      kind: "rule",
      verb: `${verb}s inbox rule ${label}`,
      infinitive: `${verb} inbox rule ${label}`,
      severity: "Low",
      scope,
      incompleteScope: pp.truncated,
    });
  }
  const isSet = verb === "set";
  const r = readRuleParams(p, c.ownerDomain, isSet);
  const clauses = [...r.deltas, ...r.actions];
  // "on every message" only for a successful New-InboxRule that supplied NO condition or exception
  // parameter at all — decoded or not; an undecoded one is named as supplied, not read.
  const undecoded = r.undecoded.length ? `conditions supplied, not decoded: ${list(r.undecoded)}` : "";
  const conds = r.conditions.length
    ? [r.conditions.join("; "), undecoded].filter(Boolean).join("; ")
    : undecoded || (!isSet && !c.attempted && !pp.truncated ? "on every message" : "");
  const words = [clauses.join(", "), conds].filter(Boolean).join(" ");
  const grade = isSet && !r.any ? { severity: "Medium" as Severity, mitre: [] as string[] } : ruleGrade(r);
  const target = [...ACTION_ADDRESS].flatMap(([k]) => values(p.get(k) ?? ""))[0] ?? "";
  return finish(c, {
    kind: "rule",
    verb: `${isSet ? "changes" : "creates"} inbox rule ${label}`,
    infinitive: `${isSet ? "change" : "create"} inbox rule ${label}`,
    words,
    qualifiers: [...(isSet ? [SET_RULE_NOTE] : []), ...(pp.truncated ? [TRUNCATED_NOTE] : [])],
    ...grade,
    scope,
    target,
    incompleteScope: pp.truncated,
  });
}

// The Outlook/EWS form: RecordType 2 `UpdateInboxRules` with the rule in OperationProperties;
// RuleActions is a serialised JSON array of `{ActionType, Recipients, …}`.
function ruleMailboxAudit(c: Common): ExchangeChange | null {
  const pp = pairs(getCI(c.rec, "OperationProperties"));
  const p = pp.map;
  const op = (p.get("ruleoperation") ?? "").toLowerCase();
  const name = p.get("rulename") ?? "";
  const label = quote(name, NAME_MAX);
  const verb = /^remove/.test(op) ? "removes" : /^modify/.test(op) ? "changes" : "creates";
  const infinitive = verb === "removes" ? "remove" : verb === "changes" ? "change" : "create";
  const rawActions = p.get("ruleactions") ?? "";
  const condition = p.get("rulecondition") ?? "";
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
  let unparsed = "";
  const forwardTargets: string[] = [];
  if (rawActions) {
    let parsed: unknown = null;
    try {
      parsed = JSON.parse(rawActions);
    } catch {
      unparsed = rawActions;
    }
    for (const a of Array.isArray(parsed) ? parsed : []) {
      if (!isObject(a)) continue;
      const type = str(getCI(a, "ActionType")).toLowerCase();
      const recips = getCI(a, "Recipients");
      const addrs = (Array.isArray(recips) ? recips : [])
        .map((x) => (isObject(x) ? str(getCI(x, "Address")) || str(getCI(x, "Name")) : str(x)))
        .filter(Boolean);
      r.any = true;
      if (/forward|redirect/.test(type) && addrs.length) {
        forwardTargets.push(...addrs);
        r.actions.push(
          `${/redirect/.test(type) ? "redirects to" : /attachment/.test(type) ? "forwards as attachment to" : "forwards to"} ${addrs.map((x) => withClass(x, c.ownerDomain)).join(", ")}`,
        );
        for (const x of addrs) {
          const cls = domainClass(x, c.ownerDomain);
          if (cls.startsWith("outside")) r.forwardsOutside = true;
          else if (cls.startsWith("inside")) r.forwardsInside = true;
          else r.forwardsUnclassed = true;
        }
      } else if (/delete/.test(type)) {
        r.hides = true;
        r.actions.push("deletes the message");
      } else if (/movetofolder/.test(type)) {
        r.hides = true;
        r.actions.push(
          `moves to ${quote(str(getCI(a, "FolderName")) || str(getCI(a, "FolderId")), FOLDER_MAX)}`,
        );
      } else if (/markasread/.test(type)) {
        r.hides = true;
        r.actions.push("marks as read");
      } else if (type) r.actions.push(type.slice(0, 30));
    }
  }
  if (condition) r.conditions.push(`when ${condition.slice(0, 80)}`);
  const words = [
    r.actions.join(", "),
    unparsed ? `actions: ${unparsed.slice(0, 80)}` : "",
    r.conditions.join("; "),
  ]
    .filter(Boolean)
    .join(" ");
  const grade =
    verb === "removes"
      ? { severity: "Low" as Severity, mitre: [] as string[] }
      : unparsed && !r.any
        ? { severity: "Medium" as Severity, mitre: [] as string[] }
        : ruleGrade(r);
  return finish(c, {
    kind: "rule",
    verb: `${verb} inbox rule ${label}`,
    infinitive: `${infinitive} inbox rule ${label}`,
    words,
    qualifiers: [...(verb === "changes" ? [SET_RULE_NOTE] : []), ...(pp.truncated ? [TRUNCATED_NOTE] : [])],
    ...grade,
    scope: `rule:${op}:${name}:${pp.digest}`,
    target: forwardTargets.join(", "),
    incompleteScope: pp.truncated,
  });
}

// ───────────────────────────── forwarding and permissions ─────────────────────────────

function forwardingCmdlet(c: Common, pp: Pairs): ExchangeChange | null {
  const p = pp.map;
  if (isDryRun(p))
    return finish(c, {
      kind: "forwarding",
      verb: "simulates a mailbox change",
      infinitive: "simulate a mailbox change",
      qualifiers: [DRY_RUN_NOTE],
      severity: "Low",
      scope: `forwarding:dryrun:${pp.digest}`,
      incompleteScope: pp.truncated,
    });
  const smtp = p.get("forwardingsmtpaddress");
  const addr = p.get("forwardingaddress");
  const deliver = p.get("delivertomailboxandforward");
  if (smtp === undefined && addr === undefined && deliver === undefined) return null;
  const clauses: string[] = [];
  const infinitives: string[] = [];
  let severity: Severity = "Low";
  const mitre: string[] = [];
  let target = "";
  const isCleared = (v: string) => !v.trim() || /^\$?null$/i.test(v.trim());
  if (smtp !== undefined) {
    if (isCleared(smtp)) {
      clauses.push("clears SMTP forwarding");
      infinitives.push("clear SMTP forwarding");
    } else {
      const a = values(smtp)[0] ?? smtp;
      const cls = domainClass(a, c.ownerDomain);
      clauses.push(`sets SMTP forwarding to ${withClass(a, c.ownerDomain)}`);
      infinitives.push(`set SMTP forwarding to ${a}`);
      target = a;
      if (cls.startsWith("outside")) {
        severity = "High";
        mitre.push("T1114.003");
      } else severity = "Medium";
    }
  }
  if (addr !== undefined) {
    if (isCleared(addr)) {
      clauses.push("clears in-organization forwarding");
      infinitives.push("clear in-organization forwarding");
    } else {
      clauses.push(`sets forwarding to in-organization recipient ${addr.slice(0, 80)}`);
      infinitives.push(`set forwarding to in-organization recipient ${addr.slice(0, 80)}`);
      target = target || addr;
      if (severity !== "High") severity = "Medium";
    }
  }
  const words: string[] = [];
  if (deliver !== undefined)
    words.push(
      truthy(deliver)
        ? "a copy stays in the mailbox"
        : falsy(deliver)
          ? "no copy stays in the mailbox"
          : `DeliverToMailboxAndForward=${deliver.slice(0, 10)}`,
    );
  if (smtp !== undefined && addr !== undefined && !isCleared(addr) && !isCleared(smtp))
    words.push("ForwardingAddress takes precedence over ForwardingSmtpAddress");
  const complete = smtp !== undefined && addr !== undefined && deliver !== undefined;
  return finish(c, {
    kind: "forwarding",
    verb: clauses.join("; "),
    infinitive: infinitives.join("; "),
    words: words.join("; "),
    qualifiers: complete ? [] : [SET_FORWARD_NOTE],
    severity,
    mitre,
    scope: `forwarding:${pp.digest}`,
    target,
    incompleteScope: pp.truncated,
  });
}

function permissionCmdlet(c: Common, pp: Pairs): ExchangeChange | null {
  const p = pp.map;
  const m = /^(add|remove)-(mailboxpermission|mailboxfolderpermission|recipientpermission)$/.exec(
    c.operation.toLowerCase(),
  );
  if (!m) return null;
  const removal = m[1] === "remove";
  if (isDryRun(p))
    return finish(c, {
      kind: "permission",
      verb: "simulates a permission change",
      infinitive: "simulate a permission change",
      qualifiers: [DRY_RUN_NOTE],
      severity: "Low",
      scope: `permission:dryrun:${pp.digest}`,
      incompleteScope: pp.truncated,
    });
  const trustee = (p.get("trustee") ?? p.get("user") ?? "").trim();
  const rights = (p.get("accessrights") ?? "").trim() || "permission";
  const mailbox = p.get("identity") ?? c.mailbox;
  // `-Deny` adds or removes a DENY entry: adding one restricts, removing one may widen access —
  // the opposite direction from an allow entry.
  const deny = p.has("deny") && (p.get("deny") === "" || truthy(p.get("deny") ?? ""));
  const on = `${rights} on ${mailbox.slice(0, 60)}`;
  const forWhom = trustee ? ` for ${withClass(trustee, c.ownerDomain)}` : "";
  const to = trustee ? ` ${removal ? "from" : "to"} ${withClass(trustee, c.ownerDomain)}` : "";
  const verb = deny
    ? `${removal ? "removes a Deny entry" : "adds a Deny entry"} for ${on}${forWhom}${removal ? " (effective access may widen)" : ""}`
    : `${removal ? "revokes" : "grants"} ${on}${to}`;
  const infinitive = deny
    ? `${removal ? "remove a Deny entry" : "add a Deny entry"} for ${on}${forWhom}`
    : `${removal ? "revoke" : "grant"} ${on}${to}`;
  const widens = deny ? removal : !removal;
  return finish(c, {
    kind: "permission",
    verb,
    infinitive,
    severity: widens ? "Medium" : "Low",
    mitre: widens ? ["T1098.002"] : [],
    scope: `permission:${pp.digest}`,
    target: trustee,
    incompleteScope: pp.truncated,
  });
}

// ───────────────────────────── access and items ─────────────────────────────

// The item identity as the record holds it: every id it carries, so two records that differ in
// any of them are two rows.
const itemIds = (i: Row): string =>
  ["Id", "ImmutableId", "InternetMessageId"].map((k) => str(getCI(i, k))).join("/");
const listOf = (v: unknown): Row[] => (Array.isArray(v) ? v : []).filter(isObject);

// Access is graded by privilege, not suspicion — and an application actor is never the owner's
// own Outlook: at least Low, so a Low floor on import cannot drop it.
function accessSeverity(c: Common): Severity {
  if (c.actorIsApp) return c.logon === "admin" ? "Medium" : "Low";
  return c.logon === "owner" ? "Info" : c.logon === "admin" ? "Medium" : "Low";
}

function accessRecord(c: Common): ExchangeChange {
  const props = pairs(getCI(c.rec, "OperationProperties")).map;
  const accessType = (props.get("mailaccesstype") ?? str(getCI(c.rec, "MailAccessType")))
    .trim()
    .toLowerCase();
  const throttled = truthy(props.get("isthrottled") ?? str(getCI(c.rec, "IsThrottled")) ?? "");
  // Two documented layouts: Folders[].FolderItems[] and Messages[].MessageItems[].
  const containers = [...listOf(getCI(c.rec, "Folders")), ...listOf(getCI(c.rec, "Messages"))];
  const items = containers.flatMap((f) => [
    ...listOf(getCI(f, "FolderItems")),
    ...listOf(getCI(f, "MessageItems")),
  ]);
  const ops = Number(str(getCI(c.rec, "OperationCount")));
  const opsWords = Number.isFinite(ops) && ops > 0 ? ` (${plural(ops, "operation")})` : "";
  const ids = items.map(itemIds);
  const containerIds = containers.map((f) => `${str(getCI(f, "Id"))}:${str(getCI(f, "Path"))}`);
  const incomplete = items.some((i) => itemIds(i) === "//");
  const sync = accessType === "sync";
  const bind = accessType === "bind";
  const verb = sync
    ? `syncs folder ${quote(str(getCI(containers[0] ?? {}, "Path")) || "(unnamed)", FOLDER_MAX)}${containers.length > 1 ? ` (+${containers.length - 1} more)` : ""}`
    : `${bind ? "binds" : "accesses"} ${plural(items.length, "item")} in ${plural(containers.length, "folder")}${opsWords}${!bind && accessType ? ` [${accessType.slice(0, 20)}]` : ""}`;
  return finish(c, {
    kind: "access",
    verb,
    infinitive: sync ? "sync a folder" : bind ? "bind items" : "access items",
    qualifiers: [ACCESS_NOTE, ...(sync ? [SYNC_NOTE] : []), ...(throttled ? [THROTTLED_NOTE] : [])],
    severity: accessSeverity(c),
    scope: `access:${accessType}:${Number.isFinite(ops) ? ops : ""}:${throttled}:${containerIds.join(",")}:${ids.join(",")}`,
    incompleteScope: incomplete || (items.length === 0 && !sync),
  });
}

function aggregateRecord(c: Common): ExchangeChange {
  const ops = Number(str(getCI(c.rec, "OperationCount")));
  const dur = str(getCI(c.rec, "AggregateDurationInSeconds")).trim();
  const n = Number.isFinite(ops) ? ops : 0;
  return finish(c, {
    kind: "aggregate",
    verb: `${plural(n, "operation")}${dur ? ` over ${dur} s` : ""}, items not listed`,
    infinitive: "access items",
    qualifiers: [ACCESS_NOTE],
    severity: accessSeverity(c),
    scope: `aggregate:${n}:${dur}`,
    incompleteScope: true,
  });
}

const ITEM_VERBS: Record<string, [string, string]> = {
  send: ["sends", "send"],
  sendas: ["sends as", "send as"],
  sendonbehalf: ["sends on behalf of", "send on behalf of"],
  harddelete: ["hard-deletes", "hard-delete"],
  softdelete: ["soft-deletes", "soft-delete"],
  movetodeleteditems: ["moves to Deleted Items", "move to Deleted Items"],
  move: ["moves", "move"],
  copy: ["copies", "copy"],
  update: ["updates", "update"],
  create: ["creates", "create"],
  folderbind: ["opens folder", "open folder"],
  messagebind: ["opens", "open"],
};

function itemRecord(c: Common): ExchangeChange | null {
  const op = c.operation.toLowerCase();
  const verbs = ITEM_VERBS[op];
  if (!verbs) return null;
  const item = isObject(getCI(c.rec, "Item")) ? (getCI(c.rec, "Item") as Row) : null;
  const affected = (
    Array.isArray(getCI(c.rec, "AffectedItems")) ? (getCI(c.rec, "AffectedItems") as unknown[]) : []
  ).filter(isObject);
  const items = c.recordType === 3 ? affected : item ? [item] : affected;
  const folder =
    str(getCI(isObject(getCI(c.rec, "Folder")) ? (getCI(c.rec, "Folder") as Row) : {}, "Path")) ||
    str(
      getCI(
        isObject(getCI(item ?? {}, "ParentFolder")) ? (getCI(item ?? {}, "ParentFolder") as Row) : {},
        "Path",
      ),
    );
  const sending = /^send/.test(op);
  const subject = sending && item ? str(getCI(item, "Subject")) : "";
  const ids = items.map(itemIds);
  // SendAs / SendOnBehalf name the impersonated identity in their own fields; the mailbox owner
  // is the fallback, never the first choice.
  const sentAs =
    op === "sendas"
      ? str(getCI(c.rec, "SendAsUserSmtp")).trim() || c.mailbox
      : op === "sendonbehalf"
        ? str(getCI(c.rec, "SendOnBehalfOfUserSmtp")).trim() || c.mailbox
        : "";
  const sentAsId =
    op === "sendas"
      ? str(getCI(c.rec, "SendAsUserMailboxGuid")).trim()
      : op === "sendonbehalf"
        ? str(getCI(c.rec, "SendOnBehalfOfUserMailboxGuid")).trim()
        : "";
  // A move or copy names its destination (a folder, or another mailbox for a cross-mailbox
  // operation); a send names its recipients — both are evidence and both are identity.
  const destFolder = str(
    getCI(isObject(getCI(c.rec, "DestFolder")) ? (getCI(c.rec, "DestFolder") as Row) : {}, "Path"),
  );
  const destMailbox =
    str(getCI(c.rec, "DestMailboxOwnerUPN")).trim() || str(getCI(c.rec, "DestMailboxId")).trim();
  const cross = truthy(str(getCI(c.rec, "CrossMailboxOperations")));
  const dest = [
    destMailbox && (cross || destMailbox.toLowerCase() !== c.mailbox.toLowerCase())
      ? `to mailbox ${destMailbox}`
      : "",
    destFolder ? `to ${quote(destFolder, FOLDER_MAX)}` : "",
  ]
    .filter(Boolean)
    .join(" ");
  const recipients = listOf(getCI(c.rec, "recipientList"))
    .map((x) => str(getCI(x, "Address")) || str(getCI(x, "Name")))
    .filter(Boolean);
  const recipientStrings = (
    Array.isArray(getCI(c.rec, "recipientList")) ? (getCI(c.rec, "recipientList") as unknown[]) : []
  ).filter((x): x is string => typeof x === "string");
  const allRecipients = [...recipients, ...recipientStrings];
  const recipientCount = Number(str(getCI(c.rec, "recipientCount")));
  const recipientWords = allRecipients.length
    ? `to ${list(allRecipients.map((x) => withClass(x, c.ownerDomain)))}`
    : Number.isFinite(recipientCount) && recipientCount > 0
      ? `to ${plural(recipientCount, "recipient")}`
      : "";
  const verb = sending
    ? `${verbs[0]}${op === "send" ? "" : ` ${sentAs}`}${recipientWords ? ` ${recipientWords}` : ""}`
    : `${verbs[0]} ${plural(items.length, "item")}${folder ? ` from ${quote(folder, FOLDER_MAX)}` : ""}${dest ? ` ${dest}` : ""}`;
  const infinitive = sending
    ? `${verbs[1]}${op === "send" ? "" : ` ${sentAs}`}`
    : `${verbs[1]} ${plural(items.length, "item")}`;
  return finish(c, {
    kind: "item",
    verb,
    infinitive,
    words: subject ? `subject ${quote(subject, SUBJECT_MAX)}` : "",
    severity: accessSeverity(c),
    scope: `item:${op}:${sentAs}:${sentAsId}:${folder}:${destMailbox}:${destFolder}:${allRecipients.join(",")}:${recipientCount}:${ids.join(",")}`,
    // The TARGET of a send is where it went — the recipients (or their count); the identity it was
    // sent as is the subject. A move or copy targets its destination mailbox.
    target: sending
      ? allRecipients.length
        ? allRecipients.join(", ")
        : Number.isFinite(recipientCount) && recipientCount > 0
          ? `${plural(recipientCount, "recipient")} (not listed)`
          : ""
      : destMailbox,
    sentAs,
    incompleteScope: items.some((i) => itemIds(i) === "//") || items.length === 0,
  });
}

/** Decode one Exchange workload record, or null when it is not one this module narrates. */
export function decodeExchangeRecord(rec: Row, index: number): ExchangeChange | null {
  if (!/^exchange$/i.test(str(getCI(rec, "Workload")).trim())) return null;
  const c = common(rec, index);
  if (c.recordType === 1) {
    const p = pairs(getCI(rec, "Parameters"));
    return (
      ruleCmdlet(c, p) ??
      (c.operation.toLowerCase() === "set-mailbox" ? forwardingCmdlet(c, p) : null) ??
      permissionCmdlet(c, p)
    );
  }
  if (c.recordType === 50 || (c.operation.toLowerCase() === "mailitemsaccessed" && c.recordType !== 19))
    return accessRecord(c);
  if (c.recordType === 19) return aggregateRecord(c);
  if (c.recordType === 2 && c.operation.toLowerCase() === "updateinboxrules") return ruleMailboxAudit(c);
  if (c.recordType === 2 || c.recordType === 3) return itemRecord(c);
  return null;
}
