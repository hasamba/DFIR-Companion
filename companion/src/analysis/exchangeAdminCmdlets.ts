import type { Severity } from "./stateTypes.js";
import { DRY_RUN_NOTE, falsy, isDryRun, truthy, type Pairs } from "./exchangeAuditValues.js";
import { auditConfigCmdlet, type AuditConfigOptions } from "./exchangeAuditConfig.js";

// Exchange admin cmdlets graded by the parameter that decides them (#2604). The Suzaku rules for
// these cmdlets only label (they sit below the critical floor), and several match on the cmdlet
// name alone, so a routine change and the attack read the same. The record's Parameters carry the
// value that tells them apart; this decoder is the one grading path for them:
//   - Set-MailboxAuditBypassAssociation with AuditBypassEnabled True: the account's mailbox
//     actions stop being audited — High, T1562.008 (anti-forensics, #2549 precedent). False
//     requests the bypass off: Low, no technique.
//   - Set-CASMailbox with PopEnabled or ImapEnabled True: the mailbox can be read over a legacy
//     protocol — Medium, T1114.002. The row says the protocol was enabled, never that mail was
//     collected. OWAEnabled alone, or a protocol turned off, keeps the plain row.
//   - New-RoleGroup / New-ManagementRoleAssignment naming the ApplicationImpersonation role (as a
//     list element, never a substring): whoever holds it can act as any mailbox — High, T1098.002.
//     Any other role keeps the plain row.
// A failed or unknown result is an attempt and a WhatIf/ValidateOnly run a dry run, both through
// the Exchange decoder's own row builder. Any other cmdlet falls through to the admin audit log
// configuration reader. Pure.

const IMPERSONATION = "applicationimpersonation";
const VALUE_SHOWN = 60;
const PROTOCOLS: ReadonlyArray<[string, string]> = [
  ["popenabled", "POP"],
  ["imapenabled", "IMAP"],
];

/** The options this decoder hands back to the Exchange decoder's row builder. */
export type AdminCmdletOptions = AuditConfigOptions & { words?: string; target?: string; object?: string };

interface Actor {
  operation: string;
  actorIsSystem: boolean;
}

type Reading = Omit<AdminCmdletOptions, "incompleteScope" | "kind"> & { dryRun: string };

const shown = (v: string): string => (v.length > VALUE_SHOWN ? `${v.slice(0, VALUE_SHOWN)}…` : v);
const quoted = (v: string): string => `"${shown(v)}"`;

function bypass(pp: Pairs): Reading | null {
  const value = pp.map.get("auditbypassenabled");
  if (value === undefined) return null;
  const who = pp.map.get("identity") ?? "";
  const words = who ? `for ${shown(who)}` : "";
  const scope = `auditbypass:${value.toLowerCase()}:${who.toLowerCase()}`;
  const dryRun = "simulate a mailbox audit bypass change";
  if (truthy(value))
    return {
      verb: "turns the mailbox audit bypass on (AuditBypassEnabled True)",
      infinitive: "turn the mailbox audit bypass on",
      words,
      target: who,
      severity: "High",
      mitre: ["T1562.008"],
      scope,
      polarity: "removes",
      dryRun,
    };
  if (falsy(value))
    return {
      verb: "requests the mailbox audit bypass off (AuditBypassEnabled False)",
      infinitive: "turn the mailbox audit bypass off",
      words,
      target: who,
      severity: "Low",
      scope,
      polarity: "adds",
      dryRun,
    };
  return null;
}

function casMailbox(pp: Pairs): Reading | null {
  const on = PROTOCOLS.filter(([k]) => truthy(pp.map.get(k) ?? "")).map(([, word]) => word);
  if (!on.length) return null;
  const what = on.join(" and ");
  // ObjectId is often the mailbox GUID; Identity is the mailbox as the command named it.
  const mailbox = pp.map.get("identity") ?? "";
  return {
    verb: `enables ${what} on the mailbox`,
    words: mailbox ? `for ${shown(mailbox)}` : "",
    target: mailbox,
    infinitive: `enable ${what} on the mailbox`,
    severity: "Medium",
    mitre: ["T1114.002"],
    scope: `casmailbox:${on.join(",").toLowerCase()}:${pp.digest}`,
    polarity: "adds",
    dryRun: `simulate enabling ${what} on the mailbox`,
  };
}

/** A role list (`A, B` or `A;B`) holds ApplicationImpersonation as one of its elements. */
const namesImpersonation = (v: string | undefined): boolean =>
  (v ?? "")
    .split(/[,;]/)
    .map((s) =>
      s
        .trim()
        .replace(/^["']|["']$/g, "")
        .toLowerCase(),
    )
    .includes(IMPERSONATION);

function impersonation(op: string, pp: Pairs): Reading | null {
  const base = {
    severity: "High" as Severity,
    mitre: ["T1098.002"],
    polarity: "adds" as const,
    object: "",
    dryRun: "simulate granting the ApplicationImpersonation role",
  };
  if (op === "new-rolegroup" && namesImpersonation(pp.map.get("roles"))) {
    const name = pp.map.get("name") ?? "";
    const members = pp.map.get("members") ?? "";
    const group = name ? `role group ${quoted(name)}` : "a role group";
    return {
      ...base,
      verb: `creates ${group} with the ApplicationImpersonation role`,
      infinitive: `create ${group} with the ApplicationImpersonation role`,
      words: members ? `members ${shown(members)}` : "",
      target: members,
      scope: `impersonation:rolegroup:${pp.digest}`,
    };
  }
  if (op === "new-managementroleassignment" && namesImpersonation(pp.map.get("role"))) {
    const to = pp.map.get("user") ?? pp.map.get("securitygroup") ?? pp.map.get("app") ?? "";
    const whom = to ? ` to ${quoted(to)}` : "";
    return {
      ...base,
      verb: `assigns the ApplicationImpersonation role${whom}`,
      infinitive: `assign the ApplicationImpersonation role${whom}`,
      target: to,
      scope: `impersonation:assignment:${pp.digest}`,
    };
  }
  return null;
}

function readCmdlet(op: string, pp: Pairs): Reading | null {
  if (op === "set-mailboxauditbypassassociation") return bypass(pp);
  if (op === "set-casmailbox") return casMailbox(pp);
  return impersonation(op, pp);
}

/**
 * Decode an admin cmdlet this module grades, or hand it to the admin audit log configuration
 * reader; null for any other cmdlet (the caller keeps the plain row).
 */
export function adminCmdlet<C extends Actor, R>(
  c: C,
  pp: Pairs,
  done: (c: C, o: AdminCmdletOptions) => R,
): R | null {
  const r = readCmdlet(c.operation.toLowerCase(), pp);
  if (!r) return auditConfigCmdlet(c, pp, done);
  const { dryRun, ...o } = r;
  if (isDryRun(pp.map))
    return done(c, {
      ...o,
      kind: "config",
      verb: `${dryRun.replace(/^simulate/, "simulates")}`,
      infinitive: dryRun,
      qualifiers: [DRY_RUN_NOTE],
      severity: "Low",
      mitre: [],
      scope: `${o.scope}:dryrun`,
      incompleteScope: pp.truncated,
      polarity: "simulates",
    });
  return done(c, { ...o, kind: "config", incompleteScope: pp.truncated });
}
