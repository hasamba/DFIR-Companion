import { worstSeverity, type Severity } from "./stateTypes.js";
import { DRY_RUN_NOTE, falsy, isDryRun, truthy, type Pairs } from "./exchangeAuditValues.js";
import type { AuditConfigOptions } from "./exchangeAuditConfig.js";

// Set-Mailbox audit settings, read for what they set (#2605). A record whose only setting is the
// mailbox audit retention (AuditLogAgeLimit) or the audit switch (AuditEnabled) used to render as a
// plain "Set-Mailbox by … → <mailbox>", so neither the rules nor the AI could see the value. The
// record's Parameters carry ONLY what changed, so the setting and its value are the evidence:
//   - AuditEnabled false, or an AuditLogAgeLimit of zero (the mailbox keeps no audit records), is the
//     anti-forensics action: High, T1562.008, whoever runs it (#2549 precedent).
//   - AuditEnabled true is upkeep: Info for Exchange's own service host, Low for a person.
//   - any other age limit or audited-actions change is Medium for a person (Low for the service
//     host), no technique: the prior value is not in this record, so whether coverage shrank is not
//     established.
// The row is a "config" row, never "forwarding": the mailbox chain maps forwarding to persistence.
// A record that ALSO sets forwarding stays a forwarding row and carries the audit words. Pure.

const OP = "set-mailbox";
const AGE = "AuditLogAgeLimit";
const SWITCH = "AuditEnabled";
// The audit settings this reader names, in Microsoft's spelling. Values are bounded on display.
const SETTINGS = [AGE, SWITCH, "AuditOwner", "AuditDelegate", "AuditAdmin", "DefaultAuditSet"];
const VALUE_SHOWN = 40;
const PRIOR_NOTE = "the prior value is not in this record";
const TIMESPAN = /^(?:(\d+)\.)?(\d+):(\d+)(?::(\d+)(?:\.(\d+))?)?$/;

/** True when a .NET TimeSpan (`d.hh:mm:ss[.fff]`, `hh:mm:ss`) or a bare day count is zero. */
export function isZeroTimeSpan(v: string): boolean {
  const s = v.trim();
  if (/^\d+$/.test(s)) return Number(s) === 0;
  const m = TIMESPAN.exec(s);
  return m !== null && m.slice(1).every((x) => x === undefined || Number(x) === 0);
}

interface Actor {
  operation: string;
  actorIsSystem: boolean;
}

/** The fields of a decoded row this reader merges audit words into. */
interface MergeableRow {
  words: string;
  severity: Severity;
  mitre: string[];
  attempted: boolean;
  polarity: string;
}

interface Reading {
  clauses: string[];
  severity: Severity;
  mitre: string[];
  polarity: AuditConfigOptions["polarity"];
  prior: boolean;
}

function clauseOf(name: string, value: string): { clause: string; removes: boolean } {
  const shown = value.slice(0, VALUE_SHOWN);
  if (name === SWITCH && falsy(value))
    return { clause: "turns mailbox auditing off (AuditEnabled False)", removes: true };
  if (name === SWITCH && truthy(value)) return { clause: "turns mailbox auditing on", removes: false };
  if (name === AGE && isZeroTimeSpan(value))
    return { clause: `sets ${AGE} to ${shown} (zero: the mailbox keeps no audit records)`, removes: true };
  return { clause: `sets ${name} to ${shown}`, removes: false };
}

function readMailboxAudit(c: Actor, pp: Pairs): Reading | null {
  const found = SETTINGS.flatMap((name) => {
    const v = pp.map.get(name.toLowerCase());
    return v === undefined ? [] : [{ name, value: v, ...clauseOf(name, v) }];
  });
  if (!found.length) return null;
  const clauses = found.map((f) => f.clause);
  if (found.some((f) => f.removes))
    return { clauses, severity: "High", mitre: ["T1562.008"], polarity: "removes", prior: false };
  // Only a readable "on": an unreadable AuditEnabled value is a change of unknown effect (Medium).
  const onlyOn = found.every((f) => f.name === SWITCH && truthy(f.value));
  if (onlyOn)
    return { clauses, severity: c.actorIsSystem ? "Info" : "Low", mitre: [], polarity: "adds", prior: false };
  return { clauses, severity: c.actorIsSystem ? "Low" : "Medium", mitre: [], polarity: "none", prior: true };
}

/** The forwarding row with the audit words appended and the worse grade kept — a new object. */
function merged<R extends MergeableRow>(row: R, r: Reading): R {
  const words = [row.words, r.clauses.join("; ")].filter(Boolean).join("; ");
  if (row.attempted || row.polarity === "simulates") return { ...row, words };
  return {
    ...row,
    words,
    severity: worstSeverity(row.severity, r.severity),
    mitre: [...new Set([...row.mitre, ...r.mitre])],
  };
}

/**
 * Decode a Set-Mailbox record: forwarding through the caller's `forwarding` reader, audit settings
 * here. Audit only → a config row through `done`; both → the forwarding row carrying the audit
 * words; neither → whatever `forwarding` returns. Null for any other cmdlet.
 */
export function setMailboxCmdlet<C extends Actor, R extends MergeableRow>(
  c: C,
  pp: Pairs,
  done: (c: C, o: AuditConfigOptions) => R,
  forwarding: (c: C, pp: Pairs) => R | null,
): R | null {
  if (c.operation.toLowerCase() !== OP) return null;
  const r = readMailboxAudit(c, pp);
  if (!r) return forwarding(c, pp);
  const fwd = forwarding(c, pp);
  if (fwd && !(isDryRun(pp.map) && fwd.polarity === "simulates" && !hasForwarding(pp))) return merged(fwd, r);
  const what = r.clauses.join("; ");
  const scope = `mailboxaudit:${pp.digest}`;
  if (isDryRun(pp.map))
    return done(c, {
      kind: "config",
      verb: `simulates a mailbox audit setting change (${what})`,
      infinitive: "simulate a mailbox audit setting change",
      qualifiers: [DRY_RUN_NOTE],
      severity: "Low",
      scope: `${scope}:dryrun`,
      incompleteScope: pp.truncated,
      polarity: "simulates",
    });
  return done(c, {
    kind: "config",
    verb: what,
    infinitive: "change the mailbox audit settings",
    qualifiers: r.prior ? [PRIOR_NOTE] : [],
    severity: r.severity,
    mitre: r.mitre,
    scope,
    incompleteScope: pp.truncated,
    polarity: r.polarity,
  });
}

const hasForwarding = (pp: Pairs): boolean =>
  ["forwardingsmtpaddress", "forwardingaddress", "delivertomailboxandforward"].some((k) => pp.map.has(k));
