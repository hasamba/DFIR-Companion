import type { Severity } from "./stateTypes.js";
import { DRY_RUN_NOTE, falsy, isDryRun, truthy, type Pairs } from "./exchangeAuditValues.js";

// Set-AdminAuditLogConfig, read for what it set (#2549). The record's Parameters carry ONLY what
// changed, so the setting and its value are the evidence: turning admin audit logging or unified
// audit ingestion OFF is the anti-forensics action (High, T1562.008) whoever runs it. Turning it ON
// is upkeep when Exchange's own service host does it (Info — every tenant's log is full of these)
// and Low when a person does. Any other change of the audit configuration (the age limit, the
// audited or excluded cmdlets, no parameters recorded) by a person is Medium with no technique:
// the setting changed and its effect on coverage is not in this record. The tags.yaml rule for this
// cmdlet is tag-only; this decoder is the one grading path.

const OP = "set-adminauditlogconfig";
const SWITCHES = ["AdminAuditLogEnabled", "UnifiedAuditLogIngestionEnabled"];
// The cmdlet's documented setting names, to show a lowercased parameter in Microsoft's spelling.
const SETTINGS = [
  ...SWITCHES,
  "AdminAuditLogAgeLimit",
  "AdminAuditLogCmdlets",
  "AdminAuditLogExcludedCmdlets",
  "AdminAuditLogParameters",
  "LogLevel",
];
// Parameters that name or route the command and change no setting.
const HOUSEKEEPING = new Set([
  "identity",
  "domaincontroller",
  "ignoredehydratedflag",
  "confirm",
  "force",
  "whatif",
  "validateonly",
  "erroraction",
  "warningaction",
]);
const VALUE_SHOWN = 40;

/** The options this decoder hands back to the Exchange decoder's row builder. */
export interface AuditConfigOptions {
  kind: "config";
  verb: string;
  infinitive: string;
  qualifiers?: string[];
  severity: Severity;
  mitre?: string[];
  scope: string;
  incompleteScope: boolean;
  polarity: "adds" | "removes" | "simulates" | "none";
}

interface Actor {
  operation: string;
  actorIsSystem: boolean;
}

function readSettings(pp: Pairs): { off: string[]; on: string[]; other: string[] } {
  const named = (k: string): string => SETTINGS.find((s) => s.toLowerCase() === k) ?? k;
  const off: string[] = [];
  const on: string[] = [];
  const other: string[] = [];
  for (const [k, v] of pp.map) {
    if (HOUSEKEEPING.has(k)) continue;
    const isSwitch = SWITCHES.some((s) => s.toLowerCase() === k);
    if (isSwitch && falsy(v)) off.push(named(k));
    else if (isSwitch && truthy(v)) on.push(named(k));
    else other.push(`${named(k)}=${v.slice(0, VALUE_SHOWN)}`);
  }
  return { off, on, other };
}

function grade(c: Actor, s: ReturnType<typeof readSettings>): Omit<AuditConfigOptions, "scope" | "kind"> {
  if (s.off.length) {
    const what = `${s.off.join(", ")} off`;
    return {
      verb: `turns ${what}`,
      infinitive: `turn ${what}`,
      severity: "High",
      mitre: ["T1562.008"],
      incompleteScope: false,
      polarity: "removes",
    };
  }
  if (s.on.length && !s.other.length) {
    const what = `${s.on.join(", ")} on`;
    return {
      verb: `turns ${what}`,
      infinitive: `turn ${what}`,
      severity: c.actorIsSystem ? "Info" : "Low",
      incompleteScope: false,
      polarity: "adds",
    };
  }
  const changed = [...s.on.map((x) => `${x} on`), ...s.other];
  const words = changed.length ? changed.join(", ") : "no setting recorded";
  return {
    verb: `changes the admin audit log configuration (${words})`,
    infinitive: "change the admin audit log configuration",
    severity: c.actorIsSystem ? "Low" : "Medium",
    incompleteScope: !changed.length,
    polarity: "none",
  };
}

/**
 * Decode a Set-AdminAuditLogConfig record into a row through the caller's builder `done`, or null
 * for any other cmdlet. Pure: reads only the operation, the actor class and the parameters.
 */
export function auditConfigCmdlet<C extends Actor, R>(
  c: C,
  pp: Pairs,
  done: (c: C, o: AuditConfigOptions) => R,
): R | null {
  if (c.operation.toLowerCase() !== OP) return null;
  const s = readSettings(pp);
  const scope = `config:${[...s.off, "|", ...s.on, "|", ...s.other].join(",")}`;
  if (isDryRun(pp.map))
    return done(c, {
      kind: "config",
      verb: "simulates an admin audit log configuration change",
      infinitive: "simulate an admin audit log configuration change",
      qualifiers: [DRY_RUN_NOTE],
      severity: "Low",
      scope: `${scope}:dryrun`,
      incompleteScope: pp.truncated,
      polarity: "simulates",
    });
  const g = grade(c, s);
  return done(c, { kind: "config", ...g, scope, incompleteScope: g.incompleteScope || pp.truncated });
}
