// Samples built from bundled cloud Sigma rules' selections for the detection-overlap check (#2348).
//
// A FILTER, not a compiler: it handles a condition of `ref`, `and` (its `not` operands are left
// unsatisfied by the plain base record), `or` / `1 of` (the first operand), `all of`; map
// selections and the first alternative of a list selection; and the modifiers contains, startswith,
// endswith and all. Anything else — keywords, `re`, `cidr`, numeric comparisons, a bare negation —
// makes the rule "not checked" with the reason. A built sample is only a candidate: the check
// counts it only after the real importer, run with the bundled rules, reports that rule matched.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { bundledSigmaDir } from "../../../../src/analysis/sigmaBundledRules.js";
import {
  bundledSuzakuDir,
  SUZAKU_NAME,
  SUZAKU_PATH_PREFIX,
} from "../../../../src/analysis/sigmaSuzakuRules.js";
import {
  AWS_CLOUDTRAIL,
  AZURE_ACTIVITY,
  AZURE_AUDIT_LOGS,
  AZURE_M365,
  AZURE_SIGNIN_LOGS,
  GCP_AUDIT,
  GWS_SIGMA_APPS,
  gwsSourceFor,
  fieldResolvers,
  type SigmaLogSourceDef,
} from "../../../../src/analysis/sigmaLogSources.js";
import { parseSigmaRule } from "../../../../src/analysis/sigmaRule.js";
import type { SigmaRuleSet } from "../../../../src/analysis/sigmaRuleSet.js";
import type { SigmaCondition, SigmaFieldMatch, SigmaRule } from "../../../../src/analysis/sigmaRuleTypes.js";
import { cloudTrailBase } from "./aws.js";
import { auditBase, azureActivityBase, signInBase, ualBase } from "./m365.js";
import { gcpBase } from "./gcp.js";
import { gwsBase, gwsParam } from "./gws.js";
import type { DetectionSample } from "./types.js";

type Row = Record<string, unknown>;

/** The cloud log sources in scope, with the importer and base record each one's samples use. */
export const CLOUD_SIGMA_SOURCES: Record<
  string,
  {
    def: SigmaLogSourceDef;
    base: () => Row;
    kind: DetectionSample["kind"];
    notBuilt?: string;
    /** Writes a field the generic path writer cannot place (a Workspace event's name or parameter). */
    write?: (rec: Row, field: string, value: string) => Row;
  }
> = {
  // A neutral read call: the importer needs an event name, and a rule that names one overwrites it.
  "aws-cloudtrail": {
    def: AWS_CLOUDTRAIL,
    base: () =>
      cloudTrailBase({ eventSource: "ec2.amazonaws.com", eventName: "DescribeInstances", readOnly: true }),
    kind: "cloudtrail",
  },
  "azure-signinlogs": { def: AZURE_SIGNIN_LOGS, base: () => signInBase(), kind: "m365" },
  "azure-auditlogs": { def: AZURE_AUDIT_LOGS, base: () => auditBase(), kind: "m365" },
  // #2500: a UAL record (AuditData already merged) and an Azure Activity REST event.
  "azure-m365": { def: AZURE_M365, base: () => ualBase(), kind: "m365" },
  "azure-activitylogs": { def: AZURE_ACTIVITY, base: () => azureActivityBase(), kind: "azure" },
  // Not built (#2346): a sample built from a GCP rule carries the rule's own spelling of the method
  // (`.serviceAccounts.disable`), which hid that real records never matched. The rules are checked
  // with real-shaped hand samples (gcp.ts SIGMA_REAL_SAMPLES) instead.
  "gcp-audit": {
    def: GCP_AUDIT,
    base: () => gcpBase(),
    kind: "gcp",
    notBuilt: "GCP rules are checked with real-shaped hand samples, not rule-shaped built ones",
  },
  // #2522: one source per Workspace application, each built on a neutral event of that application.
  ...Object.fromEntries(
    GWS_SIGMA_APPS.map((app) => [
      `gws-${app}`,
      { def: gwsSourceFor(app)!, base: () => gwsBase(app), kind: "gws" as const, write: gwsWrite(app) },
    ]),
  ),
};

/**
 * A Workspace field written where the Reports API carries it (#2522): the event name on the one
 * event, the service only when it is the sample application's own, a bare name as a parameter.
 * Anything else (id / actor paths) takes the generic path writer.
 */
function gwsWrite(app: string): (rec: Row, field: string, value: string) => Row {
  return (rec, field, value) => {
    const f = field.toLowerCase();
    const events = (rec.events as Row[]) ?? [];
    const event = { ...(events[0] ?? {}) };
    if (f === "eventname" || f === "protopayload.metadata.event.eventname")
      return { ...rec, events: [{ ...event, name: value }] };
    if (f === "eventservice" || f === "protopayload.servicename") {
      if (value.toLowerCase() === `${app}.googleapis.com`) return rec;
      throw new NotBuildable(`field ${field} names ${value}, not this application's service`);
    }
    if (!/^[A-Za-z0-9_]+$/.test(field)) throw new GenericPath();
    const params = ((event.parameters as Row[]) ?? []).filter(
      (p) => String(p.name).toLowerCase() !== field.toLowerCase(),
    );
    return { ...rec, events: [{ ...event, parameters: [...params, gwsParam(field, value)] }] };
  };
}

/** Thrown by a source's writer to hand a field back to the generic path writer. */
class GenericPath extends Error {}

export interface SigmaBuild {
  ruleId: string;
  title: string;
  source: string;
  sample?: DetectionSample;
  /** Why no sample could be built. */
  notBuilt?: string;
}

class NotBuildable extends Error {}

/** The selection names that, all true, satisfy the condition. */
function positives(c: SigmaCondition): string[] {
  switch (c.kind) {
    case "ref":
      return [c.name];
    case "allOf":
      return [...c.names];
    case "oneOf":
      if (!c.names.length) throw new NotBuildable("a '1 of' pattern names no selection");
      return [c.names[0]];
    case "or":
      return positives(c.operands[0]);
    case "and": {
      const pos = c.operands.filter((o) => o.kind !== "not").flatMap(positives);
      if (!pos.length) throw new NotBuildable("the condition has no positive selection");
      return pos;
    }
    case "not":
      throw new NotBuildable("the condition is only a negation");
  }
}

const PLAIN_MODIFIERS = new Set(["contains", "startswith", "endswith", "all"]);

function valueFor(f: SigmaFieldMatch): string | undefined {
  if (f.nullValue) return undefined;
  // `exists: true` (#2499) needs any value; `exists: false` needs the key left out.
  if (f.exists !== undefined) return f.exists ? "SampleValue" : undefined;
  const odd = f.modifiers.find((m) => !PLAIN_MODIFIERS.has(m));
  if (odd) throw new NotBuildable(`field ${f.field} uses the '${odd}' modifier`);
  if (!f.values.length) throw new NotBuildable(`field ${f.field} has no value`);
  const values = f.modifiers.includes("all") ? f.values.map(String) : [String(f.values[0])];
  // A plain Sigma value may carry wildcards; a literal stand-in satisfies them.
  return values.map((v) => v.replace(/\*/g, "").replace(/\?/g, "x")).join(" ");
}

/** Set a dotted path on a record, reusing existing keys case-insensitively. Returns a new record. */
function setPath(rec: Row, path: string[], value: unknown): Row {
  const [head, ...rest] = path;
  const key = Object.keys(rec).find((k) => k.toLowerCase() === head.toLowerCase()) ?? head;
  if (!rest.length) return { ...rec, [key]: value };
  const child = rec[key];
  const next = child && typeof child === "object" && !Array.isArray(child) ? (child as Row) : {};
  return { ...rec, [key]: setPath(next, rest, value) };
}

/** The value for a path, joined with what THIS build already wrote there (never the base's). */
function written(done: Map<string, string>, path: string, value: string): string {
  const prev = done.get(path.toLowerCase());
  // Two fields landing on one path (e.g. two `contains`) are both kept in one string.
  const next = prev !== undefined && prev !== value ? `${prev} ${value}` : value;
  done.set(path.toLowerCase(), next);
  return next;
}

/** Sign-in fields Sigma derives from the record rather than reading a path. */
function derived(field: string, value: string): Array<[string, unknown]> {
  const f = field.toLowerCase();
  if (f === "status") return [["status", { errorCode: value.toLowerCase() === "success" ? 0 : 50126 }]];
  if (f === "location") return [["location.countryOrRegion", value]];
  throw new NotBuildable(`field ${field} is derived and has no stand-in`);
}

function apply(
  rec: Row,
  def: SigmaLogSourceDef,
  f: SigmaFieldMatch,
  done: Map<string, string>,
  write?: (rec: Row, field: string, value: string) => Row,
): Row {
  const value = valueFor(f);
  if (value === undefined) return rec;
  const resolvers = fieldResolvers(def, f.field);
  if (!Array.isArray(resolvers)) throw new NotBuildable(resolvers.refused);
  if (write) {
    try {
      return write(rec, f.field, value);
    } catch (err) {
      if (!(err instanceof GenericPath)) throw err;
    }
  }
  const path = resolvers.find((r): r is string => typeof r === "string");
  const writes: Array<[string, unknown]> = path
    ? [[path, written(done, path, value)]]
    : derived(f.field, value);
  return writes.reduce((acc, [p, v]) => setPath(acc, p.split("."), v), rec);
}

function build(rule: SigmaRule, source: string): Row {
  const { def, base, notBuilt, write } = CLOUD_SIGMA_SOURCES[source];
  if (notBuilt) throw new NotBuildable(notBuilt);
  const names = positives(rule.detection.condition);
  let rec = base();
  const done = new Map<string, string>();
  for (const name of names) {
    const sel = rule.detection.selections.find((s) => s.name === name);
    if (!sel) throw new NotBuildable(`selection ${name} is not defined`);
    if (sel.kind === "keywords") throw new NotBuildable(`selection ${name} is a keyword list`);
    const fields = sel.kind === "map" ? sel.fields : (sel.alternatives[0] ?? []);
    for (const f of fields) rec = apply(rec, def, f, done, write);
  }
  return rec;
}

/** One build per LOADED rule of an in-scope cloud source (the rules import grading can run). */
export function buildCloudSigmaSamples(set: SigmaRuleSet): SigmaBuild[] {
  const dir = bundledSigmaDir();
  if (!dir) throw new Error("the bundled Sigma rules folder (data/sigma) is missing");
  const suzakuDir = bundledSuzakuDir();
  // A Suzaku rule's path is the upstream repo's (suzaku/…); its file sits under data/sigma-suzaku/rules.
  const fileOf = (e: { path: string; origin?: string }): string =>
    e.origin === SUZAKU_NAME && suzakuDir
      ? join(suzakuDir, "rules", e.path.slice(SUZAKU_PATH_PREFIX.length))
      : join(dir, e.path);
  return set.inventory
    .filter((e) => e.outcome === "loaded" && e.source && e.source in CLOUD_SIGMA_SOURCES)
    .map((e): SigmaBuild => {
      const source = e.source as string;
      const head = { ruleId: e.id, title: e.title, source };
      const parsed = parseSigmaRule(readFileSync(fileOf(e), "utf8"), { allowNull: true });
      if (!parsed.ok) return { ...head, notBuilt: "the rule did not parse here" };
      try {
        const record = build(parsed.rule, source);
        const kind = CLOUD_SIGMA_SOURCES[source].kind;
        return {
          ...head,
          sample: { id: `sigma.${e.id}`, kind, from: `built from Sigma: ${e.title}`, record },
        };
      } catch (err) {
        if (err instanceof NotBuildable) return { ...head, notBuilt: err.message };
        throw err;
      }
    });
}
