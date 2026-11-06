// The content tagger's severity rules, applied to a streamed batch BEFORE the output budget decides
// what is aggregated (#2303). The whole-file import keeps every row it maps until the settle seam,
// where the tagger gets its one chance to raise high-value telemetry out of Info before the demote
// (CLAUDE.md §7: merge → tag → demote). A streamed import aggregates Info and writes it to the
// super-timeline batch by batch, so a row the tagger would have raised must be raised here first —
// otherwise it would be folded into a count, or sent past the forensic timeline, before any rule
// saw it. That is "gating Info at merge time" by another route; this module is what prevents it.
//
// Only the rules that set a severity can change routing, and only when they would raise the row;
// tags and MITRE on the rows that reach the forensic timeline are still written by the settle
// tagger, exactly as for any other import. Raise-only, union-only: applyToForensicEvent's rules.

import type { CompiledRuleset } from "./taggerRules.js";
import { matchEvent } from "./taggerRules.js";
import { raiseSeverity } from "./tagger.js";
import { SEVERITY_RANK, type ForensicEvent, type Severity } from "./stateTypes.js";
import type { MappedEvent } from "./siemImport.js";
import { keepsVendorGrade } from "./vendorGrade.js";

export interface PreGrader {
  /** Graded copies of the rows (a raised row is a new object), and how many a rule raised. */
  grade(rows: readonly MappedEvent[]): { rows: MappedEvent[]; raised: number };
}

/** The row as the tagger reads it — the ForensicEvent fields a rule can match. */
function asEvent(m: MappedEvent): ForensicEvent {
  return {
    id: "pre-grade",
    timestamp: m.timestamp,
    description: m.description,
    severity: m.severity,
    mitreTechniques: m.mitre,
    relatedFindingIds: [],
    sourceScreenshots: [],
    ...(m.message ? { message: m.message } : {}),
    ...(m.asset ? { asset: m.asset } : {}),
    ...(m.path ? { path: m.path } : {}),
    ...(m.artifactName ? { artifactName: m.artifactName } : {}),
    ...(m.processName ? { processName: m.processName } : {}),
    ...(m.parentName ? { parentName: m.parentName } : {}),
    ...(m.commandLine ? { commandLine: m.commandLine } : {}),
    ...(m.sha256 ? { sha256: m.sha256 } : {}),
    ...(m.md5 ? { md5: m.md5 } : {}),
    ...(m.srcIp ? { srcIp: m.srcIp } : {}),
    ...(m.dstIp ? { dstIp: m.dstIp } : {}),
    ...(m.sources ? { sources: m.sources } : {}),
    ...(m.port !== undefined ? { port: m.port } : {}),
    ...(m.pid !== undefined ? { pid: m.pid } : {}),
  };
}

/**
 * A grader over `ruleset`'s severity rules; null ruleset (tagger off, scope "super", no rules)
 * grades nothing, which is what the settle tagger would do to the forensic timeline in that case.
 */
export function createPreGrader(ruleset: CompiledRuleset | null): PreGrader {
  const rules = (ruleset?.rules ?? []).filter((r) => r.severity && r.severity !== "Info");
  return {
    grade(rows) {
      if (!rules.length) return { rows: [...rows], raised: 0 };
      let raised = 0;
      const out = rows.map((m) => {
        if (m.severity === "Critical" || keepsVendorGrade(m)) return m;
        const event = asEvent(m);
        let severity: Severity = m.severity;
        const mitre = [...m.mitre];
        for (const rule of rules) {
          if (SEVERITY_RANK[rule.severity!] >= SEVERITY_RANK[severity]) continue;
          if (!matchEvent(event, rule)) continue;
          severity = raiseSeverity(severity, rule.severity);
          for (const t of rule.mitre) if (!mitre.includes(t)) mitre.push(t);
        }
        if (severity === m.severity) return m;
        raised++;
        return { ...m, severity, mitre };
      });
      return { rows: out, raised };
    },
  };
}
