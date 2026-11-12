// Remove-DlpCompliancePolicy, graded from its own record (#2604). Removing a data loss prevention
// policy switches off a control that watches data leaving the tenant: Medium, T1562.001. The Suzaku
// rule for it only labels (below the critical floor), and a bare grading-table entry would grade a
// WhatIf run or a failed attempt as the completed removal, and fold them into one row with it.
//
// A Security & Compliance cmdlet record (RecordType 18, Workload SecurityComplianceCenter) carries
// `Parameters` as ONE command-line string (`-Identity "x" -WhatIf`), unlike the Exchange workload's
// Name/Value pairs; both are read. The outcome follows the Exchange decoder's semantics: a failed or
// unknown result is an attempt (Medium, no technique), a WhatIf/ValidateOnly run is a dry run (Low,
// no technique) and says so on the row. The plain row's text is kept; only the grade, a short note
// and the key's outcome segment change, so a completed, a dry-run and a failed removal never fold.

import { boundedAggKey, boundedTextTo } from "./aggKey.js";
import { DRY_RUN_NOTE, isDryRun, pairs } from "./exchangeAuditValues.js";
import { getCI, oneLine, str, type MappedEvent } from "./siemImport.js";

type Row = Record<string, unknown>;

const OP = "remove-dlpcompliancepolicy";
const POLICY_SHOWN = 80;
const DESCRIPTION_MAX = 600;
// `-WhatIf`, `-WhatIf:$true`, `-ValidateOnly` — never `-WhatIf:$false`.
const DRY_SWITCH = /(?:^|\s)-(?:whatif|validateonly)(?::\s*\$?(true|false))?(?=\s|$)/gi;
// `-Identity "Finance DLP"` / `-Identity Finance` — the policy the command named.
const IDENTITY = /(?:^|\s)-Identity(?::|\s+)(?:"([^"]*)"|'([^']*)'|(\S+))/i;

function readParameters(v: unknown): { dryRun: boolean; policy: string } {
  if (Array.isArray(v)) {
    const p = pairs(v);
    return { dryRun: isDryRun(p.map), policy: p.map.get("identity") ?? "" };
  }
  const text = str(v);
  const dryRun = [...text.matchAll(DRY_SWITCH)].some((m) => (m[1] ?? "true").toLowerCase() === "true");
  const id = IDENTITY.exec(text);
  return { dryRun, policy: (id?.[1] ?? id?.[2] ?? id?.[3] ?? "").trim() };
}

function outcomeOf(rec: Row): "success" | "failure" | "unknown" {
  const r = str(getCI(rec, "ResultStatus")).trim().toLowerCase();
  if (/^(succeeded|success|true)$/.test(r)) return "success";
  if (/^(failed|failure|false)$/.test(r)) return "failure";
  return "unknown";
}

/** The plain UAL row of a Remove-DlpCompliancePolicy record, graded; any other row unchanged. */
export function gradeComplianceCmdlet(rec: Row, row: MappedEvent): MappedEvent {
  const op = str(getCI(rec, "Operation") ?? getCI(rec, "Operations")).trim();
  if (op.toLowerCase() !== OP) return row;
  const { dryRun, policy } = readParameters(getCI(rec, "Parameters"));
  const outcome = outcomeOf(rec);
  const shownPolicy = policy ? oneLine(policy).slice(0, POLICY_SHOWN) : "";
  const grade = dryRun
    ? { severity: "Low" as const, mitre: [], note: DRY_RUN_NOTE, segment: "dryrun" }
    : outcome === "success"
      ? { severity: "Medium" as const, mitre: ["T1562.001"], note: "", segment: "removed" }
      : {
          severity: "Medium" as const,
          mitre: [],
          // The plain row marks a failure [FAILED] only when ResultStatus spells "fail".
          note: outcome === "unknown" ? "result unknown" : /\[FAILED/.test(row.description) ? "" : "failed",
          segment: `attempt:${outcome}`,
        };
  const notes = [shownPolicy ? `policy "${shownPolicy}"` : "", grade.note].filter(Boolean);
  return {
    ...row,
    description: boundedTextTo(`${row.description}${notes.map((n) => ` [${n}]`).join("")}`, DESCRIPTION_MAX),
    severity: grade.severity,
    mitre: grade.mitre,
    aggKey: row.aggKey
      ? boundedAggKey(`${row.aggKey}|dlp:${grade.segment}|${policy.toLowerCase()}`)
      : row.aggKey,
  };
}
