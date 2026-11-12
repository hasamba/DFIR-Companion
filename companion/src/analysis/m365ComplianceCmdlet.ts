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
const DRY_SWITCHES = new Set(["whatif", "validateonly"]);
// A parameter NAME token: `-WhatIf`, `-WhatIf:$false`, `-Identity:x` — only ever an unquoted token.
const PARAM = /^-([A-Za-z][A-Za-z0-9]*)(?::(.*))?$/s;

interface Token {
  text: string;
  /** True when any part of the token came from a quoted span or an escape: a value, never a name. */
  quoted: boolean;
}

/**
 * Split a PowerShell-style command line into tokens, honouring single quotes (literal), double
 * quotes and the backtick escape, so a quoted value such as `"Finance -WhatIf Policy"` stays one
 * value token and is never read as a switch (#2604 review: the policy name is attacker-chosen).
 */
export function tokenizeParameters(text: string): Token[] {
  const out: Token[] = [];
  let cur = "";
  let quoted = false;
  let open = false;
  let quote: '"' | "'" | "" = "";
  const flush = (): void => {
    if (open) out.push({ text: cur, quoted });
    cur = "";
    quoted = false;
    open = false;
  };
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (quote === "'") {
      if (ch === "'" && text[i + 1] === "'") {
        cur += "'";
        i++;
      } else if (ch === "'") quote = "";
      else cur += ch;
    } else if (ch === "`" && i + 1 < text.length) {
      cur += text[++i];
      quoted = true;
      open = true;
    } else if (quote === '"') {
      if (ch === '"') quote = "";
      else cur += ch;
    } else if (ch === '"' || ch === "'") {
      quote = ch;
      quoted = true;
      open = true;
    } else if (/\s/.test(ch)) flush();
    else {
      cur += ch;
      open = true;
    }
  }
  flush();
  return out;
}

const truthyArg = (v: string): boolean => /^\$?true$/i.test(v.trim());

function readStringParameters(text: string): { dryRun: boolean; policy: string } {
  const tokens = tokenizeParameters(text);
  let dryRun = false;
  let policy = "";
  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i];
    const m = t.quoted ? null : PARAM.exec(t.text);
    if (!m) continue;
    const name = m[1].toLowerCase();
    // `-Name:value`, `-Name: value` (the value is the next token), or a bare `-Name`.
    const inline = m[2];
    const valueToken = inline === "" ? tokens[i + 1] : undefined;
    if (DRY_SWITCHES.has(name)) {
      const arg = inline === undefined ? "true" : inline === "" ? (valueToken?.text ?? "true") : inline;
      if (truthyArg(arg)) dryRun = true;
      if (valueToken) i++;
    } else if (name === "identity" && !policy) {
      const next = inline ? undefined : (valueToken ?? tokens[i + 1]);
      if (inline) policy = inline;
      else if (next && (next.quoted || !PARAM.test(next.text))) {
        policy = next.text;
        i++;
      }
    }
  }
  return { dryRun, policy: policy.trim() };
}

function readParameters(v: unknown): { dryRun: boolean; policy: string } {
  if (Array.isArray(v)) {
    const p = pairs(v);
    return { dryRun: isDryRun(p.map), policy: p.map.get("identity") ?? "" };
  }
  return readStringParameters(str(v));
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
