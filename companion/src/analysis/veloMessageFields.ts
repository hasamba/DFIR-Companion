import { escapeRegExp } from "./regexEscape.js";

// High-signal labels in a RENDERED Windows event message (4688 process creation, Sysmon, service
// install, etc.). When an artifact ships the event as free text — no structured EventData to map —
// these carry the actual evidence (the LOLBIN binary + its command line), which the boilerplate
// header ("Creator Subject… Target Subject…") buries past the description cut-off. Surfacing them
// makes e.g. "Use of 32-bit LOLBINs" name the binary that ran, not just the rule. (#102)
const MSG_FIELD_LABELS = [
  "New Process Name",
  "Process Command Line",
  "CommandLine",
  "Command Line",
  "Image",
  "Application Name",
  "TargetFilename",
  "Service File Name",
  "ServiceFileName",
  "ScriptBlockText",
];
// Velociraptor renders some fields with a trailing "!S!" sentinel — strip it for readability.
function cleanFieldValue(v: string): string {
  return v
    .trim()
    .replace(/!S!\s*$/, "")
    .trim();
}
// The labels are compile-time constants, so their patterns are compiled ONCE — salientFromMessage
// runs all of MSG_FIELD_LABELS against every row's message, and re-escaping + re-constructing the
// RegExp per call cost ~1.7M throwaway compiles per capped ingest. The lazy fallback keeps any
// future dynamic label working (compiled on first use, then cached).
function labelPattern(label: string): RegExp {
  return new RegExp(`${escapeRegExp(label)}\\s*:[ \\t]*([^\\r\\n]+)`, "i");
}
const MSG_FIELD_RES = new Map<string, RegExp>(MSG_FIELD_LABELS.map((l) => [l, labelPattern(l)]));
function fieldFromMessage(msg: string, label: string): string {
  let re = MSG_FIELD_RES.get(label);
  if (!re) {
    re = labelPattern(label);
    MSG_FIELD_RES.set(label, re);
  }
  const m = re.exec(msg);
  return m ? cleanFieldValue(m[1]) : "";
}
export function salientFromMessage(msg: string): string {
  if (!msg || !msg.includes(":")) return "";
  const seen = new Set<string>();
  const out: string[] = [];
  for (const label of MSG_FIELD_LABELS) {
    const v = fieldFromMessage(msg, label);
    if (v && v !== "-" && !seen.has(v)) {
      seen.add(v);
      out.push(`${label}: ${v}`);
    }
  }
  return out.join(" - ").slice(0, 400);
}
// The created/executed process named in a rendered event message (the LOLBIN), for the structured
// processName field + IOC when the row carries no structured process column.
export function parsedNewProcess(msg: string): string {
  return fieldFromMessage(msg, "New Process Name") || fieldFromMessage(msg, "Image");
}
