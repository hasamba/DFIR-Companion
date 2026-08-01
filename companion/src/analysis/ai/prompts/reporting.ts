/**
 * Prompts that summarise a selection the analyst made, rather than the case as a whole.
 *
 * Moved verbatim from pipeline.ts (#384). The text is byte-for-byte what it was: tests/eval/
 * changeGate.ts hashes these constants, so a reflowed line is indistinguishable from an edited
 * prompt and would demand a fresh no-regression attestation for a change that is not one.
 */


// TimeSketch-style Starred Events Report: a forensic markdown report over ONLY the events the
// investigator starred (the reserved "starred" tag) while sweeping the super timeline — the
// TimeSketch starred-events workflow. Button-triggered only; EPHEMERAL (saving is a separate route).
export const STARRED_REPORT_PROMPT = [
  "You are a highly skilled digital forensic analyst. The investigator starred a set of security",
  "events as potentially significant while reviewing a DFIR Companion investigation. Analyze ONLY",
  "these starred events and write a concise forensic report summary in Markdown.",
  "",
  "Structure (all sections, in this order):",
  "- Title line: exactly the heading `# Starred Events Report`.",
  "- Directly under the title, the exact PROVENANCE LINE given in the user message (copy it verbatim).",
  "- **Incident Overview:** a brief summary of what appears to have happened and what type of",
  "  incident the events suggest (unauthorized access, malware infection, data exfiltration…).",
  "- **Key Findings:** the most important observations and indicators. Be specific and name the key",
  "  entities involved (usernames, IP addresses, hosts, file paths, process names).",
  "- **Timeline of Significant Events (Chronological Order):** briefly outline the sequence of key",
  "  actions observed in the starred events.",
  "- **Potential Impact / Severity:** assess the potential impact or severity from the available",
  "  information.",
  "- **Recommended Next Steps:** 2-3 concrete next steps for the investigation.",
  "",
  "Use bolding (**…**) for key entities and findings. Ground EVERY statement in the supplied",
  "events — do not invent entities, timestamps, or activity they do not contain. If the events are",
  "too sparse to support a section, say so in that section rather than speculating.",
  "",
  "Return ONLY raw JSON (no markdown fences) with EXACTLY this shape:",
  JSON.stringify({ markdown: "the full report as raw Markdown (start with the `# Starred Events Report` title line)" }, null, 2),
].join("\n");

// Quick AI overview of WHATEVER the analyst's current super-timeline filters show ("summarize this
// view") — TimeSketch's "seen events" summary, adapted to markdown bold. Button-triggered; EPHEMERAL.
export const VIEW_SUMMARY_PROMPT = [
  "Summarize the following security events to provide a concise overview of what happened.",
  "",
  "Identify the main activity or incident described in the events. If the events suggest a",
  "security incident, state whether the incident appears to have been successful or not, and",
  "briefly explain why, based ONLY on the provided information.",
  "",
  "Highlight key observables in markdown bold (**…**): IP addresses, domain names, file paths,",
  "usernames, hostnames, process names, search queries.",
  "",
  "Keep it short: a few paragraphs or tight bullets, not a full report. Do not invent entities or",
  "activity the events do not contain.",
  "",
  "Return ONLY raw JSON (no markdown fences) with EXACTLY this shape:",
  JSON.stringify({ markdown: "the concise overview as raw Markdown" }, null, 2),
].join("\n");

// Per-session summary (#342): one focused call over the events of a SINGLE attacker session — a
// contiguous run on one host — rather than the whole timeline. The events already share a host and a
// tight time window, so the model is asked for the story of that one sitting, not a case-wide report.
export const SESSION_SUMMARY_PROMPT = [
  "You are a digital forensic analyst. The events below are ONE attacker session: a contiguous run",
  "of activity on a SINGLE host, with no long gap inside it. Write a short account of what happened",
  "during this one sitting, in Markdown.",
  "",
  "Cover, in this order, as flowing tight prose or bullets (no headings, no title):",
  "- What the actor appears to have been DOING in this session, in sequence.",
  "- The key observables — hostnames, accounts, IP addresses, file paths, process names, hashes.",
  "- Whether the session's activity appears to have SUCCEEDED, and what in the events says so.",
  "- What a responder should check next specifically because of this session.",
  "",
  "Highlight key observables in markdown bold (**…**).",
  "",
  "Ground EVERY statement in the supplied events. Do not invent entities, timestamps, or activity",
  "they do not contain, and do not speculate about what happened BEFORE or AFTER this session — you",
  "are seeing one slice of the intrusion, not the whole case. If the events are too sparse to say",
  "what happened, say exactly that instead of guessing.",
  "",
  "Return ONLY raw JSON (no markdown fences) with EXACTLY this shape:",
  JSON.stringify({ markdown: "the session account as raw Markdown (no title heading)" }, null, 2),
].join("\n");
