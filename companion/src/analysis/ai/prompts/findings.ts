/**
 * Prompts that operate on findings: tagging rules, false-positive similarity, remediation advice.
 *
 * Moved verbatim from pipeline.ts (#384). The text is byte-for-byte what it was: tests/eval/
 * changeGate.ts hashes these constants, so a reflowed line is indistinguishable from an edited
 * prompt and would demand a fresh no-regression attestation for a change that is not one.
 */


// Natural-language → ONE content-tagger rule (PR #112 follow-up). The model receives the analyst's
// description and returns a JSON object describing a single rule, or a `decline` string when the
// request can't be expressed as a single-event field-match rule. The rule is validated by
// compileRuleset before it is ever offered to save (see taggerRuleSuggest.ts).
// NOTE: declared here (not beside QUERY_TRANSLATE_PROMPT) because BUILTIN_PROMPT_BY_NAME below reads
// its value eagerly at module load — a later declaration would hit the temporal dead zone.
export const TAGGER_RULE_PROMPT = [
  "You are a DFIR detection engineer. Convert the analyst's PLAIN-ENGLISH request into ONE content-tagger",
  "rule for the DFIR-Companion event tagger. A rule matches a SINGLE forensic/timeline event by its fields",
  "and, when it matches, applies tags / MITRE techniques / a raised severity.",
  "",
  "A rule is a JSON object with:",
  "- one or more CONDITION blocks: `any` (OR — ≥1 must match), `all` (AND — every one must match),",
  "  `none` (NOT — none may match). At least one condition across any/all/none is required.",
  "- at least one ACTION: `tags` (string[]), `mitre` (ATT&CK id string[]), `severity`, `view` (string).",
  "- an optional `description` (string).",
  "",
  "Each CONDITION is `{ field, <one operator> }` where exactly ONE operator is present:",
  "- contains: string | string[]   (case-insensitive substring; a list is OR)",
  "- equals:   string | string[]   (case-insensitive exact match)",
  "- regex:    string   (optional `flags`, e.g. 'i')   (JS regex against the field)",
  "- exists:   true | false   (field present-and-non-empty / absent)",
  "",
  "MATCHABLE FIELDS (an unknown field is INVALID — use only these; the exact list is in the user message):",
  "description, message, asset, path, artifactName, processName, parentName, sha256, md5, srcIp, dstIp,",
  "veloUrl, severity, action, sources, mitreTechniques, relatedFindingIds, provenance, port, pid, count.",
  "",
  "severity is one of: Critical, High, Medium, Low, Info.",
  "",
  "IMPORTANT RULES:",
  "- Author a GENERIC rule. Do NOT hardcode this case's specific IPs, hostnames, or hashes — write a rule",
  "  that would be reusable across investigations (match on artifact/event-id/path/filename patterns).",
  "- If the request CANNOT be expressed as a single-event field-match rule — e.g. it needs counting,",
  "  time-windows, thresholds, or correlating multiple events — do NOT invent a rule. Instead return",
  "  `{ \"decline\": \"<one-sentence reason>\" }` and nothing else.",
  "- Choose a short snake_case `ruleId` describing the rule.",
  "- `explanation`: one or two sentences on exactly what the rule matches and what it does.",
  "",
  "Return ONLY raw JSON (no markdown fences) in EXACTLY one of these two shapes:",
  JSON.stringify({
    ruleId: "windows_security_log_cleared",
    explanation: "Matches events whose message shows Security event ID 1102 or 'audit log was cleared'; tags them log-cleared and defense-evasion and raises severity to High.",
    rule: {
      description: "Windows Security event log cleared (Security 1102)",
      any: [{ field: "message", contains: ["1102", "audit log was cleared"] }],
      tags: ["log-cleared", "defense-evasion"],
      mitre: ["T1070.001"],
      severity: "High",
    },
  }, null, 2),
  "OR, when it cannot be expressed as a rule:",
  JSON.stringify({ decline: "This needs counting logons within a time window, which a single-event content rule can't express." }, null, 2),
].join("\n");

// Optional AI-assisted extension of the deterministic false-positive similarity pass (#227): given
// one anchor item the analyst just marked false positive, identify other case items that look like
// the SAME recurring benign pattern.
export const FP_SIMILARITY_PROMPT = [
  "You are assisting a DFIR analyst who just marked ONE item in a case as a false positive or",
  "confirmed-benign activity (not a real threat). Given that anchor item and a list of OTHER",
  "findings/events from the SAME case, identify any of the other items that look like the SAME",
  "recurring pattern (same tool, same benign activity, same root cause) and would likely ALSO be",
  "a false positive for the same reason.",
  "",
  "Only return items from the provided list, referenced by their EXACT id as given. Never invent an",
  "id. Never include the anchor item. If nothing else matches, return an empty array.",
  "",
  'Respond as JSON: { "candidateIds": ["<id>", ...] }',
].join("\n");

// Incident-specific remediation plan (#178) — turn the case's findings + ATT&CK mitigations into a
// concrete, prioritized action list the IR team can actually execute, specific to THIS incident.
export const REMEDIATION_PROMPT = [
  "You are a senior incident-response consultant writing a REMEDIATION PLAN for ONE security incident.",
  "Using ONLY the case evidence below (findings, ATT&CK techniques, the MITRE ATT&CK mitigations and the",
  "MITRE D3FEND countermeasures recommended for those techniques), write a concrete, prioritized plan the",
  "IR team can execute NOW.",
  "",
  "Rules:",
  "- Be SPECIFIC TO THIS INCIDENT: reference the actual hosts, accounts, CVEs, IOCs, and tools named in",
  "  the findings/timeline (e.g. 'reset krbtgt twice — DC01 was compromised', not 'rotate credentials').",
  "- Ground each action in the supplied ATT&CK mitigations; turn their generic guidance into a concrete",
  "  step for this environment. Do NOT invent facts the evidence doesn't support.",
  "- Organize by phase, in this order: ## Contain now, ## Eradicate, ## Harden (prevent recurrence),",
  "  ## Recover, ## Verify. Under each, a numbered list of specific actions.",
  "- For each action, end with the technique/finding it addresses in parentheses, and CITE the relevant",
  "  framework references: the ATT&CK mitigation M-code AND, where one fits, the relevant D3FEND",
  "  countermeasure name — e.g. '(T1003.001 — Mimikatz on DC01; ATT&CK M1043, D3FEND Local Account Monitoring)'.",
  "  Only cite a D3FEND countermeasure that appears in the supplied list; omit it if none fits.",
  "- Lead with the most urgent containment. Keep it actionable and tight — no filler, no restating the incident.",
  "",
  "Return ONLY raw JSON (no markdown fences) with EXACTLY this shape:",
  JSON.stringify({ plan: "the remediation plan as GitHub-flavored markdown (## headings + numbered lists)" }, null, 2),
].join("\n");
