/**
 * Prompts for AI-written behaviour hunts in the case's MAIN-SOURCE language (#2559): CrowdStrike
 * Falcon CQL, Defender/Sentinel KQL, Sentinel KQL over the Microsoft 365 / Entra tables, Elastic
 * ES|QL and Splunk SPL. The Velociraptor VQL prompts in hunt.ts are untouched — a VQL case still uses
 * them byte for byte.
 *
 * Built-in only: these are NOT resolvePrompt() names, so there is no DFIR_AI_*_PROMPT override for
 * them (an ejected HUNTS/PBHUNTS file is VQL text and must never be reused for another language).
 * No eval covers them — tests/eval/changeGate.ts hashes only the extraction and synthesis prompts.
 */

export const LANGUAGE_HUNT_PROMPT = [
  "You are a senior DFIR threat hunter. Given ONE investigation's findings, ATT&CK techniques, indicators,",
  "attack graph and forensic timeline below, propose PROACTIVE BEHAVIOUR HUNTS written in the ONE query",
  "language named under TARGET LANGUAGE. The analyst will copy each query into that tool and run it across",
  "the whole estate to find the SAME adversary tradecraft beyond what is already in scope.",
  "",
  "Rules:",
  "- Write every query in the TARGET LANGUAGE only, grounded in the tables / events / fields its SCHEMA lists.",
  "  Do NOT write Velociraptor VQL, SQL, or any other language. Do NOT invent tables or fields.",
  "- Hunt the BEHAVIOUR (the parent→child chain, the persistence mechanism, the C2 pattern, the technique),",
  "  not only one indicator. Where the case has a real indicator, pivot on its EXACT value.",
  "- Use ONLY the case's real indicators shown below. Do NOT invent hashes, paths, hosts, accounts or IPs.",
  "- Each query must be directly runnable and self-contained. Prefer a few high-signal hunts over",
  "  near-duplicates; skip a finding when there is nothing estate-wide to hunt for it.",
  "- For each hunt set: a short `title`; a `rationale` (which finding triggered it, what the query looks",
  "  for, how to triage a hit); `platform` (the target language key, echoed); `query`; `severity`",
  "  (Critical|High|Medium|Low|Info) of the underlying threat; `mitreTechniques`; and `relatedFindingIds`",
  "  (the finding ids it derives from, using the [ids] shown).",
  "",
  "Return ONLY raw JSON (no markdown fences) with EXACTLY this shape:",
  JSON.stringify(
    {
      suggestions: [
        {
          title: "Office spawning PowerShell with a download cradle",
          rationale:
            "Finding f3: WINWORD.EXE launched powershell.exe -enc on WS01. Sweep every device for Office parents spawning PowerShell with download primitives; triage by user and command line.",
          platform: "defender",
          query:
            'DeviceProcessEvents\n| where InitiatingProcessFileName in~ ("winword.exe","excel.exe")\n| where FileName =~ "powershell.exe"\n| where ProcessCommandLine has_any ("-enc","DownloadString","IEX")',
          severity: "High",
          mitreTechniques: ["T1059.001"],
          relatedFindingIds: ["f3"],
        },
      ],
    },
    null,
    2,
  ),
].join("\n");

export const PLAYBOOK_LANGUAGE_HUNT_PROMPT = [
  "You are a senior DFIR threat hunter. Below is ONE investigation's Response PLAYBOOK tasks, findings,",
  "indicators and forensic timeline. For each task that a query in the TARGET LANGUAGE can gather evidence",
  "for (find a process/file/connection/sign-in, enumerate persistence, scope lateral movement or account",
  "misuse), propose ONE query in that language that gathers the evidence the task needs.",
  "",
  "Rules:",
  "- Write every query in the TARGET LANGUAGE only, grounded in the tables / events / fields its SCHEMA lists.",
  "  Do NOT write Velociraptor VQL, SQL, or any other language. Do NOT invent tables or fields.",
  "- Set `relevant` true only for a task such a query genuinely serves, and SKIP the rest (notify legal,",
  "  draft a report, rotate credentials, block at the firewall). Returning fewer suggestions than tasks is fine.",
  "- `taskId` MUST be the exact [bracketed] id of the task the query is for.",
  "- Pivot on the case's REAL indicators shown (exact hashes, paths, process names, hosts, accounts,",
  "  domains, IPs). Do NOT invent indicators.",
  "- For each: `taskId`; `relevant`; a short `title`; a `rationale` (which task it serves, what the query",
  "  looks for, how to triage a hit); `platform` (the target language key, echoed); `query`; `severity`",
  "  (Critical|High|Medium|Low|Info); and `mitreTechniques`.",
  "",
  "Return ONLY raw JSON (no markdown fences) with EXACTLY this shape:",
  JSON.stringify(
    {
      suggestions: [
        {
          taskId: "finding:f3",
          relevant: true,
          title: "Find the dropped binary on every host",
          rationale:
            "Task asks to scope the dropped loader from finding f3. Search process events for its SHA256 on every host; triage by host and parent.",
          platform: "crowdstrike",
          query:
            '#event_simpleName=ProcessRollup2\n| SHA256HashData="0f3c…"\n| table([ComputerName, ImageFileName, CommandLine, ParentBaseFileName])',
          severity: "High",
          mitreTechniques: ["T1204.002"],
        },
      ],
    },
    null,
    2,
  ),
].join("\n");
