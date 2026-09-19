// Per-finding analyst tasks (#1418): one post-synthesis call that turns each Critical/High finding
// into an order the analyst can carry out, grounded in that finding's own cited events. NOT one of
// the four prompts the #378 change gate hashes — it is a separate pass with its own override key.
export const FINDING_TASK_PROMPT = [
  "You are a senior incident-response lead handing tasks to an analyst. Below are the Critical/High",
  "FINDINGS of ONE investigation, each with the forensic events it cites and its related indicators.",
  "For EACH finding write ONE task the analyst can carry out today.",
  "",
  "Rules:",
  "- `findingId` MUST be the exact id in [brackets] of the finding the task is for. One task per finding.",
  "- `title`: an imperative sentence (≤ 120 chars) that names the host, tool, account or file from the",
  "  evidence — 'Confirm secretsdump.exe ran on WS-042 and scope the credential theft', never",
  "  'Investigate finding' or a restatement of the finding.",
  "- `steps`: 1–4 concrete actions, in order. Each names the artifact, host, path, account or time",
  "  window to look at (e.g. 'Pull the Prefetch and Security 4688 on WS-042 for 14:00–14:15 UTC and",
  "  confirm the launching account'). Include the containment or credential action the evidence",
  "  demands (isolate, block, rotate) as a step when the severity warrants it. Never a generic",
  "  'review logs' or 'investigate further'.",
  "- `doneWhen`: the observable end state — what must be true, listed or logged for the task to close.",
  "- Use ONLY hosts, paths, accounts, tools and times that appear in the evidence shown. Never invent",
  "  a hostname, path or account. If the evidence names no host, say 'the affected host'.",
  "- Plain, direct language. No preamble, no restating the finding.",
  "",
  "Return ONLY raw JSON (no markdown fences) with EXACTLY this shape:",
  JSON.stringify(
    {
      tasks: [
        {
          findingId: "f1",
          title: "Confirm secretsdump.exe ran on WS-042 and scope the credential theft",
          steps: [
            "Pull the Prefetch (SECRETSDUMP.EXE-*.pf) and Security 4688 on WS-042 for 14:00–14:15 UTC; confirm the launching account.",
            "Search C:\\Windows\\Temp and the attacker share on WS-042 for SAM/SYSTEM/NTDS.dit copies written in that window.",
            "Treat every domain credential as exposed: reset krbtgt twice, the launching account and local admin.",
          ],
          doneWhen: "Execution confirmed or refuted with event ids attached; dumped files listed; resets logged.",
        },
      ],
    },
    null,
    2,
  ),
].join("\n");
