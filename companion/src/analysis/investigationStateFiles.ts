// The state/*.json files that hold INVESTIGATION DATA — timeline, findings, IOCs, the asset graph
// state, analyst decisions (scope/legitimate/tags/comments/playbook) — as opposed to machine/
// account/transient config (AI run status, external-enrichment opt-in, anonymization config, remote
// export ids, in-flight hunts, forensic-gate display preference). Used by BackupManager to decide
// which files to snapshot before synthesis/import so a bad run can be rolled back.
export const SNAPSHOT_STATE_FILES = [
  "investigation.json",     // the core: forensic timeline, findings, IOCs, MITRE, attacker path, questions, next steps
  "false-positive.json",    // analyst false-positive / known-good markers
  "scope.json",             // analyst investigation time-window
  "comments.json",          // investigator comments on entities
  "tags.json",              // analyst triage labels
  "notebook.json",          // analyst notebook (hypotheses, notes)
  "hypotheses.json",        // #140 status-tracked investigative hypotheses (analyst + auto-generated) — investigation data
  "report-meta.json",       // human-authored report sections (title page, distribution, BIA, glossary…)
  "playbook.json",          // response playbook (tracked checklist)
  "playbook-control.json",  // per-case IR-templates toggle
  "asset-overrides.json",   // analyst edits to the asset ↔ IoC graph (graph state)
  "customer.json",          // customer-exposure targets (victim org domains/emails the analyst entered)
  "customer-exposure.json", // exposure summary (already password-stripped at write time)
  "synth-meta.json",        // when synthesis last ran + findings diff (investigation history)
  "import-meta.json",       // when the last import ran + timeline/IOC diff (investigation history)
  "hunt-outcomes.json",     // #157 per-case hunting profile (what was hunted, what hit/missed) — investigation data
  "dwell-windows.json",     // analyst-defined attacker-presence windows (label/start/end) — investigation data
  "pinned-findings.json",   // #220 analyst-pinned key findings (ordered shortlist) — analyst decision, travels with the case
] as const;
