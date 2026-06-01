// Remove analyst/tool-usage entries (Velociraptor hunts, notebooks, searches,
// "Response and Monitoring accessed", etc.) from a case's forensic timeline.
// No AI calls. Dry-run by default — shows what WOULD be removed; pass --apply to save.
//
//   npm run clean-timeline -- <caseId>            preview what would be removed
//   npm run clean-timeline -- <caseId> --apply    actually remove them
import { config as loadDotenv } from "dotenv";
loadDotenv();

import { isAbsolute, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { CaseStore } from "../src/storage/caseStore.js";
import { StateStore } from "../src/analysis/stateStore.js";
import { partitionWorkLog } from "../src/analysis/workLogFilter.js";

async function main(): Promise<void> {
  const caseId = process.argv[2] && !process.argv[2].startsWith("--") ? process.argv[2] : "test1";
  const apply = process.argv.includes("--apply");

  const raw = process.env.DFIR_CASES_ROOT ?? "cases";
  const companionDir = fileURLToPath(new URL("../", import.meta.url));
  const casesRoot = isAbsolute(raw) ? raw : resolve(companionDir, raw);

  const store = new CaseStore(casesRoot);
  const stateStore = new StateStore(store);
  const state = await stateStore.load(caseId);

  const { keep, removed } = partitionWorkLog(state.forensicTimeline);
  console.log(`Case "${caseId}": ${state.forensicTimeline.length} forensic events → keep ${keep.length}, remove ${removed.length}.\n`);

  if (removed.length === 0) {
    console.log("Nothing matched the work-log patterns. Timeline is clean.");
    return;
  }

  console.log("WOULD REMOVE (analyst/tool-usage):");
  for (const e of removed) console.log(`  - ${e.timestamp}  ${e.description}`);

  if (!apply) {
    console.log(`\nDry run. Re-run with --apply to remove these ${removed.length} entries.`);
    return;
  }

  await stateStore.save({ ...state, forensicTimeline: keep, updatedAt: state.updatedAt });
  console.log(`\nRemoved ${removed.length} entries. Forensic timeline now has ${keep.length} real events.`);
  console.log(`Re-run conclusions to refresh findings/attacker path:  npm run synthesize -- ${caseId}`);
}

main().catch((e) => console.error("clean-timeline error:", e));
