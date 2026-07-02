// Remove IOC rows that share the same id — a known corruption class from concurrent imports racing
// on the same case's state (see analysis/iocRepair.ts for why this is safe to collapse without
// remapping references). No AI calls. Dry-run by default — shows what WOULD be removed; pass --apply
// to save.
//
//   npm run dedupe-iocs -- <caseId>            preview duplicate IOC rows
//   npm run dedupe-iocs -- <caseId> --apply    actually remove them
import { config as loadDotenv } from "dotenv";
loadDotenv({ quiet: true });

import { isAbsolute, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { CaseStore } from "../src/storage/caseStore.js";
import { StateStore } from "../src/analysis/stateStore.js";
import { dedupeIocsById } from "../src/analysis/iocRepair.js";

async function main(): Promise<void> {
  const caseId = process.argv[2] && !process.argv[2].startsWith("--") ? process.argv[2] : "test1";
  const apply = process.argv.includes("--apply");

  const raw = process.env.DFIR_CASES_ROOT ?? "cases";
  const companionDir = fileURLToPath(new URL("../", import.meta.url));
  const casesRoot = isAbsolute(raw) ? raw : resolve(companionDir, raw);

  const store = new CaseStore(casesRoot);
  const stateStore = new StateStore(store);
  const state = await stateStore.load(caseId);

  const { state: repaired, removed } = dedupeIocsById(state);
  console.log(`Case "${caseId}": ${state.iocs.length} IOC(s) -> ${repaired.iocs.length} after de-dup (${removed} duplicate row(s)).\n`);

  if (removed === 0) {
    console.log("No duplicate-id IOC rows found.");
    return;
  }

  if (!apply) {
    console.log(`Dry run. Re-run with --apply to remove these ${removed} duplicate row(s).`);
    return;
  }

  await stateStore.save({ ...repaired, updatedAt: state.updatedAt });
  console.log(`Removed ${removed} duplicate IOC row(s).`);
}

main().catch((e) => console.error("dedupe-iocs error:", e));
