// Backfill for cases written before ingest-time IOC value normalization (#177): lift the human
// annotation baked into an indicator ("10.10.20.15 (DC01)") out into the IOC's `note` field, and
// canonicalize the value itself. Strict consumers — MISP rejects a non-bare IP with a 403 —
// exact-match correlation, and value dedup all need `value` to be the bare indicator.
//
// Repair-only: an entry whose value can't be salvaged is reported and LEFT ALONE, never dropped.
// No AI calls. Dry-run by default — shows what WOULD change; pass --apply to save.
//
//   npm run repair-ioc-values -- <caseId>            preview the repairs
//   npm run repair-ioc-values -- <caseId> --apply    actually save them
import { config as loadDotenv } from "dotenv";
loadDotenv({ quiet: true });

import { isAbsolute, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { CaseStore } from "../src/storage/caseStore.js";
import { StateStore } from "../src/analysis/stateStore.js";
import { repairIocValues } from "../src/analysis/iocRepair.js";
import { isWellFormedIocValue } from "../src/analysis/iocValue.js";

function short(v: string, max = 70): string {
  const oneLine = v.replace(/\s+/g, " ").trim();
  return oneLine.length > max ? `${oneLine.slice(0, max)}…` : oneLine;
}

async function main(): Promise<void> {
  const caseId = process.argv[2] && !process.argv[2].startsWith("--") ? process.argv[2] : "test1";
  const apply = process.argv.includes("--apply");

  const raw = process.env.DFIR_CASES_ROOT ?? "cases";
  const companionDir = fileURLToPath(new URL("../", import.meta.url));
  const casesRoot = isAbsolute(raw) ? raw : resolve(companionDir, raw);

  const store = new CaseStore(casesRoot);
  const stateStore = new StateStore(store);
  const state = await stateStore.load(caseId);

  const { state: repaired, changed } = repairIocValues(state);
  console.log(`Case "${caseId}": ${state.iocs.length} IOC(s), ${changed.length} with a value to repair.\n`);

  for (const c of changed) {
    console.log(`  ${c.id}  ${short(c.before)}`);
    console.log(`  ${" ".repeat(c.id.length)}  -> ${short(c.after)}${c.note ? `   note: ${short(c.note, 40)}` : ""}`);
  }

  // Anything still malformed after repair is what an export (MISP push) will skip. Name it here so
  // the operator can fix or remove it deliberately rather than discovering it as a remote rejection.
  const unusable = repaired.iocs.filter((i) => !isWellFormedIocValue(i.type, i.value));
  if (unusable.length) {
    console.log(`\n${unusable.length} IOC(s) are still not valid for their type and will be SKIPPED by strict exports:`);
    for (const i of unusable) console.log(`  ${i.id}  [${i.type}]  ${short(i.value)}`);
  }

  if (changed.length === 0) {
    console.log("\nNothing to repair.");
    return;
  }
  if (!apply) {
    console.log(`\nDry run. Re-run with --apply to save these ${changed.length} repair(s).`);
    return;
  }

  await stateStore.save({ ...repaired, updatedAt: state.updatedAt });
  console.log(`\nRepaired ${changed.length} IOC value(s).`);
}

main().catch((e) => console.error("repair-ioc-values error:", e));
