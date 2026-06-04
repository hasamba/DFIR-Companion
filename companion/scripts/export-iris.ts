// Export a case to DFIR-IRIS from the command line. Find-or-create the IRIS case by name
// (= the Companion case id), then push assets→assets, IOCs→IOCs, forensic timeline→timeline,
// executive summary→case summary, and every other section→notes. Reads DFIR_IRIS_* from .env.
//
//   npm run iris:export -- <caseId>
import { config as loadDotenv } from "dotenv";
loadDotenv();

import { isAbsolute, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { CaseStore } from "../src/storage/caseStore.js";
import { StateStore } from "../src/analysis/stateStore.js";
import { ReportMetaStore } from "../src/reports/reportMeta.js";
import { exportCaseToIris } from "../src/integrations/iris/irisExport.js";
import { buildIrisClient, irisExportOptions } from "../src/server.js";

async function main(): Promise<void> {
  const caseId = process.argv[2] && !process.argv[2].startsWith("--") ? process.argv[2] : undefined;
  if (!caseId) {
    console.error("usage: npm run iris:export -- <caseId>");
    process.exit(2);
  }

  const client = buildIrisClient();
  if (!client) {
    console.error("DFIR-IRIS not configured. Set DFIR_IRIS_URL and DFIR_IRIS_KEY in companion/.env.");
    process.exit(1);
  }

  const raw = process.env.DFIR_CASES_ROOT ?? "cases";
  const companionDir = fileURLToPath(new URL("../", import.meta.url));
  const casesRoot = isAbsolute(raw) ? raw : resolve(companionDir, raw);
  const store = new CaseStore(casesRoot);
  const stateStore = new StateStore(store);
  const reportMetaStore = new ReportMetaStore(store);

  const state = await stateStore.load(caseId);
  const meta = await reportMetaStore.load(caseId);

  console.log(`Exporting "${caseId}" to ${process.env.DFIR_IRIS_URL} …`);
  const res = await exportCaseToIris(client, { caseName: caseId, state, meta }, irisExportOptions());

  console.log(`\nIRIS case #${res.caseId} ${res.created ? "CREATED" : "UPDATED"} ("${res.caseName}")`);
  console.log(`  assets:   +${res.assets.added}  (${res.assets.existing} existing, ${res.assets.skipped} skipped)`);
  console.log(`  iocs:     +${res.iocs.added}  (${res.iocs.existing} existing, ${res.iocs.skipped} skipped)`);
  console.log(`  timeline: +${res.timeline.added}  (${res.timeline.existing} existing, ${res.timeline.skipped} skipped)`);
  console.log(`  notes:    ${res.notes}   summary: ${res.summaryUpdated ? "updated" : "not set"}`);
  if (res.caseUrl) console.log(`  open:     ${res.caseUrl}`);
  if (res.warnings.length) {
    console.log(`\n  ${res.warnings.length} warning(s):`);
    for (const w of res.warnings.slice(0, 20)) console.log(`   - ${w}`);
    if (res.warnings.length > 20) console.log(`   … and ${res.warnings.length - 20} more`);
  }
}

main().catch((e) => { console.error("iris export error:", (e as Error).message); process.exit(1); });
