// Push a case to Timesketch from the command line. Log in, find-or-create the sketch by name
// (= the Companion case id), then upload the forensic timeline as a Timesketch timeline (the
// managed timeline is clean-replaced so re-pushes never duplicate events). Reads DFIR_TIMESKETCH_*
// from .env. The timeline matches the report / "Export Timesketch JSONL" (scope + legitimate filters).
//
//   npm run timesketch:push -- <caseId>
import { config as loadDotenv } from "dotenv";
loadDotenv();

import { isAbsolute, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { CaseStore } from "../src/storage/caseStore.js";
import { StateStore } from "../src/analysis/stateStore.js";
import { ScopeStore } from "../src/analysis/scope.js";
import { LegitimateStore } from "../src/analysis/legitimate.js";
import { ReportMetaStore } from "../src/reports/reportMeta.js";
import { ReportWriter } from "../src/reports/reportWriter.js";
import { pushCaseToTimesketch } from "../src/integrations/timesketch/timesketchPush.js";
import { buildTimesketchClient, timesketchPushOptions } from "../src/server.js";

async function main(): Promise<void> {
  const caseId = process.argv[2] && !process.argv[2].startsWith("--") ? process.argv[2] : undefined;
  if (!caseId) {
    console.error("usage: npm run timesketch:push -- <caseId>");
    process.exit(2);
  }

  const client = buildTimesketchClient();
  if (!client) {
    console.error("Timesketch not configured. Set DFIR_TIMESKETCH_URL, DFIR_TIMESKETCH_USER and DFIR_TIMESKETCH_PASSWORD in companion/.env.");
    process.exit(1);
  }

  const raw = process.env.DFIR_CASES_ROOT ?? "cases";
  const companionDir = fileURLToPath(new URL("../", import.meta.url));
  const casesRoot = isAbsolute(raw) ? raw : resolve(companionDir, raw);
  const store = new CaseStore(casesRoot);
  const stateStore = new StateStore(store);
  // Build a ReportWriter so the pushed timeline matches the report (same scope/legitimate filters).
  const reportWriter = new ReportWriter(store, stateStore, new ScopeStore(store), new LegitimateStore(store), new ReportMetaStore(store));
  const state = await reportWriter.filteredState(caseId);

  console.log(`Pushing "${caseId}" to ${process.env.DFIR_TIMESKETCH_URL} …`);
  const res = await pushCaseToTimesketch(client, { sketchName: caseId, state }, timesketchPushOptions());

  console.log(`\nTimesketch sketch #${res.sketchId} ${res.created ? "CREATED" : "UPDATED"} ("${res.sketchName}")`);
  console.log(`  timeline: "${res.timelineName}"  events: ${res.events}${res.replacedTimeline ? "  (replaced existing)" : ""}`);
  if (res.sketchUrl) console.log(`  open:     ${res.sketchUrl}`);
  if (res.warnings.length) {
    console.log(`\n  ${res.warnings.length} warning(s):`);
    for (const w of res.warnings.slice(0, 20)) console.log(`   - ${w}`);
    if (res.warnings.length > 20) console.log(`   … and ${res.warnings.length - 20} more`);
  }
}

main().catch((e) => { console.error("timesketch push error:", (e as Error).message); process.exit(1); });
