// Push a case to DFIR-IRIS from the command line. Find-or-create the IRIS case by name
// (the last-used name for this Companion case, or "<case id> — <friendly name>" on the
// first push), then push assets→assets, IOCs→IOCs, forensic timeline→timeline, executive
// summary→case summary, and every other section→notes. Reads DFIR_IRIS_* from .env.
//
//   npm run iris:push -- <caseId> [--name "custom IRIS case name"]
import { config as loadDotenv } from "dotenv";
loadDotenv({ quiet: true });

import { isAbsolute, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { CaseStore } from "../src/storage/caseStore.js";
import { StateStore } from "../src/analysis/stateStore.js";
import { ReportMetaStore } from "../src/reports/reportMeta.js";
import { PlaybookStore } from "../src/analysis/playbookStore.js";
import { PlaybookControlStore } from "../src/analysis/playbookControl.js";
import { pushCaseToIris } from "../src/integrations/iris/irisPush.js";
import { IrisExportStore, defaultIrisCaseName } from "../src/integrations/iris/irisExportStore.js";
import { buildIrisClient, irisPushOptions } from "../src/server.js";

function parseArgs(argv: string[]): { caseId?: string; name?: string } {
  const caseId = argv[0] && !argv[0].startsWith("--") ? argv[0] : undefined;
  const nameFlag = argv.indexOf("--name");
  const name = nameFlag !== -1 ? argv[nameFlag + 1] : undefined;
  return { caseId, name };
}

async function main(): Promise<void> {
  const { caseId, name: nameOverride } = parseArgs(process.argv.slice(2));
  if (!caseId) {
    console.error('usage: npm run iris:push -- <caseId> [--name "custom IRIS case name"]');
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
  const irisExportStore = new IrisExportStore(store);

  const state = await stateStore.load(caseId);
  const meta = await reportMetaStore.load(caseId);
  // Sync the playbook against current state (honoring the per-case IR-templates setting) and push it.
  const { useTemplates } = await new PlaybookControlStore(store).load(caseId);
  const playbookTasks = await new PlaybookStore(store).sync(caseId, state, { useTemplates });

  const caseMeta = await store.getCaseMeta(caseId).catch(() => null);
  const saved = await irisExportStore.load(caseId);
  const caseName = nameOverride?.trim() || saved.caseName || defaultIrisCaseName(caseId, caseMeta?.name);

  console.log(`Pushing "${caseId}" to ${process.env.DFIR_IRIS_URL} as IRIS case "${caseName}" …`);
  const res = await pushCaseToIris(
    client,
    { caseName, state, meta, playbookTasks: playbookTasks.length ? playbookTasks : undefined },
    irisPushOptions(),
  );
  await irisExportStore.record(caseId, caseName);

  console.log(`\nIRIS case #${res.caseId} ${res.created ? "CREATED" : "UPDATED"} ("${res.caseName}")`);
  console.log(`  assets:   +${res.assets.added}  (${res.assets.existing} existing, ${res.assets.skipped} skipped)`);
  console.log(`  iocs:     +${res.iocs.added}  (${res.iocs.existing} existing, ${res.iocs.skipped} skipped)`);
  console.log(`  timeline: +${res.timeline.added}  (${res.timeline.existing} existing, ${res.timeline.skipped} skipped)`);
  console.log(`  tasks:    +${res.tasks.added}  (${res.tasks.existing} existing, ${res.tasks.skipped} skipped)`);
  console.log(`  notes:    ${res.notes}   summary: ${res.summaryUpdated ? "updated" : "not set"}`);
  if (res.caseUrl) console.log(`  open:     ${res.caseUrl}`);
  if (res.warnings.length) {
    console.log(`\n  ${res.warnings.length} warning(s):`);
    for (const w of res.warnings.slice(0, 20)) console.log(`   - ${w}`);
    if (res.warnings.length > 20) console.log(`   … and ${res.warnings.length - 20} more`);
  }
}

main().catch((e) => { console.error("iris push error:", (e as Error).message); process.exit(1); });
