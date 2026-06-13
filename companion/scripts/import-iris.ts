// Import an EXISTING DFIR-IRIS case into a Companion case from the command line — the reverse
// of `iris:push`. Pull the IRIS case's assets/IOCs/timeline (by IRIS case id or exact name) and
// map them DETERMINISTICALLY (no AI call) into the Companion case's forensic timeline + IOCs.
// Reads DFIR_IRIS_* from .env.
//
//   npm run iris:import -- <companionCaseId> <irisCaseIdOrName>
import { config as loadDotenv } from "dotenv";
loadDotenv();

import { isAbsolute, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { CaseStore } from "../src/storage/caseStore.js";
import { StateStore } from "../src/analysis/stateStore.js";
import { fetchIrisCase } from "../src/integrations/iris/irisImportFetch.js";
import { buildIrisClient, buildRuntimePipeline } from "../src/server.js";

async function main(): Promise<void> {
  const caseId = process.argv[2];
  const irisRef = process.argv[3];
  if (!caseId || !irisRef) {
    console.error("usage: npm run iris:import -- <companionCaseId> <irisCaseIdOrName>");
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
  const pipeline = buildRuntimePipeline({ stateStore, store });

  const numericId = Number(irisRef);
  const ref = Number.isFinite(numericId) && /^\d+$/.test(irisRef) ? { irisCaseId: numericId } : { caseName: irisRef };

  console.log(`Importing IRIS case ${irisRef} from ${process.env.DFIR_IRIS_URL} into "${caseId}" …`);
  const data = await fetchIrisCase(client, ref);
  console.log(`  fetched: ${data.timeline.length} timeline event(s), ${data.assets.length} asset(s), ${data.iocs.length} IOC(s) from IRIS case ${data.caseName ?? `#${data.irisCaseId}`}`);

  const before = (await stateStore.load(caseId)).forensicTimeline.length;
  const importedAt = new Date().toISOString();
  const state = await pipeline.importIris(caseId, data, {
    label: `iris-case-${data.irisCaseId}.json`, idPrefix: `iriscli`, importedAt,
  });
  const added = state.forensicTimeline.length - before;

  console.log(`\nDone: case "${caseId}" now has ${state.forensicTimeline.length} timeline event(s) (+${added}) and ${state.iocs.length} IOC(s).`);
  console.log("Run `npm run synthesize -- " + caseId + "` to re-derive findings/MITRE/attacker path.");
}

main().catch((e) => { console.error("iris import error:", (e as Error).message); process.exit(1); });
