// Push a case to MISP from the command line. Find-or-create the MISP event by the
// case's idempotency tag (`dfir-companion:case-{id}`), then push IOCs as attributes
// and MITRE techniques from findings as tags. Re-pushing is idempotent — attributes
// already present in the event are skipped. Reads DFIR_MISP_* from .env.
//
//   npm run misp:push -- <caseId>
import { config as loadDotenv } from "dotenv";
loadDotenv();

import { isAbsolute, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { CaseStore } from "../src/storage/caseStore.js";
import { StateStore } from "../src/analysis/stateStore.js";
import { pushCaseToMisp } from "../src/integrations/misp/mispPush.js";
import { buildMispPushClient, mispPushOptions } from "../src/server.js";

async function main(): Promise<void> {
  const caseId = process.argv[2] && !process.argv[2].startsWith("--") ? process.argv[2] : undefined;
  if (!caseId) {
    console.error("usage: npm run misp:push -- <caseId>");
    process.exit(2);
  }

  const client = buildMispPushClient();
  if (!client) {
    console.error("MISP not configured. Set DFIR_MISP_URL and DFIR_MISP_KEY in companion/.env.");
    process.exit(1);
  }

  const raw = process.env.DFIR_CASES_ROOT ?? "cases";
  const companionDir = fileURLToPath(new URL("../", import.meta.url));
  const casesRoot = isAbsolute(raw) ? raw : resolve(companionDir, raw);
  const store = new CaseStore(casesRoot);
  const stateStore = new StateStore(store);

  const state = await stateStore.load(caseId);

  console.log(`Pushing "${caseId}" to ${process.env.DFIR_MISP_URL} …`);
  const res = await pushCaseToMisp(client, { caseId, state }, mispPushOptions());

  console.log(`\nMISP event #${res.eventId} ${res.created ? "CREATED" : "UPDATED"} ("${res.eventInfo}")`);
  console.log(`  attributes: +${res.attributes.added}  (${res.attributes.existing} existing, ${res.attributes.skipped} skipped)`);
  console.log(`  tags:       +${res.tags}`);
  if (res.eventUrl) console.log(`  open:       ${res.eventUrl}`);
  if (res.warnings.length) {
    console.log(`\n  ${res.warnings.length} warning(s):`);
    for (const w of res.warnings.slice(0, 20)) console.log(`   - ${w}`);
    if (res.warnings.length > 20) console.log(`   … and ${res.warnings.length - 20} more`);
  }
}

main().catch((e) => { console.error("misp push error:", (e as Error).message); process.exit(1); });
