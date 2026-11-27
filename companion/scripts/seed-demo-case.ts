// CLI wrapper around the shared seedDemoCase logic.
// The same logic is also available via POST /cases/seed-demo when the server is running,
// which is how EXE users (without tsx/Node) can trigger it from the dashboard.
//
//   npm run seed-demo
//   npm run seed-demo -- --force            overwrite if already exists
//   npm run seed-demo -- --case-id demo2    use a different id
import { config as loadDotenv } from "dotenv";
import { resolve, isAbsolute } from "node:path";
import { fileURLToPath } from "node:url";
import { seedDemoCase, DEMO_CASE_ID_DEFAULT } from "../src/analysis/seedDemoCase.js";
import { seedDemoWithCustody } from "../src/analysis/seedDemoEvidence.js";
import { CustodyStore } from "../src/analysis/custody.js";
import { CaseStore } from "../src/storage/caseStore.js";

// Load .env so DFIR_CASES_ROOT matches the server — otherwise the demo lands in companion/cases
// while the server reads from the configured root, and the dashboard shows no case.
loadDotenv({ quiet: true });

function arg(name: string): string | undefined {
  const i = process.argv.indexOf(`--${name}`);
  return i !== -1 && process.argv[i + 1] ? process.argv[i + 1] : undefined;
}

const caseId = arg("case-id") ?? DEMO_CASE_ID_DEFAULT;
const force = process.argv.includes("--force");
const companionDir = fileURLToPath(new URL("../", import.meta.url));
const rawRoot = process.env.DFIR_CASES_ROOT ?? "cases";
const casesRoot = isAbsolute(rawRoot) ? rawRoot : resolve(companionDir, rawRoot);

// Through the same seed slot and custody recording as POST /cases/seed-demo (#3022), so a CLI-seeded
// demo carries its chain of custody too.
const store = new CaseStore(casesRoot);
seedDemoWithCustody(store, new CustodyStore(store), caseId, (_isNew, generation) =>
  seedDemoCase(casesRoot, { caseId, force, generation }),
)
  .then(({ caseId: id, caseDir, stats, custodyError }) => {
    if (custodyError) console.warn(`Warning: the demo's chain of custody was not recorded: ${custodyError}`);
    console.log(`\nDemo case "${id}" created successfully.`);
    console.log(`  Path:            ${caseDir}`);
    console.log(`  Findings:        ${stats.findings}`);
    console.log(`  IOCs:            ${stats.iocs}`);
    console.log(`  Forensic events: ${stats.events}`);
    console.log(`  Super-timeline:  ${stats.superTimelineEvents}`);
    console.log(`\nStart the server and open the dashboard, then connect to case "${id}".`);
    console.log(`  npm run dev`);
  })
  .catch((e: NodeJS.ErrnoException) => {
    if (e.code === "EEXIST") {
      console.error(e.message);
      console.error("Pass --force to overwrite.");
    } else {
      console.error("seed-demo-case error:", e);
    }
    process.exit(1);
  });
