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

// Load .env so DFIR_CASES_ROOT matches the server — otherwise the demo lands in companion/cases
// while the server reads from the configured root, and the dashboard shows no case.
loadDotenv();

function arg(name: string): string | undefined {
  const i = process.argv.indexOf(`--${name}`);
  return i !== -1 && process.argv[i + 1] ? process.argv[i + 1] : undefined;
}

const caseId     = arg("case-id") ?? DEMO_CASE_ID_DEFAULT;
const force      = process.argv.includes("--force");
const companionDir = fileURLToPath(new URL("../", import.meta.url));
const rawRoot    = process.env.DFIR_CASES_ROOT ?? "cases";
const casesRoot  = isAbsolute(rawRoot) ? rawRoot : resolve(companionDir, rawRoot);

seedDemoCase(casesRoot, { caseId, force })
  .then(({ caseId: id, caseDir, stats }) => {
    console.log(`\nDemo case "${id}" created successfully.`);
    console.log(`  Path:            ${caseDir}`);
    console.log(`  Findings:        ${stats.findings}`);
    console.log(`  IOCs:            ${stats.iocs}`);
    console.log(`  Forensic events: ${stats.events}`);
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

