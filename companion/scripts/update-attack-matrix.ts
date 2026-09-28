// Re-fetch + re-slim the MITRE ATT&CK Enterprise matrix into companion/data/attack-matrix.json
// (#1764) — the offline catalogue behind the dashboard's and the interactive report's ATT&CK matrix.
//
// This script is the ONLY part that touches the network, and it runs offline-prep only (never at
// request time). It downloads a VERSIONED enterprise-attack STIX bundle — not master's moving
// enterprise-attack.json — so a re-run gives the same data; bump ATTACK_VERSION to move on.
//
// Run:  npm run data:update-attack-matrix
//
// Run with tsx, NOT in tsconfig `include`, so `tsc` won't type-check it — verify by running.
// Dependency-free (Node 22.5+ global fetch only).

import { writeFile, mkdir } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { slimAttackMatrix, type StixObject } from "./attackMatrixSlim.js";

const ATTACK_VERSION = "19.1";
const STIX_URL =
  process.env.DFIR_ATTACK_STIX_URL ||
  `https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-${ATTACK_VERSION}.json`;

const HERE = dirname(fileURLToPath(import.meta.url));
const OUT_PATH = join(HERE, "..", "data", "attack-matrix.json");

async function main(): Promise<void> {
  console.log(`[attack-matrix] fetching ${STIX_URL}`);
  const res = await fetch(STIX_URL);
  if (!res.ok) throw new Error(`fetch failed: ${res.status} ${res.statusText}`);
  const bundle = (await res.json()) as { objects?: StixObject[] };
  const { tactics, techniques, warnings } = slimAttackMatrix(bundle.objects ?? []);
  for (const w of warnings) console.warn(`[attack-matrix] ${w}`);

  const subs = techniques.filter((t) => t.parent).length;
  const out = {
    source: "MITRE ATT&CK Enterprise",
    attackVersion: ATTACK_VERSION,
    generated: new Date().toISOString().slice(0, 10),
    tactics,
    techniques,
  };
  await mkdir(dirname(OUT_PATH), { recursive: true });
  await writeFile(OUT_PATH, JSON.stringify(out) + "\n", "utf8");
  console.log(
    `[attack-matrix] wrote ${OUT_PATH}: ${tactics.length} tactics, ` +
      `${techniques.length - subs} techniques, ${subs} sub-techniques`,
  );
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
