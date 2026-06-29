// Re-fetch + re-slim MITRE ATT&CK Mitigations (the M-code "courses of action") into
// companion/data/attack-mitigations.json.
//
// This is the ACTIONABLE counterpart to the D3FEND mapping (issue #178). D3FEND names defensive
// *techniques/sensors*; ATT&CK Mitigations are the concrete "what to do" recommendations — e.g.
// T1003.001 → "enable Credential Guard", "disable WDigest", "no domain admins in local-admin
// groups". Each `mitigates` relationship carries a technique-SPECIFIC detail, which is the gold:
// it tells the analyst how that mitigation applies to that exact technique.
//
// This script is the ONLY part that touches the network, and it runs offline-prep only (never at
// request time). It downloads the enterprise-attack STIX bundle (~50 MB) and keeps just the
// mitigation metadata + technique→mitigation links with their per-link detail, writing a slim JSON.
//
// Run:  npm run data:update-attack-mitigations
//
// Run with tsx, NOT in tsconfig `include`, so `tsc` won't type-check it — verify by running.
// Dependency-free (Node 20+ global fetch only).

import { writeFile, mkdir } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const STIX_URL =
  process.env.DFIR_ATTACK_STIX_URL ||
  "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json";

const HERE = dirname(fileURLToPath(import.meta.url));
const OUT_PATH = join(HERE, "..", "data", "attack-mitigations.json");

const MITRE_SOURCE = "mitre-attack";
const TECHNIQUE_RE = /^T(\d{4})(?:\.(\d{3}))?$/;
const MITIGATION_RE = /^M\d{4}$/;
const DESC_MAX = 360;

interface ExternalRef {
  source_name?: string;
  external_id?: string;
  url?: string;
}
interface StixObject {
  type?: string;
  id?: string;
  name?: string;
  description?: string;
  revoked?: boolean;
  x_mitre_deprecated?: boolean;
  x_mitre_version?: string;
  external_references?: ExternalRef[];
  relationship_type?: string;
  source_ref?: string;
  target_ref?: string;
}
interface StixBundle {
  objects?: StixObject[];
}

// One mitigation's slim record.
interface SlimMitigation {
  id: string; // "M1043"
  name: string; // "Credential Access Protection"
  description: string; // general mitigation description (cleaned)
  url: string; // attack.mitre.org page
}
// A technique→mitigation link with the technique-specific detail.
interface SlimLink {
  id: string; // mitigation M-code
  detail: string; // how this mitigation applies to THIS technique (cleaned), falls back to general desc
}

function attackId(obj: StixObject): string | undefined {
  return obj.external_references?.find((r) => r.source_name === MITRE_SOURCE)?.external_id;
}
function attackUrl(obj: StixObject): string {
  return obj.external_references?.find((r) => r.source_name === MITRE_SOURCE)?.url || "";
}
function isLive(obj: StixObject): boolean {
  return !obj.revoked && !obj.x_mitre_deprecated;
}

// Strip ATT&CK "(Citation: …)" markers + markdown to a clean, bounded one-liner.
function clean(raw: string | undefined): string {
  if (!raw) return "";
  let s = raw
    .replace(/\(Citation:[^)]*\)/g, "")
    .replace(/\[([^\]]+)\]\([^)]*\)/g, "$1")
    .replace(/[`*_]/g, "")
    .replace(/\s+/g, " ")
    .trim();
  if (s.length > DESC_MAX) {
    const cut = s.slice(0, DESC_MAX);
    const lastSpace = cut.lastIndexOf(" ");
    s = (lastSpace > DESC_MAX * 0.6 ? cut.slice(0, lastSpace) : cut).trim() + "…";
  }
  return s;
}

function fullTechnique(raw: string | undefined): string | null {
  if (!raw) return null;
  const m = TECHNIQUE_RE.exec(raw.trim().toUpperCase());
  if (!m) return null;
  return m[2] ? `T${m[1]}.${m[2]}` : `T${m[1]}`;
}

async function main(): Promise<void> {
  console.log(`[mitigations] fetching ${STIX_URL}`);
  const res = await fetch(STIX_URL);
  if (!res.ok) throw new Error(`fetch failed: ${res.status} ${res.statusText}`);
  const bundle = (await res.json()) as StixBundle;
  const objects = bundle.objects ?? [];
  console.log(`[mitigations] ${objects.length} STIX objects`);

  // 1. attack-pattern STIX id → full technique id (live only).
  const techniqueById = new Map<string, string>();
  for (const o of objects) {
    if (o.type !== "attack-pattern" || !o.id || !isLive(o)) continue;
    const full = fullTechnique(attackId(o));
    if (full) techniqueById.set(o.id, full);
  }

  // 2. course-of-action STIX id → slim mitigation (live, real M-code only — drops the legacy
  //    technique-specific "mitigations" that ATT&CK deprecated).
  const mitigationByStixId = new Map<string, SlimMitigation>();
  for (const o of objects) {
    if (o.type !== "course-of-action" || !o.id || !isLive(o)) continue;
    const mid = attackId(o);
    if (!mid || !MITIGATION_RE.test(mid) || !o.name) continue;
    mitigationByStixId.set(o.id, { id: mid, name: o.name.trim(), description: clean(o.description), url: attackUrl(o) });
  }

  // 3. "mitigates" relationships course-of-action → attack-pattern, carrying the technique-specific detail.
  const map: Record<string, SlimLink[]> = {};
  const seenPerTechnique = new Map<string, Set<string>>();
  for (const o of objects) {
    if (o.type !== "relationship" || o.relationship_type !== "mitigates") continue;
    if (!o.source_ref || !o.target_ref) continue;
    const mit = mitigationByStixId.get(o.source_ref);
    const tech = techniqueById.get(o.target_ref);
    if (!mit || !tech) continue;
    let seen = seenPerTechnique.get(tech);
    if (!seen) {
      seen = new Set<string>();
      seenPerTechnique.set(tech, seen);
    }
    if (seen.has(mit.id)) continue;
    seen.add(mit.id);
    const detail = clean(o.description) || mit.description;
    (map[tech] ??= []).push({ id: mit.id, detail });
  }

  // Sort each technique's links by mitigation id (deterministic), and the mitigations dict by id.
  for (const tech of Object.keys(map)) map[tech].sort((a, b) => a.id.localeCompare(b.id));
  const sortedMap: Record<string, SlimLink[]> = {};
  for (const tech of Object.keys(map).sort()) sortedMap[tech] = map[tech];

  const mitigations: Record<string, SlimMitigation> = {};
  for (const m of [...mitigationByStixId.values()].sort((a, b) => a.id.localeCompare(b.id))) mitigations[m.id] = m;

  const collection = objects.find((o) => o.type === "x-mitre-collection");
  const attackVersion = collection?.x_mitre_version || "unknown";

  const dataset = {
    source: "MITRE ATT&CK Enterprise (Mitigations)",
    note: "Concrete defensive mitigations (M-codes) recommended by MITRE ATT&CK for each technique.",
    attackVersion,
    generated: new Date().toISOString().slice(0, 10),
    mitigationCount: Object.keys(mitigations).length,
    techniqueCount: Object.keys(sortedMap).length,
    mitigations, // M-code → { id, name, description, url }
    map: sortedMap, // technique id → [{ id, detail }]
  };

  await mkdir(dirname(OUT_PATH), { recursive: true });
  await writeFile(OUT_PATH, JSON.stringify(dataset, null, 2) + "\n", "utf8");
  const links = Object.values(sortedMap).reduce((n, l) => n + l.length, 0);
  console.log(
    `[mitigations] wrote ${OUT_PATH}\n[mitigations] ATT&CK v${attackVersion} · ${dataset.mitigationCount} mitigations · ` +
      `${dataset.techniqueCount} techniques · ${links} technique-mitigation links`,
  );
}

main().catch((err) => {
  console.error("[mitigations] FAILED:", err instanceof Error ? err.message : err);
  process.exit(1);
});
