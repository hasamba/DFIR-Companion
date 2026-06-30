// Benchmark: measure the deterministic before/after impact of the harvested attacker-tradecraft
// rules (tradecraftRules.ts) on a REAL dataset, AI-free and reproducible.
//
// It walks a dataset's ECAR (ecar.json) + Windows Event Log (Sysmon / Security XML) artifacts,
// extracts every (image, commandLine) pair the process importers would grade, and computes the
// severity + ATT&CK techniques BEFORE (isSuspiciousCmd + reconTechniques only) and AFTER
// (also tradecraftSignal) -- exactly the change this PR makes to the process branch of the
// Windows/Sysmon, ECAR and memory importers. It reports the severity-distribution delta, every
// command whose grade CHANGED (the win) and confirms benign commands are not newly escalated (FP).
//
//   npx tsx scripts/bench-tradecraft.ts "<dataset dir>"
//
// Run with no path to bench the three bundled EvidenceForge datasets if present.

import { readFileSync, readdirSync, statSync, existsSync } from "node:fs";
import { join } from "node:path";
import { isSuspiciousCmd } from "../src/analysis/siemImport.js";
import { reconTechniques, techniqueName } from "../src/analysis/reconTechniques.js";
import { tradecraftSignal } from "../src/analysis/tradecraftRules.js";

type Sev = "Info" | "Low" | "Medium" | "High" | "Critical";
const RANK: Record<Sev, number> = { Info: 0, Low: 1, Medium: 2, High: 3, Critical: 4 };
const worst = (a: Sev, b: Sev): Sev => (RANK[a] >= RANK[b] ? a : b);

interface Pair { image: string; cmd: string; source: string; }

function walk(dir: string, hits: string[]): void {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    const s = statSync(p);
    if (s.isDirectory()) walk(p, hits);
    else if (/ecar\.json$/i.test(name) || /(sysmon|security)\.xml$/i.test(name)) hits.push(p);
  }
}

function decodeXml(s: string): string {
  return s
    .replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'").replace(/&#(\d+);/g, (_, d) => String.fromCharCode(+d))
    .replace(/&amp;/g, "&");
}

// Extract (image, commandLine) pairs from one artifact file.
function extractPairs(file: string): Pair[] {
  const text = readFileSync(file, "utf8");
  const out: Pair[] = [];
  if (/\.json$/i.test(file)) {
    // ECAR: NDJSON or a JSON array of records with a `properties` bag.
    const records: unknown[] = [];
    const trimmed = text.trim();
    if (trimmed.startsWith("[")) {
      try { records.push(...(JSON.parse(trimmed) as unknown[])); } catch { /* skip */ }
    } else {
      for (const line of text.split(/\r?\n/)) {
        const t = line.trim();
        if (!t) continue;
        try { records.push(JSON.parse(t)); } catch { /* skip */ }
      }
    }
    for (const r of records) {
      if (!r || typeof r !== "object") continue;
      const props = (r as Record<string, unknown>).properties as Record<string, unknown> | undefined;
      const cmd = String(props?.command_line ?? "");
      const image = String(props?.image_path ?? "");
      if (cmd || image) out.push({ image, cmd, source: "ECAR" });
    }
  } else {
    // Windows Event Log XML: one <Event> per process record; pull the Image + CommandLine Data nodes.
    const tool = /sysmon/i.test(file) ? "Sysmon" : "Security";
    for (const ev of text.split(/<Event\b/).slice(1)) {
      const img = /Name="(?:Image|NewProcessName)">([^<]*)</i.exec(ev);
      const cl = /Name="CommandLine">([^<]*)</i.exec(ev);
      if (!img && !cl) continue;
      out.push({ image: decodeXml(img?.[1] ?? ""), cmd: decodeXml(cl?.[1] ?? ""), source: tool });
    }
  }
  return out;
}

function gradeBefore(image: string, cmd: string): { sev: Sev; mitre: Set<string> } {
  const susp = isSuspiciousCmd(image, cmd);
  const sev: Sev = susp === "strong" ? "High" : susp === "weak" ? "Medium" : "Info";
  const mitre = new Set<string>(reconTechniques(image, cmd));
  if (susp === "strong") mitre.add("T1003");
  return { sev, mitre };
}

function gradeAfter(image: string, cmd: string): { sev: Sev; mitre: Set<string> } {
  const b = gradeBefore(image, cmd);
  const tc = tradecraftSignal(image, cmd);
  if (!tc) return b;
  const sev = worst(b.sev, tc.weight === "strong" ? "High" : "Medium");
  for (const t of tc.mitre) b.mitre.add(t);
  return { sev, mitre: b.mitre };
}

function benchDataset(dir: string): void {
  const files: string[] = [];
  walk(dir, files);
  // Dedup (image, cmd) so a command repeated across thousands of telemetry rows counts once.
  const seen = new Map<string, Pair>();
  for (const f of files) for (const p of extractPairs(f)) {
    const key = `${p.image} ${p.cmd}`;
    if (!seen.has(key)) seen.set(key, p);
  }
  const pairs = [...seen.values()].filter((p) => p.cmd || p.image);

  const dist = { before: { Medium: 0, High: 0 }, after: { Medium: 0, High: 0 } };
  const escalations: { p: Pair; from: Sev; to: Sev; added: string[] }[] = [];
  const newTechniques = new Set<string>();

  for (const p of pairs) {
    const b = gradeBefore(p.image, p.cmd);
    const a = gradeAfter(p.image, p.cmd);
    if (b.sev === "Medium" || b.sev === "High") dist.before[b.sev]++;
    if (a.sev === "Medium" || a.sev === "High") dist.after[a.sev]++;
    const added = [...a.mitre].filter((t) => !b.mitre.has(t));
    added.forEach((t) => newTechniques.add(t));
    if (RANK[a.sev] > RANK[b.sev] || added.length) {
      escalations.push({ p, from: b.sev, to: a.sev, added });
    }
  }

  console.log(`\n${"=".repeat(78)}\nDATASET  ${dir.split(/[\\/]/).slice(-1)[0]}`);
  console.log(`files: ${files.length}   unique (image,cmd) pairs: ${pairs.length}`);
  console.log(`severity  before -> after   Medium: ${dist.before.Medium} -> ${dist.after.Medium}   High: ${dist.before.High} -> ${dist.after.High}`);
  console.log(`new ATT&CK techniques introduced: ${newTechniques.size ? [...newTechniques].map((t) => `${t} ${techniqueName(t)}`).join(", ") : "(none)"}`);
  if (!escalations.length) { console.log("changed commands: (none)"); return; }
  console.log(`changed commands (${escalations.length}):`);
  for (const e of escalations.sort((x, y) => RANK[y.to] - RANK[x.to])) {
    const sev = e.from === e.to ? `${e.to}` : `${e.from}->${e.to}`;
    const what = (e.p.cmd || e.p.image).slice(0, 110);
    console.log(`  [${e.p.source}] ${sev.padEnd(12)} +${e.added.join(",") || "-"}  ${what}`);
  }
}

const argDir = process.argv[2];
const DEFAULT_ROOT = "C:/Users/yaniv/10Root Dropbox/Yaniv Radunsky/Documents/30-39 DFIR/34-Sample_Data/36.29-Full-Incidends-from-EvidenceForge";
const targets = argDir
  ? [argDir]
  : ["meridian-tax-ransomware", "veridia-breach", "branch-office-example"]
      .map((d) => join(DEFAULT_ROOT, d))
      .filter((d) => existsSync(d));

if (!targets.length) {
  console.error('usage: tsx scripts/bench-tradecraft.ts "<dataset dir>"');
  process.exit(1);
}
for (const t of targets) benchDataset(t);
