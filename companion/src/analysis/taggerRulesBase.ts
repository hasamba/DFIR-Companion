// Persistence for the two small records behind "bring new rules into my copy" (#2344):
//
//   - the BASE record: which upstream rule content the analyst's copy was taken from, per rule key
//     (see taggerRulesMerge.ts). A SIDECAR file, not a header comment in the YAML: addRuleYaml and
//     removeRule re-serialize the whole copy through stringifyYaml, which drops comments, and a
//     top-level YAML key would be compiled as a rule.
//   - the DISMISS record: the upstream revision the notice was dismissed at, per server.
//
// Both are keyed by an upstream id ("builtin" today; a rule pack's id in #2349), so a second
// upstream adds an entry rather than a second file format.
//
// A missing or unreadable record reads as "no record". For the base that is the legacy path — the
// compare falls back to rule keys and says it cannot tell which side changed — which is the honest
// answer when the record is gone. It is never treated as "nothing changed".

import { readFile, rm, mkdir } from "node:fs/promises";
import { dirname } from "node:path";
import { atomicWrite } from "../storage/atomicWrite.js";
import type { RuleBase } from "./taggerRulesMerge.js";

export const BUILTIN_UPSTREAM = "builtin";

interface BaseFile {
  version: 1;
  upstreams: Record<string, RuleBase>;
}

interface DismissFile {
  version: 1;
  dismissed: Record<string, string>;
}

async function readJson(path: string): Promise<unknown> {
  try {
    return JSON.parse(await readFile(path, "utf8"));
  } catch {
    return undefined; // absent or corrupt — both mean "no record" (see header)
  }
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return !!v && typeof v === "object" && !Array.isArray(v);
}

function isRuleBase(v: unknown): v is RuleBase {
  if (!isRecord(v) || typeof v.revision !== "string" || !isRecord(v.rules)) return false;
  return Object.values(v.rules).every((h) => typeof h === "string");
}

async function readBaseFile(path: string): Promise<BaseFile> {
  const doc = await readJson(path);
  if (!isRecord(doc) || !isRecord(doc.upstreams)) return { version: 1, upstreams: {} };
  const upstreams = Object.fromEntries(Object.entries(doc.upstreams).filter(([, b]) => isRuleBase(b)));
  return { version: 1, upstreams: upstreams as Record<string, RuleBase> };
}

async function writeJson(path: string, value: unknown): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  await atomicWrite(path, JSON.stringify(value, null, 2) + "\n");
}

export async function readRuleBase(path: string, upstreamId: string): Promise<RuleBase | null> {
  const file = await readBaseFile(path);
  return Object.hasOwn(file.upstreams, upstreamId) ? file.upstreams[upstreamId] : null;
}

export async function writeRuleBase(path: string, upstreamId: string, base: RuleBase): Promise<void> {
  const file = await readBaseFile(path);
  await writeJson(path, { version: 1, upstreams: { ...file.upstreams, [upstreamId]: base } });
}

export async function removeRuleBase(path: string): Promise<void> {
  await rm(path, { force: true });
}

export async function readDismissedRevision(path: string, upstreamId: string): Promise<string | undefined> {
  const doc = await readJson(path);
  if (!isRecord(doc) || !isRecord(doc.dismissed)) return undefined;
  const rev = doc.dismissed[upstreamId];
  return typeof rev === "string" ? rev : undefined;
}

export async function writeDismissedRevision(
  path: string,
  upstreamId: string,
  revision: string,
): Promise<void> {
  const doc = await readJson(path);
  const prior = isRecord(doc) && isRecord(doc.dismissed) ? (doc as unknown as DismissFile).dismissed : {};
  await writeJson(path, { version: 1, dismissed: { ...prior, [upstreamId]: revision } });
}
