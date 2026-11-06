// Types for buildRulePack.mjs. It is .mjs so the rule-pack-publish workflow runs it under plain
// `node` with no install step, and tsconfig has no allowJs, so the test that imports it needs this
// bridge (the same arrangement as upstreamRulesDiff.d.mts). Nothing generates this file.

export interface PackSource {
  name: string;
  commit: string;
  date: string;
}

export interface PackFile {
  name: string;
  sha256: string;
  bytes: number;
}

export interface PackManifest {
  schema: number;
  kind: string;
  version: string;
  minAppVersion: string;
  createdAt: string;
  commit?: string;
  ruleCount: number;
  sources: PackSource[];
  files: PackFile[];
}

export const PACK_SCHEMA: number;
export const PACK_KIND: string;
export const RULES_ASSET: string;
export const MANIFEST_ASSET: string;
export function sha256(text: string): string;
export function parseUpstreamSources(tagsYaml: string): PackSource[];
export function countRules(tagsYaml: string): number;
export function nextPackVersion(date: string, taken?: readonly string[]): string;
export function buildManifest(input: {
  tagsYaml: string;
  appVersion: string;
  version: string;
  createdAt: string;
  commit?: string;
}): PackManifest;
export function isUnchanged(previous: unknown, next: PackManifest): boolean;
