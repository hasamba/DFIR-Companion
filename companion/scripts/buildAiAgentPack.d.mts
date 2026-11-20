// Types for buildAiAgentPack.mjs (#2690). It is .mjs so the ai-agent-pack-publish workflow runs it
// under plain `node` with no install step, and tsconfig has no allowJs, so the test that imports it
// needs this bridge (the same arrangement as buildRulePack.d.mts). Nothing generates this file.

export interface AiPackFileText {
  path: string;
  text: string;
}

export interface AiPackManifest {
  schema: number;
  kind: string;
  version: string;
  minAppVersion: string;
  createdAt: string;
  commit?: string;
  upstream: { name: string; commit: string; date: string };
  ruleCount: number;
  files: { name: string; sha256: string; bytes: number }[];
  contents: { path: string; sha256: string }[];
}

export const AI_PACK_SCHEMA: number;
export const AI_PACK_KIND: string;
export const AI_PACK_BUNDLE_ASSET: string;
export const AI_PACK_MANIFEST_ASSET: string;
export const AI_PACK_TAG_PREFIX: string;
export function sha256(text: string): string;
export function readRuleFolder(dir: string): AiPackFileText[];
export function nextAiPackVersion(date: string, taken?: string[]): string;
export function buildAiPack(input: {
  files: AiPackFileText[];
  appVersion: string;
  version: string;
  createdAt: string;
  commit?: string;
}): { bundle: string; manifest: AiPackManifest };
export function isAiPackUnchanged(previous: unknown, next: AiPackManifest): boolean;
