// Types for upstreamRulesDiff.mjs. It is .mjs so the upstream-rules-check workflow runs it under
// plain `node` with no install step, and tsconfig has no allowJs, so the test that imports it needs
// this bridge (the same arrangement as architectureCounts.d.mts). Nothing generates this file.

export interface UpstreamGroup {
  readonly id: string;
  readonly name: string;
  readonly repo: string;
  /** The tags.yaml comment label in front of "<sha> (<date>)". */
  readonly marker: string;
  /** Upstream path whose newest commit is the comparison head. */
  readonly watchPath: string;
  readonly files: readonly string[];
}

export interface RecordedCommit {
  sha: string;
  date: string;
}

export interface ListEntry {
  key: string;
  cells: string[];
}

export interface ChangedEntry {
  key: string;
  before: string[];
  after: string[];
}

export interface ListDiff {
  added: ListEntry[];
  removed: ListEntry[];
  changed: ChangedEntry[];
  headerChanged: boolean;
  baseHeader: string[];
  headHeader: string[];
}

export interface GroupResult {
  group: UpstreamGroup;
  base: string;
  head: string;
  lists: { path: string; diff: ListDiff }[];
}

export type FetchFile = (repo: string, path: string, ref: string) => Promise<string>;

export const UPSTREAM_GROUPS: readonly UpstreamGroup[];
export function recordedCommitPattern(marker: string): RegExp;
export function readRecordedCommit(tagsYaml: string, marker: string): RecordedCommit;
export function parseCsv(text: string): string[][];
export function parseList(text: string, label: string): { header: string[]; entries: Map<string, string[]> };
export function diffList(baseText: string, headText: string, label?: string): ListDiff;
export function hasChanges(diff: ListDiff): boolean;
export function compareGroup(
  group: UpstreamGroup,
  base: string,
  head: string,
  fetchFile: FetchFile,
): Promise<GroupResult>;
export function groupChanged(result: GroupResult): boolean;
export function issueMarker(result: GroupResult): string;
export function issueTitle(results: GroupResult[]): string;
export function renderReport(results: GroupResult[]): string;
