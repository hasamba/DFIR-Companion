// Types for upstreamRulesDiff.mjs. It is .mjs so the upstream-rules-check workflow runs it under
// plain `node` with no install step, and tsconfig has no allowJs, so the test that imports it needs
// this bridge (the same arrangement as architectureCounts.d.mts). Nothing generates this file.

export interface UpstreamGroup {
  readonly id: string;
  /** "csv-lists" (fixed CSV files, the default), "event-files" (one JSON file per entry under
   * watchPath) or "rule-files" (every file directly in watchPath, compared by content hash). */
  readonly kind?: "csv-lists" | "event-files" | "rule-files";
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
/** Every file under `dir` at `ref`, as path → blob sha. */
export type ListFiles = (repo: string, dir: string, ref: string) => Promise<Map<string, string>>;
/** The files directly in `dir` at `ref` (not recursive), as path → content hash. */
export type ListDir = (repo: string, dir: string, ref: string) => Promise<Map<string, string>>;

export const UPSTREAM_GROUPS: readonly UpstreamGroup[];
export function recordedCommitPattern(marker: string): RegExp;
export function readRecordedCommit(tagsYaml: string, marker: string): RecordedCommit;
export function parseCsv(text: string): string[][];
export function parseList(text: string, label: string): { header: string[]; entries: Map<string, string[]> };
export function diffList(baseText: string, headText: string, label?: string): ListDiff;
export function diffEntries(
  base: { header: string[]; entries: Map<string, string[]> },
  head: { header: string[]; entries: Map<string, string[]> },
): ListDiff;
export const EVENT_HEADER: readonly string[];
export function isEventFile(path: string, watchPath: string): boolean;
export function summariseEventFile(text: string, path: string): string[];
export function diffEventFiles(
  group: UpstreamGroup,
  base: string,
  head: string,
  fetchFile: FetchFile,
  listFiles: ListFiles,
): Promise<ListDiff>;
export const RULE_FILE_HEADER: readonly string[];
export function diffRuleFiles(
  group: UpstreamGroup,
  base: string,
  head: string,
  listDir: ListDir,
): Promise<ListDiff>;
export function hasChanges(diff: ListDiff): boolean;
export function compareGroup(
  group: UpstreamGroup,
  base: string,
  head: string,
  fetchFile: FetchFile,
  listFiles?: ListFiles,
  listDir?: ListDir,
): Promise<GroupResult>;
export function groupChanged(result: GroupResult): boolean;
export function issueMarker(result: GroupResult): string;
export function issueTitle(results: GroupResult[]): string;
export function renderReport(results: GroupResult[]): string;
