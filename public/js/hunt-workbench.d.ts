export interface HuntAutocompleteItem {
  value: string;
  label: string;
}

export function buildPivotQuery(
  kind: "event" | "ioc" | "finding" | "asset",
  value: string,
): string;

export function autocompleteFor(
  text: string,
  cursor: number,
  fields?: readonly string[],
): HuntAutocompleteItem[];

export function csvFromRows(
  columns: readonly string[],
  rows: ReadonlyArray<
    Readonly<Record<string, string | number | boolean | null | undefined>>
  >,
): string;

export interface HuntHistoryEntry {
  executedAt?: string;
  executedBy?: string;
  status?: string;
  matched?: number;
  scanned?: number;
  durationMs?: number;
  parameters?: Readonly<Record<string, string | number | boolean | null>>;
  error?: string;
}

/** A saved hunt's execution history as escaped HTML, newest first; "" for no hunt (#1833). */
export function renderHuntHistory(
  hunt: { history?: readonly HuntHistoryEntry[] } | null | undefined,
): string;
