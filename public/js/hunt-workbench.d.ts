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
