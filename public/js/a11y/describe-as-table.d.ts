// Hand-written declarations, matching the convention used by the other public/js modules.
// buildTableModel and laneRows are the DOM-free half and are what the node unit tests import.
export declare function laneRows(
  lanes: Array<{ label?: string; events?: Array<Record<string, unknown>> }>,
): Array<{ lane: string; timestamp: string; severity: string; description: string }>;
export declare function buildTableModel(
  rows: Array<Record<string, unknown>>,
  columns: string[],
): { columns: string[]; rows: string[][] };
export declare function renderTableAlternative(
  host: HTMLElement,
  model: { columns: string[]; rows: string[][] },
  caption: string,
): void;
