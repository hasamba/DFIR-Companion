import type { InvestigationState } from "./stateTypes.js";
import { safeImporterLabel, type OperationalMetricsStore } from "./operationalMetrics.js";

function wrappedRows(value: unknown): number | null {
  if (Array.isArray(value)) return value.length;
  if (!value || typeof value !== "object") return null;
  const record = value as Record<string, unknown>;
  for (const key of ["rows", "events", "records", "results", "items", "alerts", "value"]) {
    if (Array.isArray(record[key])) return record[key].length;
  }
  return null;
}

/** Estimate parser input rows without retaining any source text. */
export function estimateImportRows(text: string): number {
  const trimmed = text.trim();
  if (!trimmed) return 0;
  try {
    return wrappedRows(JSON.parse(trimmed)) ?? 1;
  } catch {
    return trimmed.split(/\r?\n/).filter((line) => line.trim().length > 0).length;
  }
}

function importedEvents(result: unknown, idPrefix: string): number {
  if (!result || typeof result !== "object") return 0;
  const timeline = (result as Partial<InvestigationState>).forensicTimeline;
  if (!Array.isArray(timeline)) return 0;
  return timeline.filter((event) => event && typeof event.id === "string" && event.id.startsWith(idPrefix))
    .length;
}

/** Observe an importer promise without allowing metrics I/O to change its outcome. */
export async function observeImport<T>(
  metrics: OperationalMetricsStore | undefined,
  input: { kind: string; idPrefix: string; text: string; startedAt: number },
  work: Promise<T>,
): Promise<T> {
  const rowsRead = estimateImportRows(input.text);
  try {
    const result = await work;
    const accepted = importedEvents(result, input.idPrefix);
    await metrics?.record({
      type: "import",
      importer: safeImporterLabel(input.kind),
      durationMs: Math.max(0, Date.now() - input.startedAt),
      rowsRead,
      accepted,
      rejected: Math.max(0, rowsRead - accepted),
      promoted: 0,
      rejectionReason: rowsRead > accepted ? "filtered" : "none",
    });
    return result;
  } catch (error) {
    await metrics?.record({
      type: "import",
      importer: safeImporterLabel(input.kind),
      durationMs: Math.max(0, Date.now() - input.startedAt),
      rowsRead,
      accepted: 0,
      rejected: rowsRead,
      promoted: 0,
      rejectionReason: "error",
    });
    throw error;
  }
}
