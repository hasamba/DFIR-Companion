// "Was this hunt or flow already pulled into this case?" (#1965) — asked by the import-external route
// BEFORE any Velociraptor call, so a repeat paste does not re-read every row under the case's import
// slot only to dedup to "+0 events". The answer comes from the case's import audit log
// (metadata/imports.jsonl): every Velociraptor artifact import appends one line whose originalName is
// `velo-hunt_<huntId>_<artifact>.json` or `velo-flow_<flowId>_<artifact>.json`. A hunt the Companion
// collected itself ("Collect now") uses the same hunt label, so it counts too — its rows are in the case.
//
// The audit line is written before the memory guard can refuse an import, so a "prior import" means
// "already pulled into this case", not "fully imported". The route only warns; "Re-import anyway"
// always goes through. Uploads URLs (`velo-hunt-uploads_…`) never reach this log by that label and are
// out of scope.

import { readFile } from "node:fs/promises";
import type { VeloRef } from "../analysis/veloRef.js";

/** What the 409 answer carries so the dashboard can say when and what. */
export type PriorVeloImport = (
  { kind: "hunt"; huntId: string } | { kind: "flow"; clientId: string; flowId: string }
) & { firstImportedAt: string; lastImportedAt: string; artifacts: string[] };

/** A notebook URL cannot be imported here; moved out of routes/velociraptor.ts to fit its size ledger. */
export const NOTEBOOK_URL_ERROR =
  "this is a Velociraptor NOTEBOOK URL — importing it here would pull the flow/hunt's complete raw results, not your notebook's filtered query. Open the notebook in your browser and use the DFIR Companion extension's \"Push rows → DFIR-Companion\" button instead, which imports exactly what the notebook shows.";

// A flow label holds no client id, so a flow is keyed on its flow id alone. Flow ids are random per
// collection, so a collision across clients is not a practical risk. The trailing `_` keeps H.AB from
// matching H.ABC.
const labelPrefix = (ref: VeloRef): string =>
  ref.kind === "hunt" ? `velo-hunt_${ref.huntId}_` : `velo-flow_${ref.flowId}_`;

interface AuditLine {
  originalName: string;
  importedAt: string;
}

function parseAuditLine(line: string): AuditLine | null {
  try {
    const v = JSON.parse(line) as Partial<AuditLine> | null;
    return typeof v?.originalName === "string" && typeof v.importedAt === "string"
      ? { originalName: v.originalName, importedAt: v.importedAt }
      : null;
  } catch {
    return null; // a torn or hand-edited line is not evidence of a prior import
  }
}

async function readAuditLog(path: string): Promise<string> {
  try {
    return await readFile(path, "utf8");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return ""; // no import yet
    throw err;
  }
}

/** The case's prior import of this hunt or flow, or null when it has none. */
export async function priorVeloImport(
  store: { importsLogPath(caseId: string): string },
  caseId: string,
  ref: VeloRef,
): Promise<PriorVeloImport | null> {
  const prefix = labelPrefix(ref);
  const hits = (await readAuditLog(store.importsLogPath(caseId)))
    .split("\n")
    .map(parseAuditLine)
    .filter((l): l is AuditLine => l !== null && l.originalName.startsWith(prefix));
  if (!hits.length) return null;
  const dates = hits.map((h) => h.importedAt).sort();
  const artifacts = [...new Set(hits.map((h) => h.originalName.slice(prefix.length).replace(/\.json$/, "")))];
  const id =
    ref.kind === "hunt"
      ? { kind: "hunt" as const, huntId: ref.huntId }
      : { kind: "flow" as const, clientId: ref.clientId, flowId: ref.flowId };
  return { ...id, firstImportedAt: dates[0], lastImportedAt: dates[dates.length - 1], artifacts };
}

/**
 * The prior import the route must warn about, or null to import now. Null for an uploads URL (out of
 * scope) and for "Re-import anyway". Only a literal `true` forces it: a truthy string must not.
 */
export async function priorVeloImportToWarn(
  store: { importsLogPath(caseId: string): string },
  caseId: string,
  ref: VeloRef,
  reimport: unknown,
): Promise<PriorVeloImport | null> {
  return ref.isUploadsUrl || reimport === true ? null : priorVeloImport(store, caseId, ref);
}
