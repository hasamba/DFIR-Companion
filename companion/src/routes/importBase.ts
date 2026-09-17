import type { Request } from "express";
import { resolveTrailerProfile } from "../analysis/webRecordFields.js";
import type { Severity } from "../analysis/stateTypes.js";
import type { RegisteredJob } from "../analysis/jobManager.js";
import { hasParseProgress } from "./importKinds.js";
import type { createImportJobTracking } from "./importJobTracking.js";
import type { ImportBase } from "./context.js";

/**
 * The ImportBase object both `/cases/:id/import` and `/cases/:id/import-file` build identically —
 * extracted so neither grows the size-ledgered `routes/import.ts` (#993 added the trailerProfile
 * piece with no headroom left to spend; see `companion/scripts/check-file-size.mjs`). Takes the
 * whole `req` (not just `req.body?.webLogFormat`) so the call site fits this file's line-width gate.
 */
export function buildImportBase(o: {
  storedName: string;
  seq: number;
  importedAt: string;
  kind: string;
  minSeverity: Severity | undefined;
  tracking: ReturnType<typeof createImportJobTracking>;
  job: RegisteredJob | undefined;
  req: Request;
}): ImportBase {
  const trailerProfile =
    o.kind === "combinedlog" ? resolveTrailerProfile(o.req.body?.webLogFormat) : undefined;
  return {
    label: o.storedName,
    idPrefix: `${o.seq}`,
    importedAt: o.importedAt,
    onProgress: o.tracking.onProgress,
    ...(hasParseProgress(o.kind) ? { onParseProgress: o.tracking.onParseProgress } : {}),
    minSeverity: o.minSeverity,
    ...(o.job?.signal ? { signal: o.job.signal } : {}),
    ...(trailerProfile ? { combinedLog: { trailerProfile } } : {}),
  };
}
