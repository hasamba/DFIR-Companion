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
/**
 * The resumable job's parameters for the two generic routes — what importRecovery.ts restores an
 * interrupted import from, so everything that shaped the import must be here: the analyst's declared
 * host included (#1496), or a resumed import would land its rows under the record names.
 */
export function importJobParameters(o: {
  kind: string;
  storedName: string;
  seq: number;
  importedAt: string;
  minSeverity: Severity | undefined;
  streaming: boolean;
  req: Request;
}): Record<string, string | number | boolean | null> {
  const assetHost =
    typeof o.req.body?.assetHost === "string" && o.req.body.assetHost ? o.req.body.assetHost : null;
  return {
    kind: o.kind,
    storedName: o.storedName,
    sequence: o.seq,
    importedAt: o.importedAt,
    minSeverity: o.minSeverity ?? null,
    streaming: o.streaming,
    assetHost,
  };
}

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
    // Validated and normalised by registerImportAssetHostGuard before the route ran (#1496).
    ...(typeof o.req.body?.assetHost === "string" && o.req.body.assetHost
      ? { assetHost: o.req.body.assetHost }
      : {}),
  };
}
