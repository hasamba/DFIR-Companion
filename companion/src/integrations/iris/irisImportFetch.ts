// Pulls an existing DFIR-IRIS case's evidence (assets + IOCs + timeline) into the raw shape
// the pure parser (analysis/irisImport.ts) consumes. The reverse of irisPush.ts.
//
// The IRIS client is injected as a structural interface so this is unit-testable with a mock
// (no network), matching the irisPush orchestrator pattern.

import type { IrisCaseData } from "../../analysis/irisImport.js";
import type { IrisCaseRef } from "./irisClient.js";

// Structural subset of IrisClient used by the import fetch — lets tests pass a lightweight mock.
export interface IrisImportClientLike {
  ping(): Promise<void>;
  findCaseByName(name: string): Promise<IrisCaseRef | null>;
  listCases(): Promise<IrisCaseRef[]>;
  getRawAssets(cid: number): Promise<Array<Record<string, unknown>>>;
  getRawIocs(cid: number): Promise<Array<Record<string, unknown>>>;
  getRawTimeline(cid: number): Promise<Array<Record<string, unknown>>>;
}

// Which IRIS case to import: by numeric case id (cid) and/or by exact name. At least one is
// required; a name is resolved to a cid via findCaseByName.
export interface IrisImportRef {
  irisCaseId?: number;
  caseName?: string;
}

export class IrisImportError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "IrisImportError";
  }
}

// Resolve the ref to a concrete { cid, name }, then fetch the three evidence sections.
export async function fetchIrisCase(client: IrisImportClientLike, ref: IrisImportRef): Promise<IrisCaseData> {
  // 1. Connectivity / auth (fatal).
  await client.ping();

  // 2. Resolve the case id + name.
  let cid: number;
  let caseName: string | undefined;
  if (ref.caseName && ref.caseName.trim()) {
    const found = await client.findCaseByName(ref.caseName.trim());
    if (!found) throw new IrisImportError(`IRIS case not found by name: "${ref.caseName.trim()}"`);
    cid = found.caseId;
    caseName = found.caseName;
  } else if (ref.irisCaseId != null && Number.isFinite(ref.irisCaseId)) {
    cid = ref.irisCaseId;
    // Best-effort: look up the display name from the case list (non-fatal).
    try {
      caseName = (await client.listCases()).find((c) => c.caseId === cid)?.caseName;
    } catch { /* ignore — name is cosmetic */ }
    caseName ??= `IRIS case #${cid}`;
  } else {
    throw new IrisImportError("an IRIS case id or name is required");
  }

  // 3. Fetch the evidence sections in parallel.
  const [assets, iocs, timeline] = await Promise.all([
    client.getRawAssets(cid),
    client.getRawIocs(cid),
    client.getRawTimeline(cid),
  ]);

  return { irisCaseId: cid, caseName, assets, iocs, timeline };
}
