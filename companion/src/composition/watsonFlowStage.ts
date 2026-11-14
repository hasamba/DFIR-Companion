import { mkdir, readFile, rm } from "node:fs/promises";
import { dirname, join } from "node:path";
import { atomicWrite } from "../storage/atomicWrite.js";
import type { CaseStore } from "../storage/caseStore.js";
import type { WatsonIngested } from "./watsonVeloResults.js";

// The durable stage of a Watson collection's ingest result (final review G7). The rows are ingested
// (stored, merged, held promotions built) BEFORE the chat save that records them; if that save fails,
// the held promotions existed only in memory and were lost. So the result is written here right
// after the ingest, keyed by the flow, and a retry or restart finishes the chat save from it once —
// the rows are never ingested twice.

export interface StagedIngest {
  flowId: string;
  rows: number;
  added: number;
  truncated?: true;
  total?: number;
  ingested: WatsonIngested;
}

export interface WatsonIngestStage {
  save(caseId: string, proposalId: string, staged: StagedIngest): Promise<void>;
  /** The staged result for this launch's flow, or null (none, another flow's, or unreadable). */
  load(caseId: string, proposalId: string, flowId: string): Promise<StagedIngest | null>;
  clear(caseId: string, proposalId: string): Promise<void>;
}

const SAFE_ID = /^[A-Za-z0-9_-]{1,80}$/;
const DIR = "watson-flow-stage";

export function fileIngestStage(store: Pick<CaseStore, "stateDir">): WatsonIngestStage {
  const path = (caseId: string, id: string): string => {
    if (!SAFE_ID.test(id)) throw new Error("invalid proposal id for the ingest stage");
    return join(store.stateDir(caseId), DIR, `${id}.json`);
  };
  return {
    save: async (caseId, id, staged) => {
      const file = path(caseId, id);
      await mkdir(dirname(file), { recursive: true });
      await atomicWrite(file, JSON.stringify(staged));
    },
    load: async (caseId, id, flowId) => {
      try {
        const raw = JSON.parse(await readFile(path(caseId, id), "utf8")) as StagedIngest;
        return raw && raw.flowId === flowId && raw.ingested?.paste ? raw : null;
      } catch {
        return null;
      }
    },
    clear: (caseId, id) => rm(path(caseId, id), { force: true }),
  };
}
