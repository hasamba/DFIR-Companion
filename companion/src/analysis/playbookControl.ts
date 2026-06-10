import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { z } from "zod";
import type { CaseStore } from "../storage/caseStore.js";
import { atomicWrite } from "../storage/atomicWrite.js";

// Per-case playbook settings (issue #36, Phase 2). Currently just `useTemplates`: when on,
// Critical/High findings expand into severity-based IR templates (Contain/Investigate/Eradicate/
// Recover) instead of a single task. Default OFF so the playbook isn't flooded — opt-in per case,
// mirroring the conservative-default philosophy elsewhere (enrichment off by default, notebook-in-
// synthesis opt-in). Kept in `state/playbook-control.json` via atomicWrite.

export interface PlaybookControl {
  useTemplates: boolean;
}

export const DEFAULT_PLAYBOOK_CONTROL: PlaybookControl = { useTemplates: false };

const playbookControlSchema = z
  .object({ useTemplates: z.boolean().catch(false) })
  .catch(DEFAULT_PLAYBOOK_CONTROL);

export class PlaybookControlStore {
  constructor(private readonly cases: CaseStore) {}

  private path(caseId: string): string {
    return join(this.cases.stateDir(caseId), "playbook-control.json");
  }

  async load(caseId: string): Promise<PlaybookControl> {
    try {
      return playbookControlSchema.parse(JSON.parse(await readFile(this.path(caseId), "utf8")));
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return { ...DEFAULT_PLAYBOOK_CONTROL };
      throw err;
    }
  }

  async set(caseId: string, patch: Partial<PlaybookControl>): Promise<PlaybookControl> {
    const next: PlaybookControl = {
      ...(await this.load(caseId)),
      ...(typeof patch.useTemplates === "boolean" ? { useTemplates: patch.useTemplates } : {}),
    };
    await atomicWrite(this.path(caseId), JSON.stringify(next, null, 2));
    return next;
  }
}
