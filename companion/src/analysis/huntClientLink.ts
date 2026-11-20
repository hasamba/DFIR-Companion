import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { atomicWrite } from "../storage/atomicWrite.js";
import type { CaseStore } from "../storage/caseStore.js";

/**
 * Which client a hunt case belongs to (#2670), in the case's own `state/hunt-client.json`. Linking
 * needs case-administrator rights (auth/policy.ts) — separate from writing evidence to the case.
 */
export interface HuntClientLink {
  clientId: string;
  linkedAt: string;
  linkedBy: string;
}

export class HuntClientLinkStore {
  constructor(private readonly cases: Pick<CaseStore, "stateDir">) {}

  private path(caseId: string): string {
    return join(this.cases.stateDir(caseId), "hunt-client.json");
  }

  async load(caseId: string): Promise<HuntClientLink | null> {
    try {
      const raw = JSON.parse(await readFile(this.path(caseId), "utf8")) as Partial<HuntClientLink>;
      return typeof raw?.clientId === "string" && raw.clientId
        ? {
            clientId: raw.clientId,
            linkedAt: String(raw.linkedAt ?? ""),
            linkedBy: String(raw.linkedBy ?? ""),
          }
        : null;
    } catch (err) {
      const code = (err as NodeJS.ErrnoException).code;
      if (code === "ENOENT" || err instanceof SyntaxError) return null;
      throw err;
    }
  }

  async save(caseId: string, link: HuntClientLink): Promise<HuntClientLink> {
    await atomicWrite(this.path(caseId), JSON.stringify(link, null, 2));
    return link;
  }
}
