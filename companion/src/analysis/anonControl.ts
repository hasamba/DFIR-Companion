import { readFile } from "node:fs/promises";
import { join } from "node:path";
import type { CaseStore } from "../storage/caseStore.js";
import { atomicWrite } from "../storage/atomicWrite.js";
import type { AnonCategory, AnonPolicy } from "./anonymize.js";

// Per-case anonymization control. Default ON (privacy-first) — flip the default for NEW cases
// with DFIR_ANONYMIZE=off. Real values always stay in state; this only governs the wire to the
// LLM. `categories` selects which entity kinds are tokenized; `redactSecrets` one-way-redacts
// credentials/keys.
export interface AnonControl {
  enabled: boolean;
  categories: Record<AnonCategory, boolean>;
  redactSecrets: boolean;
}

const ALL_ON: Record<AnonCategory, boolean> = { IP: true, EMAIL: true, USER: true, HOST: true, DOMAIN: true, PATH: true };

function defaultControl(): AnonControl {
  const off = /^(0|false|no|off)$/i.test(process.env.DFIR_ANONYMIZE ?? "");
  return { enabled: !off, categories: { ...ALL_ON }, redactSecrets: true };
}

// Resolve a stored control (or null) into the policy the anonymizer consumes. A missing control
// (store not wired) → disabled, so nothing is tokenized unless explicitly configured.
export function toAnonPolicy(control: AnonControl | null): AnonPolicy {
  if (!control) return { enabled: false, categories: { ...ALL_ON }, redactSecrets: true };
  return {
    enabled: control.enabled,
    categories: { ...ALL_ON, ...control.categories },
    redactSecrets: control.redactSecrets !== false,
  };
}

export class AnonControlStore {
  constructor(private readonly cases: CaseStore) {}

  private path(caseId: string): string {
    return join(this.cases.stateDir(caseId), "anon-control.json");
  }

  async load(caseId: string): Promise<AnonControl> {
    try {
      const raw = JSON.parse(await readFile(this.path(caseId), "utf8")) as Partial<AnonControl>;
      const base = defaultControl();
      return {
        enabled: typeof raw.enabled === "boolean" ? raw.enabled : base.enabled,
        categories: { ...ALL_ON, ...(raw.categories ?? {}) },
        redactSecrets: typeof raw.redactSecrets === "boolean" ? raw.redactSecrets : base.redactSecrets,
      };
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return defaultControl();
      throw err;
    }
  }

  async save(caseId: string, control: AnonControl): Promise<void> {
    await atomicWrite(this.path(caseId), JSON.stringify(control, null, 2));
  }
}
