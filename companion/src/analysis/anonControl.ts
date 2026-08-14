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
  /**
   * Whether the optional Presidio layer runs for THIS case. Defaults to on, so a configured
   * analyzer keeps its existing behaviour and nobody loses name detection by upgrading.
   *
   * Separate from DFIR_PRESIDIO_URL on purpose. That variable is read once at startup and is not in
   * /settings/reload's allowlist, so the only way to stand a case down off a sick or slow analyzer
   * used to be editing .env and restarting the server — which also throws away the configuration
   * you want back the moment the container is healthy. This is the runtime switch: the URL stays
   * configured, the layer stops running, and the case keeps working.
   */
  presidio: boolean;
}

const ALL_ON: Record<AnonCategory, boolean> = {
  IP: true,
  EMAIL: true,
  USER: true,
  HOST: true,
  DOMAIN: true,
  PATH: true,
  CMD: true,
  REG: true,
  CARD: true,
  PHONE: true,
  NATID: true,
};

function defaultControl(): AnonControl {
  const off = /^(0|false|no|off)$/i.test(process.env.DFIR_ANONYMIZE ?? "");
  return { enabled: !off, categories: { ...ALL_ON }, redactSecrets: true, presidio: true };
}

// Resolve a stored control (or null) into the policy the anonymizer consumes. A missing control
// (store not wired) → disabled, so nothing is tokenized unless explicitly configured.
export function toAnonPolicy(control: AnonControl | null): AnonPolicy {
  if (!control)
    return { enabled: false, categories: { ...ALL_ON }, redactSecrets: true, maskPublicIps: true };
  return {
    enabled: control.enabled,
    categories: { ...ALL_ON, ...control.categories },
    redactSecrets: control.redactSecrets !== false,
    maskPublicIps: true,
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
        // A control file written before this field existed has no `presidio` key, and must keep
        // scanning — absence means "never chose", not "chose off".
        presidio: typeof raw.presidio === "boolean" ? raw.presidio : base.presidio,
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
