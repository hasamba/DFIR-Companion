import { readFile } from "node:fs/promises";
import { randomBytes } from "node:crypto";
import { join } from "node:path";
import type { CaseStore } from "../storage/caseStore.js";
import { atomicWrite } from "../storage/atomicWrite.js";

// Per-case push token (#84): the shared secret an external tool presents in X-DFIR-Key to POST alerts
// to POST /cases/:id/push. Generated on demand from Settings (a global DFIR_PUSH_TOKEN also works and
// covers every case). Persisted to a side file so it survives the #1-gotcha restart. NOT part of
// InvestigationState, and excluded from the snapshot allowlist — it's a machine secret, not case data.

export interface PushTokenRecord {
  token: string;
  createdAt: string;   // ISO
}

// A URL-safe high-entropy token (32 hex chars = 128 bits). Standalone so the route can mint one and
// the store just persists it (keeps the store I/O-only + the crypto call easy to reason about).
export function generatePushToken(): string {
  return randomBytes(16).toString("hex");
}

export class PushTokenStore {
  constructor(private readonly cases: CaseStore) {}

  private path(caseId: string): string {
    return join(this.cases.stateDir(caseId), "push-token.json");
  }

  // The case's token, or null when none has been generated (never throws on a missing file).
  async get(caseId: string): Promise<PushTokenRecord | null> {
    try {
      const parsed = JSON.parse(await readFile(this.path(caseId), "utf8")) as PushTokenRecord;
      if (parsed && typeof parsed.token === "string" && parsed.token.trim()) {
        return { token: parsed.token.trim(), createdAt: String(parsed.createdAt ?? "") };
      }
      return null;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return null;
      throw err;
    }
  }

  // Set (or rotate) the token. `now` is injected so the store has no clock dependency.
  async set(caseId: string, token: string, now: string): Promise<PushTokenRecord> {
    const rec: PushTokenRecord = { token: String(token).trim(), createdAt: now };
    await atomicWrite(this.path(caseId), JSON.stringify(rec, null, 2));
    return rec;
  }

  // Remove the token (disables per-case push for this case; a global DFIR_PUSH_TOKEN still applies).
  async clear(caseId: string): Promise<void> {
    await atomicWrite(this.path(caseId), JSON.stringify({ token: "", createdAt: "" }, null, 2));
  }
}
