import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { getServerLogger } from "../logging/serverLogger.js";
import type { CaseStore } from "../storage/caseStore.js";
import { atomicWrite } from "../storage/atomicWrite.js";
import { StateLock } from "./stateLock.js";
import { ALL_TOKEN_CATEGORIES, type AnonPair, type Anonymizer } from "./anonymize.js";
import { anonPairKey } from "./anonPatterns.js";

// #2657: the case's masking map. The first time a value is masked for an AI call, its token is saved
// here, and every later call for the case gets the same token for it: ANON_HOST_3 means one host in
// Watson, synthesis, the deep pass and the reports alike.
//
// The map is an IDENTITY table only. It decides WHICH token a masked value gets, never WHETHER a value
// is masked — that stays the policy, the case's entity lists and Presidio. So it cannot unmask anything
// the analyst hid, and it cannot mask anything they left visible.
//
// Allocation is canonical: a send masks inside `withAnonMap`, under a per-case lock, and saves what it
// minted before the lock is released. Two calls on one case mask one after the other, so the token a
// call SENDS is the token the map SAVES. The lock covers entity loading, masking and the write — never
// OCR, Presidio or the provider call. Module-level, like anonDiscovered.ts: several store instances write
// the same file.
//
// It holds real values, like the rest of the case's state folder. A full case export carries it; the
// redacted export never does (it is assembled from an allowlist and uses its own anonymizer).

export const ANON_MAP_MAX = 20000;
const FILE = "anon-map.json";
const TOKEN_RE = /^ANON_([A-Z]+)_([1-9]\d*)$/;
const CATEGORIES: ReadonlySet<string> = new Set(ALL_TOKEN_CATEGORIES);

const mapLock = new StateLock();

export interface AnonMap {
  pairs: AnonPair[];
  /** The file could not be read as JSON. It is left untouched; tokens are not stable until it is fixed. */
  corrupt?: true;
}

/** Keep well-formed pairs; the first wins on a repeated token or a repeated category + value. */
export function sanitizeAnonMap(raw: unknown): AnonPair[] {
  const list = (raw as { pairs?: unknown } | null)?.pairs;
  if (!Array.isArray(list)) return [];
  const tokens = new Set<string>();
  const values = new Set<string>();
  const out: AnonPair[] = [];
  for (const item of list) {
    const p = item as Partial<AnonPair> | null;
    if (!p || typeof p.token !== "string" || typeof p.value !== "string" || p.value === "") continue;
    const cat = TOKEN_RE.exec(p.token)?.[1];
    if (!cat || cat !== p.category || !CATEGORIES.has(cat)) continue;
    const key = anonPairKey(cat, p.value);
    if (tokens.has(p.token) || values.has(key)) continue;
    tokens.add(p.token);
    values.add(key);
    out.push({ token: p.token, value: p.value, category: cat });
  }
  return out;
}

export class AnonMapStore {
  private warnedFull = false;

  constructor(private readonly cases: CaseStore) {}

  private path(caseId: string): string {
    return join(this.cases.stateDir(caseId), FILE);
  }

  async load(caseId: string): Promise<AnonMap> {
    let text: string;
    try {
      text = await readFile(this.path(caseId), "utf8");
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return { pairs: [] };
      throw err;
    }
    try {
      return { pairs: sanitizeAnonMap(JSON.parse(text)) };
    } catch {
      getServerLogger().error(`[anon] ${FILE} is not valid JSON; masking tokens are not kept stable`, {
        caseId,
      });
      return { pairs: [], corrupt: true };
    }
  }

  /**
   * Mask under the case's lock and save what was minted. `mask` gets the saved pairs (the identity
   * table for createAnonymizer) and returns its anonymizer, or null when masking is off.
   */
  withAnonMap<T>(
    caseId: string,
    mask: (identity: readonly AnonPair[]) => Promise<{ anon: Anonymizer | null; result: T }>,
  ): Promise<T> {
    return mapLock.runExclusive(caseId, async () => {
      const saved = await this.load(caseId);
      const { anon, result } = await mask(saved.pairs);
      // A failed save never fails the call: this call's own masking is complete and restores itself.
      if (anon && !saved.corrupt)
        await this.append(caseId, saved.pairs, anon.pairs()).catch((err: unknown) =>
          getServerLogger().warn(`[anon] could not save the masking map: ${String(err)}`, { caseId }),
        );
      return result;
    });
  }

  private async append(caseId: string, saved: AnonPair[], used: readonly AnonPair[]): Promise<void> {
    const tokens = new Set(saved.map((p) => p.token));
    const fresh = used.filter((p) => !tokens.has(p.token));
    if (fresh.length === 0) return;
    const room = ANON_MAP_MAX - saved.length;
    if (room < fresh.length && !this.warnedFull) {
      this.warnedFull = true;
      getServerLogger().warn(`[anon] masking map is full (${ANON_MAP_MAX}); new tokens are not saved`, {
        caseId,
      });
    }
    if (room <= 0) return;
    const pairs = [...saved, ...fresh.slice(0, room)];
    await atomicWrite(this.path(caseId), JSON.stringify({ version: 1, pairs }, null, 2));
  }
}
