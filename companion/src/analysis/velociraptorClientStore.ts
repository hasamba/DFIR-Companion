import { readFile, mkdir } from "node:fs/promises";
import { dirname, join } from "node:path";
import { atomicWrite } from "../storage/atomicWrite.js";
import type { VeloClientRecord } from "../integrations/velociraptor/velociraptorApi.js";

// Persisted inventory of one Velociraptor server's enrolled clients (issue #70), one file per server
// set (clients-<setId>.json). Resolving a hostname/FQDN
// to a client_id via a live `clients(search=...)` lookup is brittle — the search index tokenizes the
// hostname on dots, so an FQDN search misses a short-name-enrolled client (and vice-versa). Instead we
// snapshot the whole fleet once (on connect / startup / manual refresh, and lazily on a collection
// miss) into one JSON file mapping clientId ↔ hostname ↔ fqdn, and look the host up there. Shared by
// the cases on that set; lives in a subdir beside cases/ (Windows drive-root-safe, like bundles/nsrl).

export interface VeloClientInventory {
  updatedAt: string; // ISO time of the last refresh ("" when never refreshed)
  clients: VeloClientRecord[];
}

export class VelociraptorClientStore {
  constructor(private readonly file: string) {}

  // Load the inventory, or an empty one when the file is missing/malformed (never throws on read).
  async load(): Promise<VeloClientInventory> {
    try {
      const parsed = JSON.parse(await readFile(this.file, "utf8")) as VeloClientInventory;
      if (parsed && Array.isArray(parsed.clients)) {
        return {
          updatedAt: String(parsed.updatedAt ?? ""),
          clients: parsed.clients.filter((c): c is VeloClientRecord => !!c && typeof c.clientId === "string"),
        };
      }
    } catch {
      // ENOENT / malformed → empty inventory
    }
    return { updatedAt: "", clients: [] };
  }

  // Replace the inventory with a fresh snapshot. `now` is passed in (no clock dependency in the store).
  async save(clients: VeloClientRecord[], now: string): Promise<VeloClientInventory> {
    const inv: VeloClientInventory = { updatedAt: now, clients };
    await mkdir(dirname(this.file), { recursive: true });
    await atomicWrite(this.file, JSON.stringify(inv, null, 2));
    return inv;
  }
}

/** The fleet roster a case's host resolution reads: the inventory of the case's own server set. */
export interface CaseFleetInventory {
  load(caseId: string): Promise<VeloClientInventory>;
}

const EMPTY_INVENTORY: VeloClientInventory = { updatedAt: "", clients: [] };
// Set ids are generated UUIDs. Anything else never reaches a file name.
const SET_ID_RE = /^[A-Za-z0-9-]{1,64}$/;

/** One inventory store per server set, in `dir`/clients-<setId>.json. */
export function setInventories(dir: string): (setId: string) => VelociraptorClientStore {
  const stores = new Map<string, VelociraptorClientStore>();
  return (setId) => {
    if (!SET_ID_RE.test(setId)) throw new Error("invalid server set id");
    let s = stores.get(setId);
    if (!s) {
      s = new VelociraptorClientStore(join(dir, `clients-${setId}.json`));
      stores.set(setId, s);
    }
    return s;
  };
}

/**
 * The case's inventory: its linked set's file. A case with no link (or an unreadable link file)
 * gets an empty roster — never another set's.
 */
export function caseFleetInventory(
  caseSetId: (caseId: string) => string | undefined,
  inventoryFor: (setId: string) => VelociraptorClientStore,
): CaseFleetInventory {
  return {
    async load(caseId) {
      let setId: string | undefined;
      try {
        setId = caseSetId(caseId);
      } catch {
        return EMPTY_INVENTORY;
      }
      return setId ? inventoryFor(setId).load() : EMPTY_INVENTORY;
    },
  };
}
