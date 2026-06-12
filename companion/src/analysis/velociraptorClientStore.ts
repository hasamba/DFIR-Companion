import { readFile, mkdir } from "node:fs/promises";
import { dirname } from "node:path";
import { atomicWrite } from "../storage/atomicWrite.js";
import type { VeloClientRecord } from "../integrations/velociraptor/velociraptorApi.js";

// Persisted GLOBAL inventory of enrolled Velociraptor clients (issue #70). Resolving a hostname/FQDN
// to a client_id via a live `clients(search=...)` lookup is brittle — the search index tokenizes the
// hostname on dots, so an FQDN search misses a short-name-enrolled client (and vice-versa). Instead we
// snapshot the whole fleet once (on connect / startup / manual refresh, and lazily on a collection
// miss) into one JSON file mapping clientId ↔ hostname ↔ fqdn, and look the host up there. Shared
// across cases; lives in a subdir beside cases/ (Windows drive-root-safe, like bundles/whitelist/nsrl).

export interface VeloClientInventory {
  updatedAt: string;                 // ISO time of the last refresh ("" when never refreshed)
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
