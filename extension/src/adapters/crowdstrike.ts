import type { Adapter } from "./types.js";
import { asArray, getPath, isObject } from "./extractUtils.js";

// CrowdStrike Falcon console. Falcon's APIs wrap result objects in the standard
// `{ meta, resources: [...], errors: [] }` envelope (detections, alerts, incidents, hosts);
// the event-search / Logscale surfaces use `{ events: [...] }`. We return whichever array carries
// the rows. NOTE: a Falcon query response is sometimes `{ resources: ["id1","id2"] }` (id-only) —
// those aren't pushable rows, so we drop a resources array of bare strings.
export const crowdstrikeAdapter: Adapter = {
  id: "crowdstrike",
  label: "CrowdStrike Falcon",

  matchUrl(url: URL): boolean {
    return /(crowdstrike|falcon)/i.test(url.hostname);
  },

  // Fallback for a reverse-proxied / rebranded Falcon console whose hostname doesn't carry
  // "crowdstrike"/"falcon". The console titles every page "<view> | Falcon".
  matchDom(doc: Document): boolean {
    return /(crowdstrike|falcon)/i.test(doc.title);
  },

  apiPatterns: [
    "/detects/",
    "/alerts/",
    "/incidents/",
    "/devices/",
    "/threatgraph/",
    "/loggingapi/",
    "/humio/",
    "/api2/",
  ],

  extractRows(_url: string, body: unknown): unknown[] | null {
    if (!isObject(body)) return null;
    const events = asArray(getPath(body, "events"));
    if (events) return events;
    const resources = asArray(getPath(body, "resources"));
    // Keep resources only when they're row objects, not an id-list.
    if (resources && resources.some(isObject)) return resources;
    return null;
  },

  tableSelector: "table",
};
