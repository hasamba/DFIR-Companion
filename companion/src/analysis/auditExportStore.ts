import { readFile, mkdir } from "node:fs/promises";
import { existsSync } from "node:fs";
import { dirname } from "node:path";
import { randomUUID } from "node:crypto";
import { z } from "zod";
import { atomicWrite } from "../storage/atomicWrite.js";
import { StateLock } from "./stateLock.js";
import {
  AUDIT_DESTINATION_TYPES,
  SYSLOG_PROTOCOLS,
  applyDestinationPatch,
  type AuditDestination,
  type DestinationDraft,
} from "./auditExport.js";

// Persists the SIEM audit-export destinations (#929). GLOBAL, exactly like NotificationConfigStore:
// a Splunk collector or an Elasticsearch cluster is environment-level infrastructure reused across
// investigations, not a property of one case. A single JSON file in its own subdir next to `cases/`
// (a subdir, not a loose sibling, so it stays creatable when DFIR_CASES_ROOT is a drive-root child
// like C:\cases — Windows forbids files in a drive root).
//
// Secrets (HEC tokens, Elasticsearch passwords and API keys) live in this file; the routes redact
// them before they reach the browser. The list starts empty — the export is opt-in.

const splunkSchema = z.object({
  url: z.string(),
  token: z.string(),
  index: z.string().optional(),
  sourcetype: z.string().optional(),
});
const elasticSchema = z.object({
  url: z.string(),
  index: z.string(),
  username: z.string().optional(),
  password: z.string().optional(),
  apiKey: z.string().optional(),
});
const syslogSchema = z.object({
  host: z.string(),
  port: z.number(),
  protocol: z.enum(SYSLOG_PROTOCOLS),
  appName: z.string().optional(),
});

const destinationSchema = z.object({
  id: z.string(),
  type: z.enum(AUDIT_DESTINATION_TYPES),
  name: z.string().catch(""),
  // A destination persisted without the key predates nothing yet, but the default is OFF for the
  // same reason the notification channels' `milestone` toggle is: an unreadable or partial record
  // must never start pushing case detail to an external system on its own.
  enabled: z.boolean().catch(false),
  splunk: splunkSchema.optional(),
  elastic: elasticSchema.optional(),
  syslog: syslogSchema.optional(),
  createdAt: z.string().catch(""),
  updatedAt: z.string().catch(""),
});

export class AuditExportStore {
  // Serializes load->modify->save. atomicWrite stops a TORN file, not a LOST one: adding a
  // destination while another request disables one would drop whichever save landed first, and on
  // this file that means a destination the analyst turned OFF comes back ON and resumes forwarding
  // activity to an external system. Same reasoning as NotificationConfigStore (#682); the store is
  // global, so the lock is keyed by the file path.
  private readonly lock = new StateLock();

  constructor(private readonly file: string) {}

  async load(): Promise<AuditDestination[]> {
    try {
      const raw = JSON.parse(await readFile(this.file, "utf8")) as unknown;
      if (!Array.isArray(raw)) return [];
      // Re-validate on read so a hand-edited file cannot inject a malformed destination into a send.
      return raw
        .map((d) => {
          const parsed = destinationSchema.safeParse(d);
          return parsed.success ? parsed.data : null;
        })
        .filter((d): d is AuditDestination => d !== null);
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return [];
      throw err;
    }
  }

  private async persist(destinations: AuditDestination[]): Promise<void> {
    const dir = dirname(this.file);
    if (dir && !existsSync(dir)) await mkdir(dir, { recursive: true });
    await atomicWrite(this.file, JSON.stringify(destinations, null, 2));
  }

  async get(id: string): Promise<AuditDestination | null> {
    return (await this.load()).find((d) => d.id === id) ?? null;
  }

  add(draft: DestinationDraft, at: string = new Date().toISOString()): Promise<AuditDestination> {
    return this.lock.runExclusive(this.file, async () => {
      const destinations = await this.load();
      const base: AuditDestination = {
        id: randomUUID(),
        type: draft.type,
        name: draft.name,
        enabled: draft.enabled,
        createdAt: at,
        updatedAt: at,
      };
      const destination = applyDestinationPatch(base, draft, at);
      await this.persist([...destinations, destination]);
      return destination;
    });
  }

  update(
    id: string,
    draft: DestinationDraft,
    at: string = new Date().toISOString(),
  ): Promise<AuditDestination | null> {
    return this.lock.runExclusive(this.file, async () => {
      const destinations = await this.load();
      const idx = destinations.findIndex((d) => d.id === id);
      if (idx === -1) return null;
      const next = applyDestinationPatch(destinations[idx], draft, at);
      await this.persist(destinations.map((d, i) => (i === idx ? next : d)));
      return next;
    });
  }

  remove(id: string): Promise<boolean> {
    return this.lock.runExclusive(this.file, async () => {
      const destinations = await this.load();
      const next = destinations.filter((d) => d.id !== id);
      if (next.length === destinations.length) return false;
      await this.persist(next);
      return true;
    });
  }
}
