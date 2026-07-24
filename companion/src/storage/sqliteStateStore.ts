// SQLite-backed state store (#237). For very large cases whose investigation.json would exceed the
// ~512 MB in-memory string ceiling (StateStore.load throws ERR_STRING_TOO_LONG past ~900K events),
// this store persists the per-case InvestigationState in a SQLite database via Node's built-in
// `node:sqlite` (no native add-on, so it's SEA-safe like nsrlDb.ts). It implements the same
// (load, save) interface as StateStore, but the events/IOCs/findings live as indexed rows instead
// of one giant JSON blob, so a case of millions of events stays queryable and loadable.
//
// Schema (per-case DB at <stateDir>/investigation.sqlite):
//   events(id PK, case_id, timestamp, severity, description, asset, mitre_techniques JSON)
//   iocs(id PK, case_id, type, value, first_seen)
//   findings(id PK, case_id, title, severity, description, mitre_techniques JSON, status)
//   meta(case_id, key, value) — everything else on InvestigationState (narratives, threads,
//   timeline, techniques, key questions, next steps, uncertainties, exclude rules, updatedAt)
// The tables are upserted in a single transaction on save(); load() reconstructs the full
// InvestigationState by reading the rows back and merging the meta blob.

import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { existsSync } from "node:fs";
import type { CaseStore } from "./caseStore.js";
import { loadDatabaseSync, type SqliteDatabase } from "../analysis/sqliteRuntime.js";
import {
  type InvestigationState,
  type ForensicEvent,
  type IOC,
  type Finding,
  emptyState,
} from "../analysis/stateTypes.js";

const META_KEYS: Array<keyof InvestigationState> = [
  "caseId",
  "openThreads",
  "timeline",
  "mitreTechniques",
  "keyQuestions",
  "nextSteps",
  "uncertainties",
  "lastSummary",
  "attackerPath",
  "narrativeTimeline",
  "iocExcludeRules",
  "updatedAt",
];

export class SqliteStateStore {
  constructor(private readonly cases: CaseStore) {}

  private pathFor(caseId: string): string {
    return `${this.cases.stateDir(caseId)}/investigation.sqlite`;
  }

  private open(caseId: string): { db: SqliteDatabase; path: string } {
    const path = this.pathFor(caseId);
    const DatabaseSync = loadDatabaseSync();
    const dir = dirname(path);
    if (dir && !existsSync(dir)) {
      mkdirSync(dir);
    }
    const db = new DatabaseSync(path);
    this.init(db);
    return { db, path };
  }

  async load(caseId: string): Promise<InvestigationState> {
    const path = this.pathFor(caseId);
    if (!existsSync(path)) return emptyState(caseId);
    const { db } = this.open(caseId);
    try {
      const events = (db.prepare("SELECT * FROM events WHERE case_id = ? ORDER BY timestamp ASC").all(caseId) as Array<Record<string, unknown>>).map(rowToEvent);
      const iocs = (db.prepare("SELECT * FROM iocs WHERE case_id = ?").all(caseId) as Array<Record<string, unknown>>).map(rowToIoc);
      const findings = (db.prepare("SELECT * FROM findings WHERE case_id = ?").all(caseId) as Array<Record<string, unknown>>).map(rowToFinding);
      const metaRow = db.prepare("SELECT value FROM meta WHERE case_id = ? AND key = ?").get(caseId, "_state") as { value?: string } | undefined;
      let base: Partial<InvestigationState> = {};
      if (metaRow?.value) {
        try {
          base = JSON.parse(metaRow.value) as Partial<InvestigationState>;
        } catch {
          base = {};
        }
      }
      return {
        ...emptyState(caseId),
        ...base,
        caseId,
        forensicTimeline: events,
        iocs,
        findings,
      };
    } finally {
      db.close();
    }
  }

  async save(state: InvestigationState): Promise<void> {
    const { db } = this.open(state.caseId);
    try {
      db.exec("BEGIN");
      const upsertEvent = db.prepare(
        `INSERT INTO events (id, case_id, timestamp, severity, description, asset, mitre_techniques)
         VALUES (?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(id) DO UPDATE SET
           case_id=excluded.case_id, timestamp=excluded.timestamp, severity=excluded.severity,
           description=excluded.description, asset=excluded.asset, mitre_techniques=excluded.mitre_techniques`,
      );
      for (const e of state.forensicTimeline) {
        upsertEvent.run(
          e.id,
          state.caseId,
          e.timestamp,
          e.severity,
          e.description,
          e.asset ?? null,
          JSON.stringify(e.mitreTechniques ?? []),
        );
      }
      const upsertIoc = db.prepare(
        `INSERT INTO iocs (id, case_id, type, value, first_seen)
         VALUES (?, ?, ?, ?, ?)
         ON CONFLICT(id) DO UPDATE SET
           case_id=excluded.case_id, type=excluded.type, value=excluded.value, first_seen=excluded.first_seen`,
      );
      for (const i of state.iocs) {
        upsertIoc.run(i.id, state.caseId, i.type, i.value, i.firstSeen);
      }
      const upsertFinding = db.prepare(
        `INSERT INTO findings (id, case_id, title, severity, description, mitre_techniques, status)
         VALUES (?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(id) DO UPDATE SET
           case_id=excluded.case_id, title=excluded.title, severity=excluded.severity,
           description=excluded.description, mitre_techniques=excluded.mitre_techniques, status=excluded.status`,
      );
      for (const f of state.findings) {
        upsertFinding.run(
          f.id,
          state.caseId,
          f.title,
          f.severity,
          f.description,
          JSON.stringify(f.mitreTechniques ?? []),
          f.status,
        );
      }
      const meta: Partial<InvestigationState> = {};
      for (const k of META_KEYS) {
        (meta as Record<string, unknown>)[k as string] = state[k];
      }
      db.prepare(
        `INSERT INTO meta (case_id, key, value) VALUES (?, '_state', ?)
         ON CONFLICT(case_id, key) DO UPDATE SET value=excluded.value`,
      ).run(state.caseId, JSON.stringify(meta));
      db.exec("COMMIT");
    } catch (err) {
      try {
        db.exec("ROLLBACK");
      } catch {
        /* ignore */
      }
      throw err;
    } finally {
      db.close();
    }
  }

  private init(db: SqliteDatabase): void {
    db.exec(`
      CREATE TABLE IF NOT EXISTS events (
        id TEXT PRIMARY KEY,
        case_id TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        severity TEXT NOT NULL,
        description TEXT NOT NULL,
        asset TEXT,
        mitre_techniques TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS iocs (
        id TEXT PRIMARY KEY,
        case_id TEXT NOT NULL,
        type TEXT NOT NULL,
        value TEXT NOT NULL,
        first_seen TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS findings (
        id TEXT PRIMARY KEY,
        case_id TEXT NOT NULL,
        title TEXT NOT NULL,
        severity TEXT NOT NULL,
        description TEXT NOT NULL,
        mitre_techniques TEXT NOT NULL,
        status TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS meta (
        case_id TEXT NOT NULL,
        key TEXT NOT NULL,
        value TEXT NOT NULL,
        PRIMARY KEY (case_id, key)
      );
      CREATE INDEX IF NOT EXISTS idx_events_case_time ON events (case_id, timestamp);
      CREATE INDEX IF NOT EXISTS idx_events_case_severity ON events (case_id, severity);
    `);
  }
}

function rowToEvent(row: Record<string, unknown>): ForensicEvent {
  const techniques = parseJsonArray(row.mitre_techniques);
  return {
    id: String(row.id),
    timestamp: String(row.timestamp),
    description: String(row.description),
    severity: String(row.severity) as ForensicEvent["severity"],
    mitreTechniques: techniques,
    relatedFindingIds: [],
    sourceScreenshots: [],
    ...(row.asset != null ? { asset: String(row.asset) } : {}),
  };
}

function rowToIoc(row: Record<string, unknown>): IOC {
  return {
    id: String(row.id),
    type: String(row.type) as IOC["type"],
    value: String(row.value),
    firstSeen: String(row.first_seen),
  };
}

function rowToFinding(row: Record<string, unknown>): Finding {
  const techniques = parseJsonArray(row.mitre_techniques);
  return {
    id: String(row.id),
    title: String(row.title),
    severity: String(row.severity) as Finding["severity"],
    description: String(row.description),
    mitreTechniques: techniques,
    status: String(row.status) as Finding["status"],
    relatedIocs: [],
    sourceScreenshots: [],
    firstSeen: "",
    lastUpdated: "",
  };
}

function parseJsonArray(raw: unknown): string[] {
  if (typeof raw !== "string") return [];
  try {
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed.map((x) => String(x)) : [];
  } catch {
    return [];
  }
}

