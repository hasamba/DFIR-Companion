// NSRL RDS SQLite backend (#63). The real NSRL Reference Data Set is distributed as a SQLite database
// (the "modern RDS minimal" format, RDS_*.db) — ~160 GB+, hundreds of millions of rows — NOT a flat
// hash list. It can't be held in memory as a Set, so instead of ingesting it we QUERY it on demand:
// an indexed point-lookup per hash. Read-only, via Node's built-in `node:sqlite` (no native add-on,
// so it's SEA-safe). Complements the flat in-memory NsrlStore (good for small custom lists); the
// server's match pass treats a hash as known-good if EITHER backend has it.
//
// We key lookups on **sha256 + md5** (what our forensic events/IOCs carry — see the matchers in
// nsrl.ts). The modern RDS METADATA base table carries both columns (plus sha1, which we don't use,
// so no sha1 index is needed). For speed the analyst must index the queried column(s) — see the NSRL
// setup section in companion/README.md.

import { loadDatabaseSync, type SqliteDatabase, type SqliteStatement } from "./sqliteRuntime.js";
import { readFile, mkdir, rm } from "node:fs/promises";
import { readFileSync, existsSync } from "node:fs";
import { dirname } from "node:path";
import { atomicWrite } from "../storage/atomicWrite.js";

// Hash columns we look up, with the hex length that identifies each. sha1 is intentionally excluded:
// our events/IOCs don't carry sha1, and indexing it on the full RDS wastes tens of GB.
const WANTED_COLUMNS = ["sha256", "md5"] as const;
const LEN_FOR_COLUMN: Record<string, number> = { sha256: 64, md5: 32 };

interface ColumnQuery {
  column: string; // the column's real name/case in the DB
  stmt: SqliteStatement; // prepared `SELECT 1 ... WHERE col = ? LIMIT 1`
  upper: boolean; // values stored uppercase? (bind in that case so the equality uses the index)
}

export interface NsrlDbStatus {
  connected: boolean;
  path?: string;
  table?: string;
  columns?: string[]; // hash columns in use, e.g. ["sha256","md5"]
}

export class NsrlDb {
  private constructor(
    private readonly db: SqliteDatabase,
    readonly path: string,
    readonly table: string,
    private readonly byLength: Map<number, ColumnQuery>,
    readonly columns: string[],
  ) {}

  // Open the RDS DB read-only and prepare per-column lookups. Throws when the file can't be opened or
  // has no usable sha256/md5 column (so callers can surface an actionable error). The caller owns
  // close().
  static open(path: string): NsrlDb {
    const DatabaseSync = loadDatabaseSync();
    const db = new DatabaseSync(path, { readOnly: true });
    try {
      const table = detectHashTable(db);
      if (!table) {
        throw new Error("no table with a sha256 or md5 column — point this at the modern NSRL RDS (METADATA table)");
      }
      const byLength = new Map<number, ColumnQuery>();
      const columns: string[] = [];
      for (const col of hashColumnsOf(db, table)) {
        const length = LEN_FOR_COLUMN[col.toLowerCase()];
        const stmt = db.prepare(`SELECT 1 AS x FROM "${table}" WHERE "${col}" = ? LIMIT 1`);
        byLength.set(length, { column: col, stmt, upper: sampleIsUpper(db, table, col) });
        columns.push(col.toLowerCase());
      }
      if (byLength.size === 0) throw new Error("no sha256/md5 column found");
      return new NsrlDb(db, path, table, byLength, columns);
    } catch (err) {
      db.close();
      throw err;
    }
  }

  // Is this already-normalized (lowercased) hash known-good? Routes to the column matching its hex
  // length and binds in the DB's stored case so the equality hits the column index.
  has(normalizedHash: string): boolean {
    const q = this.byLength.get(normalizedHash.length);
    if (!q) return false;
    const value = q.upper ? normalizedHash.toUpperCase() : normalizedHash;
    return q.stmt.get(value) !== undefined;
  }

  // Bound predicate for the matchers in nsrl.ts.
  readonly lookup = (hash: string): boolean => this.has(hash);

  status(): NsrlDbStatus {
    return { connected: true, path: this.path, table: this.table, columns: this.columns };
  }

  close(): void {
    try {
      this.db.close();
    } catch {
      /* already closed */
    }
  }
}

// Pick the table holding a sha256/md5 column. Prefer a base TABLE named METADATA (in the modern RDS,
// FILE is a view over METADATA — querying the base table is what uses the index), then any base
// table, then views.
function detectHashTable(db: SqliteDatabase): string | null {
  const rows = db.prepare("SELECT name, type FROM sqlite_master WHERE type IN ('table','view')").all() as Array<{ name: string; type: string }>;
  const ordered = [...rows].sort((a, b) => rankTable(b) - rankTable(a));
  for (const r of ordered) {
    if (hashColumnsOf(db, r.name).length > 0) return r.name;
  }
  return null;
}

function rankTable(r: { name: string; type: string }): number {
  let n = r.type === "table" ? 2 : 0; // prefer base tables over views
  if (r.name.toUpperCase() === "METADATA") n += 4; // prefer the canonical RDS table
  return n;
}

// The sha256/md5 column names actually present in `table` (preserving their real case for queries).
function hashColumnsOf(db: SqliteDatabase, table: string): string[] {
  const cols = db.prepare(`SELECT name FROM pragma_table_info('${table.replace(/'/g, "''")}')`).all() as Array<{ name: string }>;
  const byLower = new Map(cols.map((c) => [c.name.toLowerCase(), c.name]));
  const out: string[] = [];
  for (const want of WANTED_COLUMNS) {
    const actual = byLower.get(want);
    if (actual) out.push(actual);
  }
  return out;
}

// Sample one value to learn the stored case (NSRL RDS stores hashes uppercase; default to that).
function sampleIsUpper(db: SqliteDatabase, table: string, col: string): boolean {
  try {
    const row = db.prepare(`SELECT "${col}" AS v FROM "${table}" WHERE "${col}" IS NOT NULL LIMIT 1`).get() as { v?: unknown } | undefined;
    const v = row?.v;
    if (typeof v === "string" && v) return v === v.toUpperCase();
  } catch {
    /* fall through to the convention */
  }
  return true;
}

// ── DB-path persistence (so a UI-set path survives a restart) ──────────────────────────────────
// A tiny text file next to the flat store (nsrl/db-path.txt). The DFIR_NSRL_DB env var, when set,
// takes precedence and makes the path env-managed (the UI connect is then read-only).

export function loadNsrlDbPath(file: string): string {
  try {
    return readFileSync(file, "utf8").trim();
  } catch {
    return "";
  }
}

export async function saveNsrlDbPath(file: string, path: string): Promise<void> {
  const dir = dirname(file);
  if (dir && !existsSync(dir)) await mkdir(dir, { recursive: true });
  await atomicWrite(file, path.trim() + "\n");
}

export async function removeNsrlDbPath(file: string): Promise<void> {
  try {
    await rm(file);
  } catch {
    /* already gone */
  }
}

// Async variant of loadNsrlDbPath (parity with the other stores; the startup path uses the sync one).
export async function readNsrlDbPath(file: string): Promise<string> {
  try {
    return (await readFile(file, "utf8")).trim();
  } catch {
    return "";
  }
}
