// Runtime accessor for Node's built-in `node:sqlite` (used by nsrlDb.ts to query the NSRL RDS).
//
// Why not a plain `import { DatabaseSync } from "node:sqlite"`? Two reasons:
//   1. Bundlers (Vitest/Vite) don't yet recognize this newer builtin — a static value import makes
//      them strip the `node:` prefix and fail to resolve a "sqlite" package.
//   2. `node:sqlite` only exists on Node 22.5+. A top-level value import would crash the server on
//      Node 20 (the project's floor) just because this module is in the import graph.
//
// So we load it LAZILY via `process.getBuiltinModule` (the documented, bundler-proof way to reach a
// builtin) and only when an NSRL RDS is actually opened — the type-only imports below are erased by
// the compiler, so the bundler never sees `node:sqlite` and old-Node startup never touches it.

import type { DatabaseSync as DatabaseSyncClass, StatementSync as StatementSyncType } from "node:sqlite";

export type SqliteDatabase = DatabaseSyncClass;
export type SqliteStatement = StatementSyncType;

type DatabaseSyncCtor = typeof DatabaseSyncClass;

let cached: DatabaseSyncCtor | null = null;

// Resolve the DatabaseSync constructor, or throw an actionable error when the runtime can't provide
// it (Node < 22.5). Callers (NsrlDb.open) surface the message; the flat store keeps working.
export function loadDatabaseSync(): DatabaseSyncCtor {
  if (cached) return cached;
  const getBuiltinModule = (process as unknown as { getBuiltinModule?: (id: string) => unknown }).getBuiltinModule;
  const mod = getBuiltinModule?.("node:sqlite") as { DatabaseSync?: DatabaseSyncCtor } | undefined;
  if (!mod?.DatabaseSync) {
    throw new Error("node:sqlite is unavailable — Node 22.5+ is required to query an NSRL RDS database");
  }
  cached = mod.DatabaseSync;
  return cached;
}
