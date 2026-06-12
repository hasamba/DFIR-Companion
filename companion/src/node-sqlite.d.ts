// Minimal ambient types for Node's built-in `node:sqlite` (used by analysis/nsrlDb.ts to query the
// NSRL RDS SQLite database). The pinned @types/node (v20) predates `node:sqlite` (added in Node 22,
// available unflagged in our Node 24 runtime), so we declare only the surface we use rather than
// bumping @types/node a major version. Mirrors the existing tesseract-js.d.ts ambient-decl pattern.
// If @types/node is later bumped to a version that ships node:sqlite types, delete this file.
declare module "node:sqlite" {
  export interface StatementSync {
    get(...params: unknown[]): unknown;
    all(...params: unknown[]): unknown[];
    run(...params: unknown[]): { changes: number | bigint; lastInsertRowid: number | bigint };
  }

  export interface DatabaseSyncOptions {
    open?: boolean;
    readOnly?: boolean;
    enableForeignKeyConstraints?: boolean;
    enableDoubleQuotedStringLiterals?: boolean;
    allowExtension?: boolean;
  }

  export class DatabaseSync {
    constructor(location: string, options?: DatabaseSyncOptions);
    prepare(sql: string): StatementSync;
    exec(sql: string): void;
    open(): void;
    close(): void;
  }
}
