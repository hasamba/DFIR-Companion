// The daily query budget of a shared cloud quota (#2312) — today, Microsoft's audit-log queries.
//
// Microsoft guarantees each tenant at least 200 audit query submissions per ROLLING 24 h, shared
// with every other tool on that tenant. This companion keeps its OWN count, per tenant id, in one
// file beside the cases root (never in a case folder): across jobs, cases, restarts, and accounts
// that name the same tenant. A collection checks the count before every submission and stops with
// "partial — budget used" rather than go past the operator's budget (DFIR_CLOUD_M365_QUERY_BUDGET).
//
// It is an ESTIMATE of this companion's own use — never "what the tenant has left": other tools
// spend from the same quota and nothing here can see them. A submission is counted before it is
// sent, so a crash over-counts (the safe side) and never under-counts.
//
// A reservation is reported only once it is DURABLE: temp file written and fsynced, renamed, the
// folder fsynced. A record that cannot be read or saved FAILS CLOSED — new submissions are refused
// with the file's path — and is never silently reset to a fresh count.

import { dirname, join } from "node:path";
import { DIR_FSYNC_UNSUPPORTED } from "../cloudAccounts/vaultKeyFile.js";
import { nodeCollectFs, type CollectFs } from "./collectFs.js";

export const QUOTA_WINDOW_MS = 24 * 3_600_000;
/** The per-tenant floor Microsoft documents for audit query submissions per rolling 24 h. */
export const MICROSOFT_TENANT_QUERY_FLOOR = 200;
/** This companion's share of it when DFIR_CLOUD_M365_QUERY_BUDGET is unset. */
export const DEFAULT_M365_QUERY_BUDGET = 50;

/** DFIR_CLOUD_M365_QUERY_BUDGET: a whole number 1–200; anything else is the default. */
export function parseQueryBudget(value: string | undefined): number {
  const n = Number(value?.trim());
  if (!Number.isInteger(n) || n < 1 || n > MICROSOFT_TENANT_QUERY_FLOOR) return DEFAULT_M365_QUERY_BUDGET;
  return n;
}

/** The usage file: `cloud-quota/` beside the cases root (`/data/cloud-quota` in the image). */
export function queryUsageFile(casesRoot: string): string {
  return join(dirname(casesRoot), "cloud-quota", "query-usage.json");
}

interface UsageFile {
  version: 1;
  scopes: Record<string, Array<{ at: number; n: number }>>;
}

/** What a collection draws on: one quota scope (a tenant) and the budget it may not pass. */
export interface QueryBudget {
  readonly scope: string;
  readonly limit: number;
  /** Count `n` submissions about to be sent; false (nothing counted) when that passes the budget. */
  reserve(n: number): Promise<boolean>;
  /** Submissions this companion counted under the scope in the last 24 h. */
  used(): Promise<number>;
}

function isEntry(e: unknown): boolean {
  const x = e as { at?: unknown; n?: unknown } | null;
  return !!x && Number.isFinite(x.at) && Number.isFinite(x.n);
}

function isUsage(value: unknown): value is UsageFile {
  const v = value as Partial<UsageFile> | null;
  if (!v || v.version !== 1 || !v.scopes || typeof v.scopes !== "object" || Array.isArray(v.scopes))
    return false;
  return Object.values(v.scopes).every((list) => Array.isArray(list) && list.every(isEntry));
}

/** The quota record cannot be read or saved: new submissions are refused (fail closed). */
export class QuotaRecordError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "QuotaRecordError";
  }
}

export interface QueryUsageStoreOptions {
  nowMs?: () => number;
  /** The filesystem; the tests inject faults at every persistence step. */
  fs?: CollectFs;
}

function errorCode(err: unknown): string {
  const code = (err as NodeJS.ErrnoException)?.code;
  return typeof code === "string" ? code : (err as Error)?.message?.slice(0, 120) || String(err);
}

export class QueryUsageStore {
  private chain: Promise<unknown> = Promise.resolve();
  private readonly nowMs: () => number;
  private readonly fs: CollectFs;

  constructor(
    private readonly file: string,
    options: QueryUsageStoreOptions = {},
  ) {
    this.nowMs = options.nowMs ?? (() => Date.now());
    this.fs = options.fs ?? nodeCollectFs;
  }

  /** Serialize every read-modify-write: two collections of one tenant may run at once. */
  private locked<T>(fn: () => Promise<T>): Promise<T> {
    const run = this.chain.then(fn, fn);
    this.chain = run.catch(() => {});
    return run;
  }

  private unreadable(): QuotaRecordError {
    return new QuotaRecordError(
      `quota record unreadable at ${this.file} — check or remove it. New Microsoft query ` +
        "submissions are refused until then (this companion cannot tell how many it has used).",
    );
  }

  private async load(): Promise<UsageFile> {
    let text: string;
    try {
      if (!(await this.fs.exists(this.file))) return { version: 1, scopes: {} };
      text = (await this.fs.readFile(this.file)).toString("utf8");
    } catch {
      throw this.unreadable();
    }
    try {
      const parsed: unknown = JSON.parse(text);
      if (isUsage(parsed)) return parsed;
    } catch {
      // fall through: fail closed, the file is left exactly as it is
    }
    throw this.unreadable();
  }

  /** Write tmp (fsynced) → rename → fsync the folder. Resolves only once the count is durable. */
  private async save(usage: UsageFile): Promise<void> {
    const dir = dirname(this.file);
    const tmp = `${this.file}.tmp`;
    try {
      await this.fs.mkdir(dir);
      await this.fs.writeFileSync(tmp, `${JSON.stringify(usage)}\n`);
      await this.fs.rename(tmp, this.file);
      try {
        await this.fs.fsyncDir(dir);
      } catch (err) {
        // A folder fsync the platform cannot do (Windows, some filesystems) is not a failure.
        if (!DIR_FSYNC_UNSUPPORTED.has((err as NodeJS.ErrnoException)?.code ?? "")) throw err;
      }
    } catch (err) {
      throw new QuotaRecordError(
        `quota record could not be saved at ${this.file} (${errorCode(err)}); the submission was not sent.`,
      );
    }
  }

  private recent(usage: UsageFile, scope: string): Array<{ at: number; n: number }> {
    const since = this.nowMs() - QUOTA_WINDOW_MS;
    return (usage.scopes[scope] ?? []).filter((e) => e.at > since);
  }

  async used(scope: string): Promise<number> {
    return this.locked(async () => this.recent(await this.load(), scope).reduce((t, e) => t + e.n, 0));
  }

  /** Count `n` submissions under `scope` unless that would pass `limit`. */
  async tryReserve(scope: string, n: number, limit: number): Promise<{ ok: boolean; used: number }> {
    return this.locked(async () => {
      const usage = await this.load();
      const recent = this.recent(usage, scope);
      const used = recent.reduce((t, e) => t + e.n, 0);
      if (used + n > limit) return { ok: false, used };
      const scopes: UsageFile["scopes"] = {};
      for (const key of Object.keys(usage.scopes)) {
        const kept = this.recent(usage, key);
        if (kept.length) scopes[key] = kept;
      }
      scopes[scope] = [...recent, { at: this.nowMs(), n }];
      await this.save({ version: 1, scopes });
      return { ok: true, used: used + n };
    });
  }

  budget(scope: string, limit: number): QueryBudget {
    return {
      scope,
      limit,
      reserve: async (n) => (await this.tryReserve(scope, n, limit)).ok,
      used: () => this.used(scope),
    };
  }
}

/** The reason a collection stopped on its budget — "used by this companion", never "remaining". */
export function budgetStopReason(used: number, limit: number): string {
  return (
    `partial — budget used: this companion has used ${used} of its ${limit} query submissions for ` +
    "this tenant in the last 24 h (estimate; other tools share the same tenant quota). Resume later."
  );
}
