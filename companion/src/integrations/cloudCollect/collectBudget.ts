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

import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";

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

function isUsage(value: unknown): value is UsageFile {
  const v = value as Partial<UsageFile> | null;
  return !!v && v.version === 1 && !!v.scopes && typeof v.scopes === "object";
}

export class QueryUsageStore {
  private chain: Promise<unknown> = Promise.resolve();

  constructor(
    private readonly file: string,
    private readonly nowMs: () => number = () => Date.now(),
    private readonly onWarn: (message: string) => void = () => {},
  ) {}

  /** Serialize every read-modify-write: two collections of one tenant may run at once. */
  private locked<T>(fn: () => Promise<T>): Promise<T> {
    const run = this.chain.then(fn, fn);
    this.chain = run.catch(() => {});
    return run;
  }

  private async load(): Promise<UsageFile> {
    let text: string;
    try {
      text = await readFile(this.file, "utf8");
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return { version: 1, scopes: {} };
      throw err;
    }
    try {
      const parsed: unknown = JSON.parse(text);
      if (isUsage(parsed)) return parsed;
    } catch {
      // fall through: an unreadable file is kept aside, never silently overwritten
    }
    const aside = `${this.file}.unreadable-${this.nowMs()}`;
    await rename(this.file, aside);
    this.onWarn(`[cloud-collect] query usage file was unreadable; kept as ${aside} and started a new count`);
    return { version: 1, scopes: {} };
  }

  private async save(usage: UsageFile): Promise<void> {
    await mkdir(dirname(this.file), { recursive: true });
    const tmp = `${this.file}.tmp`;
    await writeFile(tmp, `${JSON.stringify(usage)}\n`);
    await rename(tmp, this.file);
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
