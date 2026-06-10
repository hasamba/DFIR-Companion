// Minimal typed client for the Notion REST API (https://developers.notion.com/reference).
// Auth is an internal-integration secret sent as a Bearer token; every request carries the
// pinned `Notion-Version` header. We use only the handful of endpoints an export needs:
// users/me (auth check), pages/databases retrieve, block children list/append, block update
// (archive), and page create.
//
// Like the IRIS/Timesketch/MISP clients, the HTTP transport is an injectable `fetchFn` so the
// orchestrator is unit-testable with no network, and a custom TLS trust can be supplied. The
// Companion writes ALL its content inside ONE managed container block it owns on the target
// page, so it can refresh that block on re-export without ever touching the investigators'
// own notes/screenshots — see notionPush.ts.

import type { FetchFn } from "../../enrichment/provider.js";
import type { NotionBlock } from "./notionBlocks.js";

// Notion's API version is pinned — Notion is explicit that the header selects the request/
// response schema, so we don't want it drifting under us.
export const NOTION_VERSION = "2022-06-28";
const NOTION_BASE = "https://api.notion.com";

export interface NotionClientOptions {
  token: string;            // internal-integration secret (ntn_… / secret_…)
  baseUrl?: string;         // default https://api.notion.com (override for tests/proxies)
  notionVersion?: string;   // default NOTION_VERSION
  fetchFn?: FetchFn;        // injectable transport (tests pass a mock; TLS-custom in prod)
  timeoutMs?: number;       // per-request timeout (default 60s — appends can be large)
}

// Parent for a newly-created page: either an existing page or a database row.
export type NotionParent = { page_id: string } | { database_id: string };

export interface NotionPageRef { id: string; url?: string }
export interface NotionBotUser { id?: string; name?: string }
// A block as we read it back: id, its type, whether it's archived (trashed), and the plain
// text of its label (for a toggle/heading — used to adopt a previous container by title).
export interface NotionBlockRef { id: string; type?: string; archived?: boolean; plainText?: string }

export class NotionApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly kind: "auth" | "permission" | "notfound" | "ratelimit" | "validation" | "http" | "network",
  ) {
    super(message);
    this.name = "NotionApiError";
  }
}

interface NotionErrorEnvelope { object?: string; status?: number; code?: string; message?: string }

// Pull the plain text out of a block's rich_text array (Notion nests it under the block's
// own type key, e.g. block.toggle.rich_text). Used so we can recognize a previous managed
// container by its title if the local store was lost.
function blockPlainText(block: Record<string, unknown>): string | undefined {
  const type = typeof block.type === "string" ? block.type : undefined;
  if (!type) return undefined;
  const body = block[type] as { rich_text?: Array<{ plain_text?: string; text?: { content?: string } }> } | undefined;
  const rich = body?.rich_text;
  if (!Array.isArray(rich)) return undefined;
  return rich.map((r) => r.plain_text ?? r.text?.content ?? "").join("");
}

function toBlockRef(b: Record<string, unknown>): NotionBlockRef {
  return {
    id: String(b.id ?? ""),
    type: typeof b.type === "string" ? b.type : undefined,
    archived: Boolean(b.archived),
    plainText: blockPlainText(b),
  };
}

export class NotionClient {
  private readonly fetchFn: FetchFn;
  private readonly base: string;
  private readonly version: string;
  private readonly timeoutMs: number;

  constructor(private readonly opts: NotionClientOptions) {
    this.fetchFn = opts.fetchFn ?? fetch;
    this.base = (opts.baseUrl ?? NOTION_BASE).replace(/\/+$/, "");
    this.version = opts.notionVersion ?? NOTION_VERSION;
    this.timeoutMs = opts.timeoutMs ?? 60_000;
  }

  // ---- transport -----------------------------------------------------------

  private async request<T>(
    method: "GET" | "POST" | "PATCH",
    path: string,
    opts: { body?: unknown; query?: Record<string, string>; retryOn429?: boolean } = {},
  ): Promise<T> {
    const url = new URL(this.base + path);
    for (const [k, v] of Object.entries(opts.query ?? {})) url.searchParams.set(k, v);

    let res: Response;
    try {
      res = await this.fetchFn(url.toString(), {
        method,
        headers: {
          Authorization: `Bearer ${this.opts.token}`,
          "Notion-Version": this.version,
          Accept: "application/json",
          ...(opts.body !== undefined ? { "content-type": "application/json" } : {}),
        },
        body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
        signal: AbortSignal.timeout(this.timeoutMs),
      });
    } catch (err) {
      throw new NotionApiError(`Notion request failed: ${(err as Error).message}`, 0, "network");
    }

    // Rate limited: honor Retry-After once, then give up (the orchestrator already paces appends).
    if (res.status === 429 && opts.retryOn429 !== false) {
      const retryAfter = Number(res.headers.get("retry-after")) || 1;
      await new Promise<void>((r) => setTimeout(r, Math.min(retryAfter, 10) * 1000));
      return this.request<T>(method, path, { ...opts, retryOn429: false });
    }

    if (!res.ok) {
      const env = (await res.json().catch(() => ({}))) as NotionErrorEnvelope;
      const detail = env.message ? `: ${env.message}` : "";
      if (res.status === 401) throw new NotionApiError(`Notion auth failed (check DFIR_NOTION_TOKEN)${detail}`, 401, "auth");
      if (res.status === 403) throw new NotionApiError(`Notion permission denied — share the page/database with the integration${detail}`, 403, "permission");
      if (res.status === 404) throw new NotionApiError(`Notion not found — share the page/database with the integration${detail}`, 404, "notfound");
      if (res.status === 429) throw new NotionApiError(`Notion rate limit hit${detail}`, 429, "ratelimit");
      if (res.status === 400) throw new NotionApiError(`Notion rejected the request${detail}`, 400, "validation");
      throw new NotionApiError(`Notion HTTP ${res.status} on ${path}${detail}`, res.status, "http");
    }
    return (await res.json().catch(() => ({}))) as T;
  }

  // ---- connectivity --------------------------------------------------------

  async me(): Promise<NotionBotUser> {
    const data = await this.request<Record<string, unknown>>("GET", "/v1/users/me");
    const bot = data.bot as { owner?: unknown } | undefined;
    return { id: String(data.id ?? ""), name: typeof data.name === "string" ? data.name : (bot ? "integration" : undefined) };
  }

  // ---- pages / databases ---------------------------------------------------

  async retrievePage(pageId: string): Promise<NotionPageRef> {
    const data = await this.request<Record<string, unknown>>("GET", `/v1/pages/${pageId}`);
    return { id: String(data.id ?? pageId), url: typeof data.url === "string" ? data.url : undefined };
  }

  // The title-type property's NAME for a database (varies per DB — often "Name", but not
  // always). Needed to create a row, because the page's title goes under that property.
  async databaseTitleProp(databaseId: string): Promise<string> {
    const data = await this.request<{ properties?: Record<string, { type?: string }> }>("GET", `/v1/databases/${databaseId}`);
    const props = data.properties ?? {};
    for (const [name, def] of Object.entries(props)) if (def?.type === "title") return name;
    return "Name"; // fall back to the Notion default if no title prop is reported
  }

  async createPage(parent: NotionParent, title: string): Promise<NotionPageRef> {
    let properties: Record<string, unknown>;
    if ("database_id" in parent) {
      const titleProp = await this.databaseTitleProp(parent.database_id);
      properties = { [titleProp]: { title: [{ text: { content: title } }] } };
    } else {
      properties = { title: { title: [{ text: { content: title } }] } };
    }
    const data = await this.request<Record<string, unknown>>("POST", "/v1/pages", { body: { parent, properties } });
    return { id: String(data.id ?? ""), url: typeof data.url === "string" ? data.url : undefined };
  }

  // ---- blocks --------------------------------------------------------------

  // Retrieve one block — returns null on 404 (so the caller can detect a managed container the
  // user deleted and recreate it). Other errors propagate.
  async retrieveBlock(blockId: string): Promise<NotionBlockRef | null> {
    try {
      const data = await this.request<Record<string, unknown>>("GET", `/v1/blocks/${blockId}`);
      return toBlockRef(data);
    } catch (err) {
      if (err instanceof NotionApiError && err.kind === "notfound") return null;
      throw err;
    }
  }

  // All direct children of a block (or page), paginated 100 at a time.
  async listChildren(blockId: string): Promise<NotionBlockRef[]> {
    const out: NotionBlockRef[] = [];
    let cursor: string | undefined;
    do {
      const query: Record<string, string> = { page_size: "100" };
      if (cursor) query.start_cursor = cursor;
      const data = await this.request<{ results?: Array<Record<string, unknown>>; has_more?: boolean; next_cursor?: string | null }>(
        "GET", `/v1/blocks/${blockId}/children`, { query },
      );
      for (const r of data.results ?? []) out.push(toBlockRef(r));
      cursor = data.has_more ? (data.next_cursor ?? undefined) : undefined;
    } while (cursor);
    return out;
  }

  // Append children to a block/page. Caller batches to ≤100 top-level blocks per call.
  async appendChildren(blockId: string, children: NotionBlock[]): Promise<NotionBlockRef[]> {
    const data = await this.request<{ results?: Array<Record<string, unknown>> }>(
      "PATCH", `/v1/blocks/${blockId}/children`, { body: { children } },
    );
    return (data.results ?? []).map(toBlockRef);
  }

  // Archive (Notion's reversible delete) a block — used to clear the managed container's
  // children before re-appending the latest content.
  async archiveBlock(blockId: string): Promise<void> {
    await this.request<unknown>("PATCH", `/v1/blocks/${blockId}`, { body: { archived: true } });
  }
}

// Extract a Notion page id (dashed UUID) from a raw id, a dashed UUID, or any Notion URL —
// `www.notion.so`, `notion.so`, or `app.notion.com`. The page id is the trailing 32-hex of the
// URL PATH; the query string is dropped first so a database-view id (`?v=…`) or tracking params
// (`?source=copy_link`, `?pvs=…`) are NEVER mistaken for the page id (a "Copy link" on a database
// row looks like `…/Title-<pageId>?v=<viewId>&source=copy_link`). A `#block` fragment is dropped
// too; a `?p=<id>` peek param is the fallback. Returns the dashed form Notion expects, or null.
// Pure — unit-tested.
export function parseNotionPageId(input: string): string | null {
  if (!input) return null;
  const noFragment = input.trim().split("#")[0];
  const qIdx = noFragment.indexOf("?");
  const path = qIdx >= 0 ? noFragment.slice(0, qIdx) : noFragment;
  const query = qIdx >= 0 ? noFragment.slice(qIdx + 1) : "";

  // 1. The normal shape: the id trails the PATH (…/Title-<id>, or a bare id / dashed UUID).
  const fromPath = extractNotionId(path);
  if (fromPath) return fromPath;

  // 2. Fall back to a `?p=<id>` peek-panel param (only `p` — never the `v` view id).
  const peek = /(?:^|&)p=([0-9a-fA-F-]{32,36})(?=&|$)/.exec(query);
  if (peek) return extractNotionId(peek[1]);

  return null;
}

// Find the last 32-hex (or dashed-UUID) run in a string and return it as a dashed UUID.
function extractNotionId(s: string): string | null {
  const dashed = s.match(/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}/);
  if (dashed) return toDashedUuid(dashed[0].replace(/-/g, ""));
  const hex = s.match(/[0-9a-fA-F]{32}/g);
  if (hex && hex.length) return toDashedUuid(hex[hex.length - 1]); // the id trails the path
  return null;
}

function toDashedUuid(hex32: string): string | null {
  const h = hex32.toLowerCase();
  if (!/^[0-9a-f]{32}$/.test(h)) return null;
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}
