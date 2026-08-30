// Minimal typed client for the Jira REST API v3 (Cloud) / v2 (Server/Data Center).
// Auth: email + API token (Cloud) or username + password (Server). The client is injected as a
// structural interface so pushJira.ts is unit-testable with no network (matching the IRIS/Notion
// integration pattern).

import type { FetchFn } from "../../enrichment/provider.js";
import { readBoundedJson, RESPONSE_SIZE_LIMITS, rethrowIfTooLarge } from "../../providers/boundedResponse.js";

export interface JiraClientOptions {
  baseUrl: string; // e.g. https://your-domain.atlassian.net
  user: string; // email (Cloud) or username (Server)
  token: string; // API token (Cloud) or password (Server)
  projectKey: string; // default project key, e.g. IR
  issueType?: string; // default issue type name, e.g. "Bug" or "Task"
  fetchFn?: FetchFn;
  timeoutMs?: number;
}

export interface JiraIssueBody {
  projectKey: string;
  summary: string;
  description?: string;
  issueType?: string;
  priority?: string; // e.g. "Highest", "High", "Medium", "Low", "Lowest"
  labels?: string[];
}

export interface JiraIssueRef {
  id: string;
  key: string;
  url?: string;
}

// Structural subset used by jiraPush.ts so tests can pass a lightweight mock.
export interface JiraClientLike {
  me(): Promise<{ id?: string; displayName?: string }>;
  createIssue(body: JiraIssueBody): Promise<JiraIssueRef>;
  updateIssue(idOrKey: string, body: JiraIssueBody): Promise<JiraIssueRef>;
}

export class JiraApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly kind: "auth" | "permission" | "notfound" | "ratelimit" | "validation" | "http" | "network",
  ) {
    super(message);
    this.name = "JiraApiError";
  }
}

interface JiraErrorEnvelope {
  errorMessages?: string[];
  errors?: Record<string, string>;
}

function jiraBaseUrl(raw: string): string {
  return raw.replace(/\/+$/, "");
}

function basicAuth(user: string, token: string): string {
  return "Basic " + Buffer.from(`${user}:${token}`).toString("base64");
}

export class JiraClient {
  private readonly fetchFn: FetchFn;
  private readonly base: string;
  private readonly timeoutMs: number;

  constructor(private readonly opts: JiraClientOptions) {
    this.fetchFn = opts.fetchFn ?? fetch;
    this.base = jiraBaseUrl(opts.baseUrl);
    this.timeoutMs = opts.timeoutMs ?? 30_000;
  }

  private async request<T>(method: "GET" | "POST" | "PUT", path: string, body?: unknown): Promise<T> {
    let res: Response;
    try {
      res = await this.fetchFn(this.base + path, {
        method,
        headers: {
          Authorization: basicAuth(this.opts.user, this.opts.token),
          Accept: "application/json",
          "Content-Type": "application/json",
        },
        body: body !== undefined ? JSON.stringify(body) : undefined,
        signal: AbortSignal.timeout(this.timeoutMs),
      });
    } catch (err) {
      throw new JiraApiError(`Jira request failed: ${(err as Error).message}`, 0, "network");
    }

    if (!res.ok) {
      const env = (await readBoundedJson(res, { maxBytes: RESPONSE_SIZE_LIMITS.json, context: "Jira" }).catch(
        () => ({}),
      )) as JiraErrorEnvelope;
      const detail = env.errorMessages?.join("; ") || Object.values(env.errors || {}).join("; ");
      const suffix = detail ? `: ${detail}` : "";
      if (res.status === 401)
        throw new JiraApiError(
          `Jira auth failed (check DFIR_JIRA_USER and DFIR_JIRA_TOKEN)${suffix}`,
          401,
          "auth",
        );
      if (res.status === 403) throw new JiraApiError(`Jira permission denied${suffix}`, 403, "permission");
      if (res.status === 404) throw new JiraApiError(`Jira resource not found${suffix}`, 404, "notfound");
      if (res.status === 429) throw new JiraApiError(`Jira rate limit hit${suffix}`, 429, "ratelimit");
      if (res.status === 400) throw new JiraApiError(`Jira rejected the request${suffix}`, 400, "validation");
      throw new JiraApiError(`Jira HTTP ${res.status} on ${path}${suffix}`, res.status, "http");
    }
    return (await readBoundedJson(res, { maxBytes: RESPONSE_SIZE_LIMITS.json, context: "Jira" }).catch(
      (err) => rethrowIfTooLarge(err, {}),
    )) as T;
  }

  async me(): Promise<{ id?: string; displayName?: string }> {
    const data = await this.request<{ accountId?: string; displayName?: string }>(
      "GET",
      "/rest/api/3/myself",
    );
    return { id: data.accountId, displayName: data.displayName };
  }

  // Shared field map. `project` and `issuetype` are creation-only: Jira rejects a project move on
  // update, and an issue-type change needs a separate transition on many workflows.
  private issueFields(body: JiraIssueBody, forUpdate: boolean): Record<string, unknown> {
    return {
      ...(forUpdate
        ? {}
        : {
            project: { key: body.projectKey },
            issuetype: { name: body.issueType || this.opts.issueType || "Task" },
          }),
      summary: body.summary,
      ...(body.description
        ? {
            description: {
              type: "doc",
              version: 1,
              content: [{ type: "paragraph", content: [{ type: "text", text: body.description }] }],
            },
          }
        : {}),
      ...(body.priority ? { priority: { name: body.priority } } : {}),
      ...(body.labels?.length ? { labels: body.labels } : {}),
    };
  }

  // The issue as a HUMAN opens it. Deliberately NOT the create response's `self`, which is the REST
  // resource (…/rest/api/3/issue/10001) — an analyst clicking that gets raw JSON.
  private browseUrl(key: string): string | undefined {
    return key ? `${this.base}/browse/${encodeURIComponent(key)}` : undefined;
  }

  async createIssue(body: JiraIssueBody): Promise<JiraIssueRef> {
    const data = await this.request<{ id?: string; key?: string }>("POST", "/rest/api/3/issue", {
      fields: this.issueFields(body, false),
    });
    const key = String(data.key ?? "");
    return { id: String(data.id ?? ""), key, url: this.browseUrl(key) };
  }

  // Jira answers a successful edit with 204 No Content, so the ref is rebuilt from what we already
  // knew (the caller merges it over the remembered ref to keep the id/url).
  async updateIssue(idOrKey: string, body: JiraIssueBody): Promise<JiraIssueRef> {
    const data = await this.request<{ id?: string; key?: string }>(
      "PUT",
      `/rest/api/3/issue/${encodeURIComponent(idOrKey)}`,
      { fields: this.issueFields(body, true) },
    );
    const key = String(data.key ?? idOrKey);
    return { id: String(data.id ?? ""), key, url: this.browseUrl(key) };
  }
}
