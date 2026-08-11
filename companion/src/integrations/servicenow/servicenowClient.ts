// Minimal typed client for the ServiceNow REST API (Table API). Auth: Basic auth with user +
// password. Creates incidents by default; the table name can be overridden via options.

import type { FetchFn } from "../../enrichment/provider.js";

export interface ServiceNowClientOptions {
  baseUrl: string; // e.g. https://instance.service-now.com
  user: string;
  password: string;
  table?: string; // default "incident"
  fetchFn?: FetchFn;
  timeoutMs?: number;
}

export interface ServiceNowIncidentBody {
  shortDescription: string;
  description?: string;
  urgency?: number; // 1=High, 2=Medium, 3=Low
  impact?: number; // 1=High, 2=Medium, 3=Low
  caller?: string; // sys_id or email of the caller (optional)
  category?: string;
  subcategory?: string;
}

export interface ServiceNowIncidentRef {
  id: string;
  number: string;
  url?: string;
}

// Structural subset used by servicenowPush.ts so tests can pass a lightweight mock.
export interface ServiceNowClientLike {
  me(): Promise<{ userId?: string; userName?: string }>;
  createIncident(body: ServiceNowIncidentBody): Promise<ServiceNowIncidentRef>;
  updateIncident(sysId: string, body: ServiceNowIncidentBody): Promise<ServiceNowIncidentRef>;
}

export class ServiceNowApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly kind: "auth" | "permission" | "notfound" | "ratelimit" | "validation" | "http" | "network",
  ) {
    super(message);
    this.name = "ServiceNowApiError";
  }
}

interface ServiceNowErrorEnvelope {
  error?: { message?: string; detail?: string };
}

function snowBaseUrl(raw: string): string {
  return raw.replace(/\/+$/, "");
}

function basicAuth(user: string, password: string): string {
  return "Basic " + Buffer.from(`${user}:${password}`).toString("base64");
}

export class ServiceNowClient {
  private readonly fetchFn: FetchFn;
  private readonly base: string;
  private readonly timeoutMs: number;
  private readonly table: string;

  constructor(private readonly opts: ServiceNowClientOptions) {
    this.fetchFn = opts.fetchFn ?? fetch;
    this.base = snowBaseUrl(opts.baseUrl);
    this.timeoutMs = opts.timeoutMs ?? 30_000;
    this.table = opts.table ?? "incident";
  }

  private async request<T>(
    method: "GET" | "POST" | "PUT" | "PATCH",
    path: string,
    body?: unknown,
  ): Promise<T> {
    let res: Response;
    try {
      res = await this.fetchFn(this.base + path, {
        method,
        headers: {
          Authorization: basicAuth(this.opts.user, this.opts.password),
          Accept: "application/json",
          "Content-Type": "application/json",
        },
        body: body !== undefined ? JSON.stringify(body) : undefined,
        signal: AbortSignal.timeout(this.timeoutMs),
      });
    } catch (err) {
      throw new ServiceNowApiError(`ServiceNow request failed: ${(err as Error).message}`, 0, "network");
    }

    if (!res.ok) {
      const env = (await res.json().catch(() => ({}))) as ServiceNowErrorEnvelope;
      const detail = env.error?.message || env.error?.detail;
      const suffix = detail ? `: ${detail}` : "";
      if (res.status === 401)
        throw new ServiceNowApiError(
          `ServiceNow auth failed (check DFIR_SERVICENOW_USER and DFIR_SERVICENOW_PASSWORD)${suffix}`,
          401,
          "auth",
        );
      if (res.status === 403)
        throw new ServiceNowApiError(`ServiceNow permission denied${suffix}`, 403, "permission");
      if (res.status === 404)
        throw new ServiceNowApiError(`ServiceNow resource not found${suffix}`, 404, "notfound");
      if (res.status === 429)
        throw new ServiceNowApiError(`ServiceNow rate limit hit${suffix}`, 429, "ratelimit");
      if (res.status === 400)
        throw new ServiceNowApiError(`ServiceNow rejected the request${suffix}`, 400, "validation");
      throw new ServiceNowApiError(`ServiceNow HTTP ${res.status} on ${path}${suffix}`, res.status, "http");
    }
    return (await res.json().catch(() => ({}))) as T;
  }

  async me(): Promise<{ userId?: string; userName?: string }> {
    const data = await this.request<{ result?: Array<{ sys_id?: string; user_name?: string }> }>(
      "GET",
      `/api/now/v2/table/sys_user?sysparm_query=user_name%3D${encodeURIComponent(this.opts.user)}&sysparm_limit=1`,
    );
    const first = data.result?.[0];
    return { userId: first?.sys_id, userName: first?.user_name };
  }

  private incidentPayload(body: ServiceNowIncidentBody): Record<string, unknown> {
    return {
      short_description: body.shortDescription,
      ...(body.description ? { description: body.description } : {}),
      ...(body.urgency !== undefined ? { urgency: body.urgency } : {}),
      ...(body.impact !== undefined ? { impact: body.impact } : {}),
      ...(body.caller ? { caller_id: body.caller } : {}),
      ...(body.category ? { category: body.category } : {}),
      ...(body.subcategory ? { subcategory: body.subcategory } : {}),
    };
  }

  private incidentRef(
    result: { sys_id?: string; number?: string },
    fallbackSysId = "",
  ): ServiceNowIncidentRef {
    const sysId = String(result.sys_id ?? fallbackSysId);
    return {
      id: sysId,
      number: String(result.number ?? ""),
      url: `${this.base}/${this.table}.do?sys_id=${sysId}`,
    };
  }

  async createIncident(body: ServiceNowIncidentBody): Promise<ServiceNowIncidentRef> {
    const data = await this.request<{ result?: { sys_id?: string; number?: string } }>(
      "POST",
      `/api/now/table/${encodeURIComponent(this.table)}`,
      this.incidentPayload(body),
    );
    return this.incidentRef(data.result ?? {});
  }

  async updateIncident(sysId: string, body: ServiceNowIncidentBody): Promise<ServiceNowIncidentRef> {
    const data = await this.request<{ result?: { sys_id?: string; number?: string } }>(
      "PATCH",
      `/api/now/table/${encodeURIComponent(this.table)}/${encodeURIComponent(sysId)}`,
      this.incidentPayload(body),
    );
    return this.incidentRef(data.result ?? {}, sysId);
  }
}
