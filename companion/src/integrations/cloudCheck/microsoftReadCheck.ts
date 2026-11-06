// Microsoft read check (#2309). The ONLY calls it makes, all reads:
//
//   token for https://graph.microsoft.com/.default   the sign-in (app-only, certificate) — proves
//                                                    nothing about what the app may read
//   GET /v1.0/auditLogs/signIns?$top=1               one page of one entry → "entra-signins"
//   GET /v1.0/auditLogs/directoryAudits?$top=1       one page of one entry → "entra-directory-audits"
//
// The unified audit log is not tested: Graph's AuditLogQuery starts by CREATING a query, and the
// check makes no call that creates or changes anything.

import type { CloudFetch } from "../cloudTransport/cloudFetch.js";
import {
  CHECK_CALL_TIMEOUT_MS,
  sourceResult,
  type MicrosoftCheckSource,
  type SourceCheckResult,
} from "./readCheckTypes.js";
import { checkFailureReason } from "./readCheckWording.js";

export const GRAPH_BASE = "https://graph.microsoft.com/v1.0";

/** The read each source makes. */
export const GRAPH_CHECK_URLS: Readonly<Record<MicrosoftCheckSource, string>> = {
  "entra-signins": `${GRAPH_BASE}/auditLogs/signIns?$top=1`,
  "entra-directory-audits": `${GRAPH_BASE}/auditLogs/directoryAudits?$top=1`,
};

export interface MicrosoftCheckClients {
  /** A Graph access token for the app (the certificate sign-in). */
  getToken(): Promise<string>;
  fetch: CloudFetch;
}

export interface MicrosoftCheckInput {
  sources: MicrosoftCheckSource[];
  secrets: readonly string[];
}

/** A failed Graph answer as an error the reason builder reads: status, Graph code and message. */
class GraphError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = "GraphError";
  }
}

async function graphError(res: Response): Promise<GraphError> {
  try {
    const body = (await res.json()) as { error?: { code?: unknown; message?: unknown } };
    const code = typeof body.error?.code === "string" ? body.error.code : "";
    const message = typeof body.error?.message === "string" ? body.error.message : "";
    return new GraphError(res.status, code, message);
  } catch {
    return new GraphError(res.status, "", "");
  }
}

async function checkOne(
  clients: MicrosoftCheckClients,
  token: string,
  source: MicrosoftCheckSource,
  secrets: readonly string[],
): Promise<SourceCheckResult> {
  try {
    const res = await clients.fetch(GRAPH_CHECK_URLS[source], {
      method: "GET",
      headers: { Authorization: `Bearer ${token}`, Accept: "application/json" },
      signal: AbortSignal.timeout(CHECK_CALL_TIMEOUT_MS),
    });
    if (!res.ok) throw await graphError(res);
    await res.body?.cancel();
    return sourceResult(source, "succeeded");
  } catch (err) {
    return sourceResult(source, "failed", checkFailureReason(err, [...secrets, token]));
  }
}

/** Runs the Microsoft check: sign in, then one Graph read per selected source, in order. */
export async function runMicrosoftReadCheck(
  clients: MicrosoftCheckClients,
  input: MicrosoftCheckInput,
): Promise<SourceCheckResult[]> {
  let token: string;
  try {
    token = await clients.getToken();
  } catch (err) {
    const reason = `sign-in failed: ${checkFailureReason(err, input.secrets)}`;
    return input.sources.map((s) => sourceResult(s, "failed", reason));
  }
  const results: SourceCheckResult[] = [];
  for (const source of input.sources) results.push(await checkOne(clients, token, source, input.secrets));
  return results;
}
