import { describe, it, expect } from "vitest";
import { JiraClient } from "../../src/integrations/jira/jiraClient.js";
import type { FetchFn } from "../../src/enrichment/provider.js";

// Client-level coverage over a mocked fetch. The push-orchestrator tests hand back a hand-written
// `/browse/` url from their client mock, so they cannot catch the client deriving the wrong url
// from a REAL Jira response — these tests use the response shape Jira actually sends.

interface Recorded {
  url: string;
  method: string;
  body: unknown;
}

function mockFetch(responses: Array<{ status?: number; json?: unknown }>): {
  fetchFn: FetchFn;
  calls: Recorded[];
} {
  const calls: Recorded[] = [];
  let i = 0;
  const fetchFn = async (input: string | URL | Request, init?: RequestInit) => {
    const next = responses[Math.min(i, responses.length - 1)];
    i += 1;
    calls.push({
      url: String(input),
      method: String(init?.method ?? "GET"),
      body: typeof init?.body === "string" ? JSON.parse(init.body) : undefined,
    });
    const status = next.status ?? 200;
    return {
      ok: status >= 200 && status < 300,
      status,
      json: async () => next.json ?? {},
    } as unknown as Response;
  };
  return { fetchFn, calls };
}

function client(fetchFn: FetchFn, baseUrl = "https://jira.example.com"): JiraClient {
  return new JiraClient({ baseUrl, user: "analyst@example.com", token: "t0ken", projectKey: "IR", fetchFn });
}

describe("JiraClient issue urls", () => {
  it("links a created issue to the browse page, not the REST resource", async () => {
    // Exactly what POST /rest/api/3/issue answers with: `self` is the REST URL, which renders as
    // raw JSON in a browser.
    const { fetchFn } = mockFetch([
      { json: { accountId: "u1", displayName: "Analyst" } },
      { json: { id: "10001", key: "IR-42", self: "https://jira.example.com/rest/api/3/issue/10001" } },
    ]);
    const jira = client(fetchFn);
    await jira.me();
    const ref = await jira.createIssue({ projectKey: "IR", summary: "Suspicious PowerShell" });

    expect(ref.url).toBe("https://jira.example.com/browse/IR-42");
  });

  it("links an updated issue to the browse page too", async () => {
    // A successful edit answers 204 No Content, so the key comes from what the caller passed in.
    const { fetchFn } = mockFetch([{ status: 204 }]);
    const ref = await client(fetchFn).updateIssue("IR-42", {
      projectKey: "IR",
      summary: "Suspicious PowerShell",
    });

    expect(ref.key).toBe("IR-42");
    expect(ref.url).toBe("https://jira.example.com/browse/IR-42");
  });

  it("keeps the browse url on the configured host when the base url has a trailing slash", async () => {
    const { fetchFn } = mockFetch([
      { json: { id: "10001", key: "IR-7", self: "https://internal.example/rest/api/3/issue/10001" } },
    ]);
    const ref = await client(fetchFn, "https://jira.example.com/").createIssue({
      projectKey: "IR",
      summary: "x",
    });

    expect(ref.url).toBe("https://jira.example.com/browse/IR-7");
  });

  it("leaves the url unset when Jira answers without an issue key", async () => {
    const { fetchFn } = mockFetch([{ json: { id: "10001" } }]);
    const ref = await client(fetchFn).createIssue({ projectKey: "IR", summary: "x" });

    expect(ref.key).toBe("");
    expect(ref.url).toBeUndefined();
  });
});
