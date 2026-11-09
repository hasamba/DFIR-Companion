import { readFile } from "node:fs/promises";
import vm from "node:vm";
import { describe, expect, it } from "vitest";
import { pollFor } from "../helpers/poll.js";

// Runs admin.html's own inline script against a minimal fake DOM and fake API, so the test sees
// the token table the analyst sees, not a regex over the source.
type FakeEl = {
  innerHTML: string;
  textContent: string;
  className: string;
  hidden: boolean;
  value: string;
  options: unknown[];
  addEventListener: () => void;
};

function fakeElement(): FakeEl {
  return {
    innerHTML: "",
    textContent: "",
    className: "",
    hidden: false,
    value: "",
    options: [],
    addEventListener: () => {},
  };
}

async function renderTokens(tokens: unknown[]): Promise<{ tokens: string; message: FakeEl }> {
  const html = await readFile(new URL("../../../public/admin.html", import.meta.url), "utf8");
  const script = /<script nonce="__CSP_NONCE__">([\s\S]*?)<\/script>/.exec(html)?.[1];
  if (!script) throw new Error("admin.html inline script not found");
  const els = new Map<string, FakeEl>();
  const byId = (id: string): FakeEl => {
    if (!els.has(id)) els.set(id, fakeElement());
    return els.get(id) as FakeEl;
  };
  const responses: Record<string, unknown> = {
    "/auth/me": { authenticated: true, csrfToken: "c", identity: { globalRole: "administrator" } },
    "/auth/users": [],
    "/cases": [],
    "/auth/service-tokens": tokens,
    "/auth/sessions": [],
    "/auth/audit?limit=200": [],
  };
  const fetch = (path: string) =>
    Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(responses[path] ?? []) });
  const document = { getElementById: byId, querySelectorAll: () => [], addEventListener: () => {} };
  vm.runInNewContext(script, {
    document,
    fetch,
    location: {},
    setTimeout,
    Date,
    Promise,
    Object,
    Array,
    String,
  });
  const tokensHtml = await pollFor("the token table to render", () =>
    Promise.resolve(byId("tokens").innerHTML || null),
  );
  return { tokens: tokensHtml, message: byId("message") };
}

const base = { scope: "case", caseId: "INC-1", permissions: ["read"], expiresAt: null };

describe("Account & team service-token list", () => {
  it("shows a revoked token as revoked, with no Revoke button", async () => {
    const { tokens, message } = await renderTokens([
      { ...base, id: "live", name: "live token" },
      { ...base, id: "dead", name: "dead token", revokedAt: "2026-11-09T12:00:00.000Z" },
    ]);
    expect(message.textContent).toBe("");
    expect(tokens).toContain('data-token="live"');
    expect(tokens).not.toContain('data-token="dead"');
    expect(tokens).toContain("Revoked 2026-11-09T12:00:00.000Z");
    expect(tokens).toContain('class="revoked-row"');
  });
});
