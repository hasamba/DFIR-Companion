import { describe, expect, it } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

/**
 * The push token is a standing credential for ONE case. The server stopped handing it back on a
 * GET, so the dashboard keeps the copy it was given in the 201 from /generate to fill the curl
 * example. That cache is the new place it can leak from, and it needs its own identity to be safe:
 * a bare string survived a switch to another case, so opening case B's settings rendered B's push
 * URL beside A's live token, ready to copy.
 *
 * Run in the vm sandbox rather than asserted against the source text, because "the token does not
 * appear in the rendered curl example" is a statement about what the code DOES.
 */
interface PushTokenApi {
  loadPushToken: (caseId?: string) => void;
  initPushToken: () => void;
}

interface El {
  textContent: string;
  innerHTML: string;
  disabled?: boolean;
  onclick?: () => void;
}

/** A GET response for a case, and the 201 the generate button gets back. */
interface Harness {
  api: PushTokenApi;
  curl: () => string;
  els: Record<string, El>;
  setCase: (id: string) => void;
  /** What the next GET /push-token returns. */
  getReturns: (body: unknown) => void;
  /** What the next POST /push-token/generate returns. */
  generateReturns: (body: unknown) => void;
}

function harness(): Harness {
  const els: Record<string, El> = {};
  for (const id of ["pushTokenInfo", "pushCurl", "pushTokenMsg", "pushTokenGenBtn", "pushTokenClearBtn"]) {
    els[id] = { textContent: "", innerHTML: "" };
  }
  let caseId = "";
  let getBody: unknown = null;
  let genBody: unknown = null;

  const api = loadDashboardModule<PushTokenApi>("dashboard-push-token.js", [], {
    document: { getElementById: (id: string) => els[id] ?? null },
    esc: (v: unknown) => String(v),
    veloCaseId: () => caseId,
    fetch: (url: string, init?: { method?: string }) =>
      Promise.resolve({
        ok: true,
        json: () => Promise.resolve(init?.method === "POST" ? genBody : getBody),
      }),
  });
  api.initPushToken();

  return {
    api,
    curl: () => els.pushCurl.textContent,
    els,
    setCase: (id) => void (caseId = id),
    getReturns: (b) => void (getBody = b),
    generateReturns: (b) => void (genBody = b),
  };
}

/** Let the fetch promise chains settle. */
const settle = (): Promise<void> => new Promise((r) => setImmediate(r));

const info = (caseId: string, createdAt: string) => ({
  configured: true,
  createdAt,
  globalConfigured: false,
  storeAvailable: true,
  pushUrl: `/cases/${caseId}/push`,
});

describe("dashboard push token — the generated key is scoped to its case", () => {
  it("shows the key it just generated, for the case it generated it in", async () => {
    const h = harness();
    h.setCase("alpha");
    h.generateReturns({ token: "AAAA1111", createdAt: "t1" });
    h.getReturns(info("alpha", "t1"));

    h.els.pushTokenGenBtn.onclick?.();
    await settle();

    expect(h.curl()).toContain("AAAA1111");
    expect(h.curl()).toContain("/cases/alpha/push");
  });

  it("does NOT carry that key over to a different case", async () => {
    const h = harness();
    h.setCase("alpha");
    h.generateReturns({ token: "AAAA1111", createdAt: "t1" });
    h.getReturns(info("alpha", "t1"));
    h.els.pushTokenGenBtn.onclick?.();
    await settle();
    expect(h.curl()).toContain("AAAA1111"); // precondition

    // The operator switches to case bravo, which has its own token generated elsewhere.
    h.setCase("bravo");
    h.getReturns(info("bravo", "t2"));
    h.api.loadPushToken("bravo");
    await settle();

    expect(h.curl()).toContain("/cases/bravo/push");
    expect(h.curl()).not.toContain("AAAA1111");
    expect(h.curl()).toContain("<your-token>");
  });

  it("drops the key once another session rotates it", async () => {
    const h = harness();
    h.setCase("alpha");
    h.generateReturns({ token: "AAAA1111", createdAt: "t1" });
    h.getReturns(info("alpha", "t1"));
    h.els.pushTokenGenBtn.onclick?.();
    await settle();

    // Someone else regenerates: same case, new createdAt, and the key we hold is dead.
    h.getReturns(info("alpha", "t9"));
    h.api.loadPushToken("alpha");
    await settle();

    expect(h.curl()).not.toContain("AAAA1111");
  });

  it("drops the key when the token is revoked", async () => {
    const h = harness();
    h.setCase("alpha");
    h.generateReturns({ token: "AAAA1111", createdAt: "t1" });
    h.getReturns(info("alpha", "t1"));
    h.els.pushTokenGenBtn.onclick?.();
    await settle();

    h.getReturns({ ...info("alpha", ""), configured: false });
    h.els.pushTokenClearBtn.onclick?.();
    await settle();

    expect(h.curl()).not.toContain("AAAA1111");
  });
});
