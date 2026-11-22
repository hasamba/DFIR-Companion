// #2837 — editing a hypothesis, deleting one, and excluding or restoring one of its observations
// each sent a write and then ignored the answer: no `ok` check, body never read, empty catch. On a
// closed case the server refuses every one of them (423), so the control snapped back to the saved
// value with no message; on a lost connection it kept showing the value that was never saved.
// Each write now prints one line inside the affected card: the server's own sentence when it sent
// one, the status and the restart advice when it did not.
//
// The AI-off refusal, the Presidio hold and the duplicate-host hold are NOT fed to these routes:
// they make no AI call and are not host-gated, so the server cannot send them.
import { describe, expect, it } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

const RESTART = "restart the companion server";
const CLOSED = 'Case "case-1" is closed — reopen it before changing it';
// The card is markup, so the sentence is escaped on its way in (esc() in dashboard-escape.js).
const CLOSED_ESCAPED = "Case &quot;case-1&quot; is closed — reopen it before changing it";
// The sentence carries the case's own name, so it is adversary-controlled.
const HOSTILE = 'Case <img src=x onerror="alert(1)"> is closed';

interface Answer {
  status: number;
  /** The JSON body, or `undefined` for an answer with no JSON body (a 204, a stale server's 404). */
  body?: unknown;
}
/** What the write route does: an answer, or `"offline"` for a connection that is gone. */
type Outcome = Answer | "offline";

interface Api {
  loadHypotheses: (caseId: string) => void;
  hypPatch: (id: string, patch: Record<string, unknown>) => void;
  hypDelete: (id: string) => void;
  hypExcludeConfirm: (id: string, eventId: string) => void;
  hypRestoreEvidence: (id: string, eventId: string) => void;
}

interface El {
  value: string;
  textContent: string;
  innerHTML: string;
}

const HYPOTHESIS = { id: "h1", title: "RDP was the way in", status: "open", source: "analyst" };

const settle = () => new Promise((r) => setTimeout(r, 10));

/** A response that is strict about its body being read at most once. */
function response(answer: Answer) {
  let read = false;
  return {
    ok: answer.status >= 200 && answer.status < 300,
    status: answer.status,
    json: () => {
      if (read) return Promise.reject(new TypeError("body stream already read"));
      read = true;
      return answer.body === undefined
        ? Promise.reject(new SyntaxError("Unexpected end of JSON input"))
        : Promise.resolve(answer.body);
    },
  };
}

/** A page showing one hypothesis card, whose write routes answer with `page.write`. */
async function openPage(write: Outcome) {
  const els = new Map<string, El>();
  const el = (id: string): El => {
    const have = els.get(id);
    if (have) return have;
    const made: El = { value: "", textContent: "", innerHTML: "" };
    els.set(id, made);
    return made;
  };
  el("caseId").value = "case-1";
  const page = { write, listOffline: false, reloads: 0, writes: [] as string[] };
  // The exclusion's reason input lives inside the card; the module reaches it through the card.
  const reasonInput = { value: "duplicate of another row", placeholder: "" };
  const globals = {
    document: {
      getElementById: (id: string) => el(id),
      querySelector: () => ({ querySelector: () => reasonInput }),
      querySelectorAll: (): unknown[] => [],
      addEventListener: () => {},
    },
    CSS: { escape: (s: string) => s },
    fetch: (url: string, init?: { method?: string }) => {
      const method = init?.method ?? "GET";
      if (method === "GET") {
        page.reloads += 1;
        if (page.listOffline) return Promise.reject(new TypeError("Failed to fetch"));
        return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve([HYPOTHESIS]) });
      }
      page.writes.push(`${method} ${url}`);
      return page.write === "offline"
        ? Promise.reject(new TypeError("Failed to fetch"))
        : Promise.resolve(response(page.write));
    },
  };
  const api = loadDashboardModule<Api>(
    "dashboard-hypotheses.js",
    ["dashboard-escape.js", "dashboard-presidio.js"],
    globals,
  );
  api.loadHypotheses("case-1");
  await settle();
  const list = el("hypList");
  expect(list.innerHTML).toContain("RDP was the way in");
  page.reloads = 0;
  return { api, page, list };
}

type Page = Awaited<ReturnType<typeof openPage>>;

const WRITES = [
  {
    name: "edit",
    prefix: "not saved: ",
    sent: "PATCH /cases/case-1/hypotheses/h1",
    press: (p: Page) => p.api.hypPatch("h1", { status: "refuted" }),
  },
  {
    name: "delete",
    prefix: "not deleted: ",
    sent: "DELETE /cases/case-1/hypotheses/h1",
    press: (p: Page) => p.api.hypDelete("h1"),
  },
  {
    name: "evidence exclude",
    prefix: "not excluded: ",
    sent: "POST /cases/case-1/hypotheses/h1/exclusions",
    press: (p: Page) => p.api.hypExcludeConfirm("h1", "ev-1"),
  },
  {
    name: "evidence restore",
    prefix: "not restored: ",
    sent: "DELETE /cases/case-1/hypotheses/h1/exclusions/ev-1",
    press: (p: Page) => p.api.hypRestoreEvidence("h1", "ev-1"),
  },
] as const;

describe.each(WRITES)("hypothesis $name shows why the server refused (#2837)", (w) => {
  async function pressed(write: Outcome) {
    const p = await openPage(write);
    w.press(p);
    await settle();
    expect(p.page.writes).toEqual([w.sent]);
    return p;
  }

  it("a closed case (423): the server's sentence in the card, no status code, no restart advice", async () => {
    const p = await pressed({ status: 423, body: { error: CLOSED } });
    expect(p.list.innerHTML).toContain(
      `<div class="manual-msg" role="status">${w.prefix}${CLOSED_ESCAPED}</div>`,
    );
    expect(p.list.innerHTML).not.toContain(RESTART);
    expect(p.list.innerHTML).not.toContain("HTTP 423");
    // The reload is what puts the control back on the saved value.
    expect(p.page.reloads).toBe(1);
  });

  it("a refusal with no JSON body keeps the status and the restart advice", async () => {
    const p = await pressed({ status: 404 });
    expect(p.list.innerHTML).toContain(`${w.prefix}HTTP 404 — ${RESTART} if this 404s`);
  });

  it("a success with no body (204) shows no message and reloads the list", async () => {
    const p = await pressed({ status: 204 });
    expect(p.list.innerHTML).not.toContain(w.prefix);
    expect(p.list.innerHTML).not.toContain("manual-msg");
    expect(p.page.reloads).toBe(1);
  });

  it("a lost connection: a message in the card even though the reload fails too", async () => {
    const p = await openPage("offline");
    p.page.listOffline = true;
    p.list.innerHTML = "";
    w.press(p);
    await settle();
    // Re-rendered from the list already held, so the control shows the saved value again.
    expect(p.list.innerHTML).toContain("RDP was the way in");
    expect(p.list.innerHTML).toContain(`<div class="manual-msg" role="status">${w.prefix}`);
  });

  it("a hostile sentence lands as text, never as markup", async () => {
    const p = await pressed({ status: 423, body: { error: HOSTILE } });
    expect(p.list.innerHTML).toContain(
      `${w.prefix}Case &lt;img src=x onerror=&quot;alert(1)&quot;&gt; is closed`,
    );
    expect(p.list.innerHTML).not.toContain("<img");
  });
});

describe("the refusal line belongs to the card's state (#2837)", () => {
  it("survives a list reload, and goes once a write is accepted", async () => {
    const p = await openPage({ status: 423, body: { error: CLOSED } });
    p.api.hypPatch("h1", { notes: "checked the RDP logs" });
    await settle();
    expect(p.list.innerHTML).toContain("not saved: ");

    // A live `hypotheses_changed` push redraws the list; the reason must still be there.
    p.api.loadHypotheses("case-1");
    await settle();
    expect(p.list.innerHTML).toContain(`not saved: ${CLOSED_ESCAPED}`);

    p.page.write = { status: 200, body: { ...HYPOTHESIS, notes: "checked the RDP logs" } };
    p.api.hypPatch("h1", { notes: "checked the RDP logs" });
    await settle();
    expect(p.list.innerHTML).toContain("RDP was the way in");
    expect(p.list.innerHTML).not.toContain("not saved: ");
    expect(p.list.innerHTML).not.toContain("manual-msg");
  });

  it("does not follow the analyst into another case whose hypothesis has the same id", async () => {
    const p = await openPage({ status: 423, body: { error: CLOSED } });
    p.api.hypPatch("h1", { status: "refuted" });
    await settle();
    expect(p.list.innerHTML).toContain("not saved: ");

    p.api.loadHypotheses("case-2");
    await settle();
    expect(p.list.innerHTML).toContain("RDP was the way in");
    expect(p.list.innerHTML).not.toContain("not saved: ");
    expect(p.list.innerHTML).not.toContain("manual-msg");
  });

  it("a refused delete replaces an earlier refused edit's line, it does not stack", async () => {
    const p = await openPage({ status: 423, body: { error: CLOSED } });
    p.api.hypPatch("h1", { status: "refuted" });
    await settle();
    p.api.hypDelete("h1");
    await settle();
    expect(p.list.innerHTML).toContain(`not deleted: ${CLOSED_ESCAPED}`);
    expect(p.list.innerHTML).not.toContain("not saved: ");
  });
});
