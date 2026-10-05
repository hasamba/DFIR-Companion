import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

// #1952: on a case with anonymisation on, the server refuses an MCP run with 409 until the analyst
// acknowledges that MCP output reaches Claude Code unmasked. The panel shows the server's warning
// with a Continue control; Continue resends the same run carrying the acknowledgement, and Cancel
// sends nothing.

interface Api {
  initMcp(): void;
}

type El = Record<string, unknown> & {
  value: string;
  textContent: string;
  style: Record<string, string>;
  onclick?: () => unknown;
};

function fakeDom() {
  const els: Record<string, El> = {};
  const el = (id: string): El =>
    (els[id] ??= {
      id,
      value: "",
      checked: false,
      textContent: "",
      innerHTML: "",
      disabled: false,
      dataset: {},
      files: null,
      style: {},
      classList: { add() {}, remove() {}, toggle() {} },
      setAttribute() {},
    } as unknown as El);
  return { els, document: { getElementById: el, querySelectorAll: () => [] } };
}

const flush = () => new Promise((r) => setTimeout(r, 0));

function setup(answers: { status: number; body: unknown }[]) {
  const dom = fakeDom();
  const posts: { url: string; body: Record<string, unknown> }[] = [];
  const m = loadDashboardModule<Api>("dashboard-mcp.js", ["dashboard-escape.js"], {
    document: dom.document,
    setTimeout: () => 0, // the job watcher polls; nothing here needs it to
    fileToBase64: async () => "",
    mcpJobDuration: () => "",
    fetch: (url: string, init?: { method?: string; body?: string }) => {
      if (init?.method === "POST") {
        posts.push({ url, body: JSON.parse(init.body ?? "{}") });
        const a = answers.shift() ?? { status: 202, body: { ok: true, jobId: "j1" } };
        return Promise.resolve({ ok: a.status < 300, status: a.status, json: () => Promise.resolve(a.body) });
      }
      return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve({ jobs: [] }) });
    },
  });
  m.initMcp();
  dom.document.getElementById("caseId").value = "INC-1";
  dom.document.getElementById("mcpRunServer").value = "sift-mcp";
  dom.document.getElementById("mcpAgentPrompt").value = "investigate";
  return { dom, posts };
}

const REFUSAL = {
  status: 409,
  body: { error: "mcp_unmasked_ack_required", message: "MCP runs are not anonymized. Continue only if…" },
};

describe("the MCP panel asks before an unmasked run (#1952)", () => {
  it("shows the server's warning and a Continue control on the 409", async () => {
    const { dom, posts } = setup([REFUSAL]);
    await dom.els.mcpAgentBtn.onclick!();
    await flush();
    expect(posts).toHaveLength(1);
    expect(posts[0].body.ackUnmasked).toBeUndefined();
    expect(dom.els.mcpUnmaskedWarn.style.display).not.toBe("none");
    expect(dom.els.mcpUnmaskedText.textContent).toContain("not anonymized");
    expect(typeof dom.els.mcpUnmaskedContinueBtn.onclick).toBe("function");
  });

  it("Continue resends the same run with the acknowledgement", async () => {
    const { dom, posts } = setup([REFUSAL]);
    await dom.els.mcpAgentBtn.onclick!();
    await flush();
    dom.els.mcpUnmaskedContinueBtn.onclick!();
    await flush();
    expect(posts).toHaveLength(2);
    expect(posts[1].url).toBe(posts[0].url);
    expect(posts[1].body).toEqual({ ...posts[0].body, ackUnmasked: true });
    expect(dom.els.mcpUnmaskedWarn.style.display).toBe("none");
  });

  it("Cancel sends nothing and hides the warning", async () => {
    const { dom, posts } = setup([REFUSAL]);
    await dom.els.mcpAgentBtn.onclick!();
    await flush();
    dom.els.mcpUnmaskedCancelBtn.onclick!();
    await flush();
    expect(posts).toHaveLength(1);
    expect(dom.els.mcpUnmaskedWarn.style.display).toBe("none");
  });

  it("the page carries the warning block and a standing note", () => {
    const html = readFileSync(new URL("../../../public/dashboard.html", import.meta.url), "utf8");
    for (const id of ["mcpUnmaskedWarn", "mcpUnmaskedText", "mcpUnmaskedContinueBtn", "mcpUnmaskedCancelBtn"])
      expect(html).toContain(`id="${id}"`);
    const section = html.slice(html.indexOf('id="sec-mcp"'), html.indexOf('id="mcpRunJob"'));
    expect(section).toMatch(/not anonymi[sz]ed/i);
  });
});
