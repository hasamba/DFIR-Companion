import { describe, expect, it } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

// #1839: the Anonymization modal's Save replaces the whole custom-entity list. A stale window used
// to erase a value another window had just hidden. Save now sends the version it loaded; on a 409
// the modal reloads the list with the analyst's unsaved edits on top, and saves nothing.

type Entity = { value: string; category: string };
interface Api {
  rebaseAnonCustom(
    base: Entity[],
    working: Entity[],
    server: Entity[],
    max: number,
  ): { merged: Entity[]; kept: number; dropped: number; removed: string[] };
  loadAnonToggle(caseId: string): void;
  openAnonModal(): void;
  addCustomEntity(): void;
  saveAnon(): void;
}

const JANE = { value: "Jane Doe", category: "PERSON" };
const DC9 = { value: "DC9", category: "HOST" };
const SRV = { value: "SRV1", category: "HOST" };

function api(extra: Record<string, unknown> = {}) {
  return loadDashboardModule<Api>("dashboard-presidio.js", ["dashboard-escape.js"], extra);
}

describe("rebaseAnonCustom", () => {
  const rebase = api().rebaseAnonCustom;

  it("keeps additions and category changes on top of the other window's list", () => {
    const x = rebase([DC9], [{ value: "DC9", category: "OTHER" }, SRV], [DC9, JANE], 500);
    expect(x.merged).toEqual([{ value: "DC9", category: "OTHER" }, JANE, SRV]);
    expect(x.kept).toBe(2);
    expect(x.removed).toEqual([]);
  });

  // The stricter choice wins: the other window may have just hidden the value again.
  it("does not re-apply a removal of a value the server still hides, and names it", () => {
    const x = rebase([DC9, JANE], [DC9], [DC9, JANE], 500);
    expect(x.merged).toEqual([DC9, JANE]);
    expect(x.removed).toEqual(["Jane Doe"]);
  });

  it("counts an addition that does not fit a full list as dropped, not kept", () => {
    const x = rebase([], [SRV], [DC9, JANE], 2);
    expect(x.merged).toEqual([DC9, JANE]);
    expect(x.kept).toBe(0);
    expect(x.dropped).toBe(1);
  });
});

/** A stand-in DOM: every element exists and records what the module writes. */
function fakeDom() {
  const els: Record<string, Record<string, unknown>> = {};
  const el = (id: string) =>
    (els[id] ??= {
      id,
      value: id === "caseId" ? "INC-1" : "",
      checked: false,
      textContent: "",
      innerHTML: "",
      style: {},
      classList: { add() {}, remove() {}, toggle() {} },
      insertAdjacentHTML(_where: string, html: string) {
        this.innerHTML = String(this.innerHTML) + html;
      },
      querySelectorAll: () => [],
      setAttribute() {},
    });
  return { els, document: { getElementById: el, querySelectorAll: () => [] } };
}

// Every stubbed answer is an already-resolved promise, so one macrotask drains every chain.
const flush = () => new Promise((r) => setTimeout(r, 0));

describe("the modal's Save on a stale list (#1839)", () => {
  it("saves nothing, reloads the list with the analyst's edit kept, and saves from the new version next", async () => {
    const dom = fakeDom();
    const posts: { url: string; body: Record<string, unknown> }[] = [];
    let entityAnswers = [
      { status: 409, body: { error: "anon_entities_stale", custom: [DC9, JANE], customVersion: 2 } },
      { status: 200, body: { custom: [], customVersion: 3 } },
    ];
    const control = { enabled: true, categories: {}, redactSecrets: true, version: "v1" };
    const reply = (status: number, body: unknown) =>
      Promise.resolve({ ok: status < 300, status, json: () => Promise.resolve(body) });
    const m = api({
      document: dom.document,
      refreshAiState() {},
      fetch: (url: string, init?: { method?: string; body?: string }) => {
        if (init?.method === "POST") {
          const body = JSON.parse(init.body ?? "{}");
          posts.push({ url, body });
          if (url.endsWith("/anon-entities")) {
            const [a, ...rest] = entityAnswers;
            entityAnswers = rest;
            return reply(a.status, a.body);
          }
          return reply(200, { ...control, ...body });
        }
        if (url.endsWith("/anon-control")) return reply(200, control);
        if (url.endsWith("/anon-entities"))
          return reply(200, { auto: {}, custom: [DC9], customVersion: 1, suppressed: [] });
        return reply(200, { pending: [] });
      },
    });
    m.loadAnonToggle("INC-1");
    await flush();
    m.openAnonModal();
    await flush();
    dom.document.getElementById("anonCustVal").value = "SRV1";
    dom.document.getElementById("anonCustCat").value = "HOST";
    m.addCustomEntity();

    m.saveAnon();
    await flush();
    expect(posts.map((p) => p.url)).toEqual(["/cases/INC-1/anon-entities"]); // settings not sent
    expect(posts[0].body.version).toBe(1);
    expect(String(dom.els.anonMsg.textContent)).toContain("Nothing was saved");
    expect(String(dom.els.anonMsg.textContent)).toContain("1 unsaved change(s) of yours kept");
    const shown = String(dom.els.anonCustom.innerHTML);
    for (const v of ["DC9", "Jane Doe", "SRV1"]) expect(shown).toContain(v);

    m.saveAnon();
    await flush();
    const second = posts[1];
    expect(second.url).toBe("/cases/INC-1/anon-entities");
    expect(second.body.version).toBe(2);
    expect((second.body.entities as Entity[]).map((e) => e.value)).toEqual(["DC9", "Jane Doe", "SRV1"]);
    expect(posts[2].url).toBe("/cases/INC-1/anon-control");
    expect(posts[2].body.version).toBe("v1");
  });

  it("refuses to save before the list has loaded", async () => {
    const dom = fakeDom();
    const posts: string[] = [];
    const m = api({
      document: dom.document,
      fetch: (url: string, init?: { method?: string }) => {
        if (init?.method === "POST") posts.push(url);
        if (url.endsWith("/anon-control"))
          return Promise.resolve({
            ok: true,
            status: 200,
            json: () => Promise.resolve({ enabled: true, categories: {}, version: "v1" }),
          });
        return new Promise(() => {}); // the entity list never answers
      },
    });
    m.loadAnonToggle("INC-1");
    await flush();
    m.openAnonModal();
    m.saveAnon();
    await flush();
    expect(posts).toEqual([]);
    expect(String(dom.els.anonMsg.textContent)).toContain("has not loaded yet");
  });
});
