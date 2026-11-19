// #2647: the Watson panel's "Mirrored to Telegram" list. It shows the chats that mirror the case, each
// with an Off button, and offers no way to turn a chat on. Runs the real module in a vm context.
import { describe, expect, it } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

interface Mirror {
  watsonMirrorListHtml(list: unknown[]): string;
  watsonMirrorRefresh(caseId: string): Promise<void>;
  watsonMirrorOff(el: unknown): Promise<void>;
}

interface El {
  innerHTML: string;
  hidden: boolean;
}

function load(responses: Record<string, unknown>) {
  const calls: string[] = [];
  const slot: El = { innerHTML: "", hidden: true };
  const m = loadDashboardModule<Mirror>("dashboard-watson-mirror.js", ["dashboard-escape.js"], {
    document: {
      getElementById: (id: string) => (id === "caseId" ? { value: "c1" } : null),
      querySelectorAll: (sel: string) => (sel === '[data-w="mirrors"]' ? [slot] : []),
    },
    fetch: async (url: string, init?: { method?: string }) => {
      calls.push(`${init?.method ?? "GET"} ${url}`);
      const body = responses[url] ?? { ok: true };
      return { ok: true, json: async () => body };
    },
  });
  return { m, calls, slot };
}

const mirror = (over: Record<string, unknown> = {}) => ({
  chatId: "-100123",
  chatType: "supergroup",
  enabledAt: "2026-11-19T10:00:00.000Z",
  enabledBy: "555",
  held: false,
  pending: 0,
  ...over,
});

describe("Mirrored to Telegram list", () => {
  it("lists each chat with an Off button and no On control", () => {
    const { m } = load({});
    const html = m.watsonMirrorListHtml([mirror(), mirror({ chatId: "555", chatType: "private", held: true })]);
    expect(html).toContain("Mirrored to Telegram");
    expect(html.match(/data-w-verb="mirrorOff"/g)?.length).toBe(2);
    expect(html).toContain("Group -100123");
    expect(html).toContain("Private chat 555");
    expect(html).toContain("Held");
    expect(html).not.toMatch(/mirrorOn|>On</);
  });

  it("escapes what the server sent", () => {
    const { m } = load({});
    const html = m.watsonMirrorListHtml([mirror({ chatId: '"><img src=x onerror=1>' })]);
    expect(html).not.toContain("<img");
  });

  it("is empty and hidden when no chat mirrors the case", async () => {
    const { m, slot } = load({ "/cases/c1/watson/mirrors": { mirrors: [] } });
    await m.watsonMirrorRefresh("c1");
    expect(slot.hidden).toBe(true);
    expect(slot.innerHTML).toBe("");
  });

  it("switches a chat off and reloads the list", async () => {
    const { m, calls, slot } = load({ "/cases/c1/watson/mirrors": { mirrors: [mirror()] } });
    await m.watsonMirrorRefresh("c1");
    expect(slot.hidden).toBe(false);
    await m.watsonMirrorOff({ dataset: { chat: "-100123" }, disabled: false });
    expect(calls).toEqual([
      "GET /cases/c1/watson/mirrors",
      "POST /cases/c1/watson/mirrors/-100123/off",
      "GET /cases/c1/watson/mirrors",
    ]);
  });
});
