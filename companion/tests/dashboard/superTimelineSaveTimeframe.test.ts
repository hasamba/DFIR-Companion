// "Save current range" must check the range before it asks for a name (#2067).
//
// saveTimeframe() used to prompt for a label and POST whatever the From/To inputs held. With both
// empty — the panel's default state — the server rejected the body with "start must be a valid
// date": a round trip and a wasted name prompt, ending in a message that names fields the analyst
// never saw (the inputs are labelled From and To). The client now refuses an incomplete or
// reversed range up front. The server check stays; it is the boundary.
import { describe, it, expect } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

interface SaveTimeframeApi {
  saveTimeframe: () => void;
}

const PRELOAD = ["dashboard-state.js", "dashboard-time.js"];

function harness(from: string, to: string) {
  const msg = { textContent: "", style: { color: "" } };
  const elements: Record<string, unknown> = {
    caseId: { value: "INC-1" },
    stFrom: { value: from },
    stTo: { value: to },
    stSaveMsg: msg,
  };
  const prompts: string[] = [];
  const fetches: { url: string; body: { label: string; start: string | null; end: string | null } }[] = [];
  const globals = {
    URLSearchParams,
    // superSaveMsg auto-clears after 5s; the vm sandbox has no timers, and the clear is not under test.
    setTimeout: () => 0,
    clearTimeout: () => {},
    document: { getElementById: (id: string) => elements[id] ?? null, addEventListener: () => {} },
    prompt: (text: string) => {
      prompts.push(text);
      return "Attacker session 1";
    },
    fetch: (url: string, init: { body: string }) => {
      fetches.push({ url, body: JSON.parse(init.body) });
      return new Promise(() => {}); // the response is not what these tests are about
    },
  };
  return {
    msg,
    prompts,
    fetches,
    api: loadDashboardModule<SaveTimeframeApi>("dashboard-super-timeline.js", PRELOAD, globals),
  };
}

describe("saving a named timeframe", () => {
  it("refuses an empty range before asking for a name", () => {
    const { api, msg, prompts, fetches } = harness("", "");
    api.saveTimeframe();
    expect(prompts).toHaveLength(0);
    expect(fetches).toHaveLength(0);
    expect(msg.textContent).toBe("Set both From and To before saving a timeframe");
    expect(msg.style.color).toBe("var(--badge-danger-text)");
  });

  it("refuses a range with From set and To empty", () => {
    const { api, msg, prompts, fetches } = harness("2026-01-01T10:00", "");
    api.saveTimeframe();
    expect(prompts).toHaveLength(0);
    expect(fetches).toHaveLength(0);
    expect(msg.textContent).toBe("Set both From and To before saving a timeframe");
  });

  it("refuses a range with To set and From empty", () => {
    const { api, msg, prompts, fetches } = harness("", "2026-01-01T10:00");
    api.saveTimeframe();
    expect(prompts).toHaveLength(0);
    expect(fetches).toHaveLength(0);
    expect(msg.textContent).toBe("Set both From and To before saving a timeframe");
  });

  it("refuses a range whose To is before its From", () => {
    const { api, msg, prompts, fetches } = harness("2026-01-02T10:00", "2026-01-01T10:00");
    api.saveTimeframe();
    expect(prompts).toHaveLength(0);
    expect(fetches).toHaveLength(0);
    expect(msg.textContent).toBe("To must be after From");
    expect(msg.style.color).toBe("var(--badge-danger-text)");
  });

  it("asks for a name and saves a valid range", () => {
    const { api, msg, prompts, fetches } = harness("2026-01-01T10:00", "2026-01-02T11:30");
    api.saveTimeframe();
    expect(prompts).toHaveLength(1);
    expect(fetches).toHaveLength(1);
    expect(fetches[0].url).toBe("/cases/INC-1/dwell-windows");
    expect(fetches[0].body).toEqual({
      label: "Attacker session 1",
      start: "2026-01-01T10:00:00.000Z",
      end: "2026-01-02T11:30:00.000Z",
    });
    expect(msg.textContent).toBe("");
  });

  it("accepts a zero-length range, which the server also accepts", () => {
    const { api, prompts, fetches } = harness("2026-01-01T10:00", "2026-01-01T10:00");
    api.saveTimeframe();
    expect(prompts).toHaveLength(1);
    expect(fetches).toHaveLength(1);
  });
});
