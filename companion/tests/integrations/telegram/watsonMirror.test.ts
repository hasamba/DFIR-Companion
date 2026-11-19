import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { beforeEach, describe, expect, it } from "vitest";
import {
  HELD_TEXT,
  WatsonMirror,
  type MirrorLiveness,
  type MirrorMasking,
} from "../../../src/integrations/telegram/watsonMirror.js";
import { WatsonMirrorStore } from "../../../src/integrations/telegram/watsonMirrorStore.js";
import type { MirrorSendOutcome } from "../../../src/integrations/telegram/watsonMirrorSender.js";
import { workstationRoots } from "../../../src/integrations/telegram/watsonMirrorFormat.js";
import { emptyWatsonChat, type WatsonTurn } from "../../../src/analysis/ai/watson/types.js";

// #2647: the mirror service end to end against a fake Bot API, a fake clock and fake timers. Covers
// the batching window, immediate answers, holds, retries, revocation and restart resume.

const T0 = Date.parse("2026-11-19T10:00:00.000Z");
const iso = (ms: number) => new Date(ms).toISOString();

interface Harness {
  mirror: WatsonMirror;
  store: WatsonMirrorStore;
  sends: Array<{ chatId: string; text: string; at: number }>;
  audits: string[];
  live: WatsonTurn[];
  history: WatsonTurn[];
  clock: { now: number };
  outcomes: MirrorSendOutcome[];
  liveness: { value: MirrorLiveness };
  masking: { value: MirrorMasking };
  advance: (ms: number) => Promise<void>;
  addTurn: (t: Partial<WatsonTurn> & { role: WatsonTurn["role"] }) => WatsonTurn;
  newMirror: () => WatsonMirror;
}

let n = 0;

async function harness(): Promise<Harness> {
  const root = await mkdtemp(join(tmpdir(), "dfir-mirror-svc-"));
  const store = new WatsonMirrorStore(join(root, "notifications", "watson-mirror.json"));
  const clock = { now: T0 };
  const timers: Array<{ at: number; fn: () => void; live: boolean }> = [];
  const h = {
    store,
    sends: [],
    audits: [],
    live: [],
    history: [],
    clock,
    outcomes: [],
    liveness: { value: { ok: true } },
    masking: { value: { ok: true, mask: (t: string) => t.replace(/HOST-REAL/g, "HOST_1") } },
  } as unknown as Harness;
  const settle = async () => {
    await new Promise((r) => setImmediate(r));
    await h.mirror.idle();
  };
  h.newMirror = () =>
    new WatsonMirror({
      store,
      loadChat: async () => ({ ...emptyWatsonChat(), turns: h.live.slice(-3) }), // a small live window
      loadHistory: async () => h.history,
      liveness: async () => h.liveness.value,
      masking: async () => h.masking.value,
      send: async (chatId, text) => {
        h.sends.push({ chatId, text, at: clock.now });
        return h.outcomes.shift() ?? { kind: "sent", messageId: 1000 + h.sends.length };
      },
      audit: (_c, action, detail) => h.audits.push(`${action}: ${detail}`),
      roots: workstationRoots({ casesRoot: "/srv/dfir/cases", dataDir: "/srv/dfir", installDirs: [] }),
      publicUrl: () => undefined,
      log: { warn: () => {}, info: () => {}, error: () => {}, debug: () => {} } as never,
      now: () => clock.now,
      setTimer: (fn, ms) => {
        const t = { at: clock.now + ms, fn, live: true };
        timers.push(t);
        return () => {
          t.live = false;
        };
      },
      sleep: async (ms) => {
        clock.now += ms;
      },
    });
  h.mirror = h.newMirror();
  h.advance = async (ms: number) => {
    const end = clock.now + ms;
    await settle();
    for (;;) {
      const due = timers.filter((t) => t.live && t.at <= end).sort((a, b) => a.at - b.at)[0];
      if (!due) break;
      due.live = false;
      clock.now = Math.max(clock.now, due.at);
      due.fn();
      await settle();
    }
    clock.now = Math.max(clock.now, end);
  };
  h.addTurn = (t) => {
    const turn: WatsonTurn = { id: `wt-${++n}`, at: iso(clock.now), text: `turn ${n}`, ...t };
    h.live.push(turn);
    h.history.push(turn);
    return turn;
  };
  return h;
}

const enable = (h: Harness, chatId = "100", chatType = "private") =>
  h.store.enable(chatId, { caseId: "c1", chatType, by: "42", boundAt: "b1", at: iso(h.clock.now - 1) });

let h: Harness;
beforeEach(async () => {
  h = await harness();
});

describe("WatsonMirror", () => {
  it("sends nothing when no chat mirrors the case (AC1)", async () => {
    h.addTurn({ role: "analyst", text: "q" });
    await h.mirror.notify("c1");
    await h.advance(120_000);
    expect(h.sends).toEqual([]);
  });

  it("sends a dashboard question and Watson's answer at once, in chat order (AC2)", async () => {
    await enable(h);
    h.addTurn({ role: "analyst", actor: "ana", text: "what ran?" });
    await h.mirror.notify("c1");
    await h.advance(0);
    h.clock.now += 2_000;
    h.addTurn({ role: "watson", text: "PsExec ran on HOST-REAL" });
    await h.mirror.notify("c1");
    await h.advance(1_000);
    expect(h.sends.map((s) => s.text.split("\n")[0])).toEqual(["Analyst (ana):", "Watson:"]);
    expect(h.sends[1].text).toContain("HOST_1"); // re-masked
    expect(h.sends[1].text).not.toContain("HOST-REAL");
    expect(h.sends[1].at - T0).toBeLessThan(5_000);
  });

  it("only the chat that turned mirroring on receives (AC3)", async () => {
    await enable(h, "100");
    h.addTurn({ role: "analyst", text: "q" });
    await h.mirror.notify("c1");
    await h.advance(1_000);
    expect(new Set(h.sends.map((s) => s.chatId))).toEqual(new Set(["100"]));
  });

  it("batches 12 Auto turns over 3 minutes into at most 4 new messages with every turn (AC8)", async () => {
    await enable(h);
    for (let i = 0; i < 12; i++) {
      h.addTurn({ role: i % 2 ? "watson" : "system", text: `auto ${i}` });
      await h.mirror.notify("c1");
      await h.advance(15_000);
    }
    await h.advance(120_000);
    expect(h.sends.length).toBeLessThanOrEqual(4);
    const all = h.sends.map((s) => s.text).join("\n");
    for (let i = 0; i < 12; i++) expect(all).toContain(`auto ${i}`);
  });

  it("replaces workstation roots but keeps evidence paths (AC10)", async () => {
    await enable(h);
    h.addTurn({
      role: "analyst",
      text: String.raw`see /srv/dfir/cases/c1/imports/a.json and C:\Windows\Temp\x.ps1`,
    });
    await h.mirror.notify("c1");
    await h.advance(0);
    expect(h.sends[0].text).toContain("&lt;case&gt;/c1/imports/a.json");
    expect(h.sends[0].text).toContain(String.raw`C:\Windows\Temp\x.ps1`);
    expect(h.sends[0].text).not.toContain("/srv/dfir");
  });

  it("holds when masking fails, sends the Held notice once, and later turns wait (AC11)", async () => {
    await enable(h);
    h.masking.value = { ok: false, reason: "names await approval" };
    h.addTurn({ role: "analyst", text: "q1" });
    await h.mirror.notify("c1");
    await h.advance(0);
    h.addTurn({ role: "watson", text: "a1" });
    await h.mirror.notify("c1");
    await h.advance(120_000);
    expect(h.sends.map((s) => s.text.split("\n")[0])).toEqual([HELD_TEXT]);
    expect(h.audits.some((a) => a.startsWith("watson-mirror-held"))).toBe(true);
    h.masking.value = { ok: true, mask: (t) => t };
    await h.advance(60_000);
    expect(h.sends.length).toBe(2);
    expect(h.sends[1].text).toContain("q1");
    expect(h.sends[1].text).toContain("a1");
  });

  it("waits retry_after on a 429 (AC13)", async () => {
    await enable(h);
    h.outcomes.push({ kind: "rate_limited", retryAfterMs: 7_000 });
    h.addTurn({ role: "analyst", text: "q" });
    await h.mirror.notify("c1");
    await h.advance(6_000);
    expect(h.sends.length).toBe(1);
    await h.advance(2_000);
    expect(h.sends.length).toBe(2);
    expect(h.sends[1].at - h.sends[0].at).toBeGreaterThanOrEqual(7_000);
  });

  it("retries a 500 on the backoff schedule with no new Watson activity (AC13)", async () => {
    await enable(h);
    h.outcomes.push({ kind: "transient", reason: "HTTP 500" }, { kind: "transient", reason: "HTTP 500" });
    h.addTurn({ role: "analyst", text: "q" });
    await h.mirror.notify("c1");
    await h.advance(0);
    await h.advance(5_000);
    await h.advance(30_000);
    expect(h.sends.map((s) => s.at - h.sends[0].at)).toEqual([0, 5_000, 35_000]);
    expect((await h.store.get("100"))?.pending).toEqual([]);
  });

  it("switches a kicked chat off and logs it (AC13)", async () => {
    await enable(h);
    h.outcomes.push({ kind: "gone", reason: "Forbidden: bot was kicked" });
    h.addTurn({ role: "analyst", text: "q" });
    await h.mirror.notify("c1");
    await h.advance(0);
    expect(await h.store.get("100")).toBeUndefined();
    expect(h.audits.some((a) => a.startsWith("watson-mirror-auto-off") && a.includes("kicked"))).toBe(true);
    h.addTurn({ role: "analyst", text: "q2" });
    await h.mirror.notify("c1");
    await h.advance(60_000);
    expect(h.sends.length).toBe(1);
  });

  it("stops sending once the chat is unbound or the case is locked (AC14)", async () => {
    await enable(h);
    h.liveness.value = { ok: false, action: "disable", reason: "the chat was unbound" };
    h.addTurn({ role: "analyst", text: "q" });
    await h.mirror.notify("c1");
    await h.advance(60_000);
    expect(h.sends).toEqual([]);
    expect(await h.store.get("100")).toBeUndefined();
  });

  it("does not send a Telegram question back to the chat that asked it", async () => {
    await enable(h);
    h.mirror.expectEcho("100", "c1", "42 via telegram", "what ran?");
    h.addTurn({ role: "analyst", actor: "42 via telegram", text: "what ran?" });
    await h.mirror.notify("c1");
    await h.advance(0);
    h.addTurn({ role: "watson", text: "the beacon" });
    await h.mirror.notify("c1");
    await h.advance(1_000);
    expect(h.sends.length).toBe(1);
    expect(h.sends[0].text).toContain("the beacon");
    expect(h.sends[0].text).not.toContain("what ran?");
  });

  it("resumes after a restart: one duplicate at most, nothing lost, rotated turns read from history (AC12)", async () => {
    await enable(h);
    h.addTurn({ role: "analyst", text: "before crash" });
    await h.mirror.notify("c1");
    await h.advance(0);
    expect(h.sends.length).toBe(1);
    // A crash between send and mark: the turn is back in pending, not in sent.
    const e = (await h.store.get("100"))!;
    await h.store.disable("100");
    await h.store.enable("100", {
      caseId: "c1",
      chatType: "private",
      by: "42",
      boundAt: "b1",
      at: e.enabledAt,
      cursor: e.cursor,
    });
    await h.store.enqueue("100", [h.live[0].id], h.live[0].id);
    h.mirror.stop();
    // While down, five turns land; the live window (3) no longer holds the cursor.
    for (let i = 0; i < 5; i++) h.addTurn({ role: i === 0 ? "analyst" : "watson", text: `down ${i}` });
    h.mirror = h.newMirror();
    await h.mirror.start();
    await h.advance(1_000);
    const out = h.sends
      .slice(1)
      .map((s) => s.text)
      .join("\n");
    expect(out.match(/before crash/g)?.length).toBe(1);
    for (let i = 0; i < 5; i++) expect(out).toContain(`down ${i}`);
  });
});
