import { describe, expect, it } from "vitest";
import { AnonControlStore } from "../../../src/analysis/anonControl.js";
import { ROSTER_FULL_NOTE } from "../../../src/analysis/ai/watson/roundHop.js";
import { maskRosterFull, WATSON_MASK_ROSTER_MAX } from "../../../src/analysis/ai/watson/superRoster.js";
import { CASE, harness, lastWatsonTurn, raw, reply, superLookup } from "./superPromoteFixtures.js";

// Final review H5 (controller ruling): a masking roster name is never evicted, because Watson's
// memory and chat history can still carry it in clear. When a super-timeline search would need more
// names than the roster holds, the search is refused for that round. Nothing is sent unmasked.

const hosts = (n: number) => Array.from({ length: n }, (_, i) => `oldhost${i}`);

async function anonymized(h: Awaited<ReturnType<typeof harness>>) {
  const anon = new AnonControlStore(h.deps.cases!);
  await anon.save(CASE, { ...(await anon.load(CASE)), enabled: true });
}

describe("a full masking roster refuses the super-timeline search (H5)", () => {
  it("Codex repro: an old name in memory stays masked, the new rows are never sent", async () => {
    const h = await harness([reply(superLookup()), reply()], {
      raw: [raw("raw1", { asset: "NEWHOST-9" })],
    });
    await anonymized(h);
    await h.chatStore.update(CASE, (c) => ({
      ...c,
      memory: "Memory: cedar had the evidence",
      maskRoster: { hosts: ["cedar", ...hosts(WATSON_MASK_ROSTER_MAX - 1)], users: [], ips: [] },
    }));
    const chat = await h.run();
    expect(h.provider.sent).toHaveLength(1);
    const wire = h.provider.sent.map((r) => r.userPrompt).join("\n");
    expect(wire).not.toMatch(/cedar|NEWHOST-9/i);
    const turn = lastWatsonTurn(chat);
    expect(turn.text).toContain(ROSTER_FULL_NOTE);
    expect(turn.lookedUp).toBeUndefined();
    expect(chat.maskRoster?.hosts).toContain("cedar");
    expect(chat.maskRoster?.hosts).not.toContain("newhost-9");
  });

  it("anonymization off: the search runs on a full roster, and the roster still records the new name", async () => {
    const h = await harness([reply(superLookup()), reply()], {
      raw: [raw("raw1", { asset: "NEWHOST-9" })],
    });
    await h.chatStore.update(CASE, (c) => ({
      ...c,
      maskRoster: { hosts: hosts(WATSON_MASK_ROSTER_MAX), users: [], ips: [] },
    }));
    const chat = await h.run();
    expect(h.provider.sent).toHaveLength(2);
    expect(lastWatsonTurn(chat).text).not.toContain(ROSTER_FULL_NOTE);
    expect(lastWatsonTurn(chat).lookedUp?.shownIds).toEqual(["raw1"]);
    expect(chat.maskRoster?.hosts).toContain("newhost-9");
    expect(chat.maskRoster?.hosts).toHaveLength(WATSON_MASK_ROSTER_MAX + 1);
  });

  it("the search runs when the rows add no new name to a full roster", async () => {
    const h = await harness([reply(superLookup()), reply()], { raw: [raw("raw1", { asset: "HOST-A" })] });
    await h.chatStore.update(CASE, (c) => ({
      ...c,
      maskRoster: { hosts: ["host-a", ...hosts(WATSON_MASK_ROSTER_MAX - 1)], users: [], ips: [] },
    }));
    const chat = await h.run();
    expect(h.provider.sent).toHaveLength(2);
    expect(lastWatsonTurn(chat).lookedUp?.shownIds).toEqual(["raw1"]);
  });

  it("counts hosts and users, never IPs", () => {
    const full = { hosts: hosts(WATSON_MASK_ROSTER_MAX), users: [], ips: [] };
    expect(maskRosterFull(full, { hosts: ["x"] })).toBe(true);
    expect(maskRosterFull(full, { hosts: ["OLDHOST0"] })).toBe(false);
    expect(maskRosterFull({ users: hosts(WATSON_MASK_ROSTER_MAX) }, { users: ["y"] })).toBe(true);
    expect(maskRosterFull({ ips: hosts(WATSON_MASK_ROSTER_MAX) }, { ips: ["10.1.1.1"] })).toBe(false);
  });
});
