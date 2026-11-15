import { describe, expect, it } from "vitest";
import {
  Scripted,
  calls,
  final,
  forensic,
  lastTurn,
  superSearch,
  toolHarness,
} from "./roundToolsFixtures.js";
import { raw } from "./superPromoteFixtures.js";

// Watson phase 5, Task 7: the turn keeps every lookup of the round (also on an error turn), and the
// shown super-timeline ids count as "shown earlier" for the next round.

describe("lookups saved on the turn", () => {
  it("a tool round saves lookups[] in order, with the shown ids of the super search", async () => {
    const p = new Scripted([
      calls(forensic({ text: "quiet" })),
      calls(superSearch({ text: "rclone" })),
      final(),
    ]);
    const h = await toolHarness(p, { raw: [raw("raw1", { asset: "FINSRV-07" })] });
    const chat = await h.run();
    const t = lastTurn(chat);
    expect(t.role).toBe("watson");
    expect(t.lookups?.map((l) => l.source ?? "forensic")).toEqual(["forensic", "supertimeline"]);
    expect(t.lookups?.[1]?.shownIds).toContain("raw1");
  });

  it("an error turn after a mid-loop stop still lists its lookups", async () => {
    const p = new Scripted([calls(superSearch({ text: "rclone" })), final()], { tokens: 1000 });
    const h = await toolHarness(p, { tokenLimit: 900, raw: [raw("raw1", { asset: "FINSRV-07" })] });
    const chat = await h.run();
    const t = lastTurn(chat);
    expect(t).toMatchObject({ role: "system", error: true });
    expect(t.lookups).toHaveLength(1);
    expect(t.lookups?.[0]?.shownIds).toContain("raw1");
  });

  it("superCapHit is saved on the turn (R2)", async () => {
    const p = new Scripted([
      calls(superSearch({ text: "rclone" })),
      calls(superSearch({ text: "rclone copy" })),
      calls(superSearch({ text: "rclone raw" })),
      final(),
    ]);
    const chat = await (await toolHarness(p, { maxToolCalls: 6 })).run();
    expect(lastTurn(chat).superCapHit).toBe(true);
    expect(lastTurn(chat).superCapLimit).toBe(2);
    expect(lastTurn(chat).lookups).toHaveLength(2);
  });
});
