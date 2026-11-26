// Which paste a queued held row is offered under (#2934 item 2). The rule is deterministic, not
// exclusive provenance: a row whose sources name two recorded pastes goes under the EARLIEST recorded
// one, whatever order its own sources list them in; a row naming no recorded paste goes under its file.
import { describe, expect, it } from "vitest";
import { pasteOf, withQueuedHeld } from "../../../src/analysis/ai/watson/heldOfferChat.js";
import { emptyWatsonChat, type WatsonChat, type WatsonPaste } from "../../../src/analysis/ai/watson/types.js";
import type { ForensicEvent } from "../../../src/analysis/stateTypes.js";

const AT = "2026-07-30T00:00:00.000Z";

function paste(id: string, storedName: string, filename: string): WatsonPaste {
  return { id, storedName, filename, bytes: 10, lines: 1, at: AT };
}

function row(id: string, sources: string[]): ForensicEvent {
  return {
    id,
    timestamp: AT,
    severity: "High",
    description: `Synthetic event ${id}`,
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: sources,
  };
}

const chat: WatsonChat = {
  ...emptyWatsonChat(),
  pastes: [paste("p-first", "stored-a.txt", "first.txt"), paste("p-second", "stored-b.txt", "second.txt")],
};

describe("held rows naming two pastes (#2934)", () => {
  it("go under the earliest recorded paste, whichever order the row lists them in", () => {
    for (const sources of [
      ["stored-a.txt", "stored-b.txt"],
      ["stored-b.txt", "stored-a.txt"],
    ]) {
      const e = row("e1", sources);
      expect(pasteOf(chat, e)?.id).toBe("p-first");

      const offer = withQueuedHeld(chat, [e], AT);
      const turn = offer.chat.turns.at(-1)!;
      expect(turn.pasteId).toBe("p-first");
      expect(turn.text).toContain("first.txt");
      expect(offer.chat.proposals.at(-1)).toMatchObject({ pasteId: "p-first", status: "pending" });
      expect(offer.offered).toEqual(["e1"]);
    }
  });

  it("a row naming one recorded paste goes under that paste", () => {
    expect(pasteOf(chat, row("e2", ["stored-b.txt"]))?.id).toBe("p-second");
  });

  it("a row naming no recorded paste goes under its stored file, with no paste id", () => {
    const e = row("e3", ["stored-gone.txt"]);
    expect(pasteOf(chat, e)).toBeUndefined();
    const turn = withQueuedHeld(chat, [e], AT).chat.turns.at(-1)!;
    expect(turn.pasteId).toBeUndefined();
    expect(turn.text).toContain("stored-gone.txt");
  });
});
