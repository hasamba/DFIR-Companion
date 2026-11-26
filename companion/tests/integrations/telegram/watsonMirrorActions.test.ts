import { describe, expect, it } from "vitest";
import {
  buildMirrorKeyboard,
  encodeMirrorCallback,
  MIRROR_PREVIEW_MAX,
  newActionToken,
  parseMirrorCallback,
  presserId,
  proposalPreview,
  telegramActor,
  telegramApprovable,
} from "../../../src/integrations/telegram/watsonMirrorActions.js";
import type { WatsonProposal } from "../../../src/analysis/ai/watson/types.js";
import { turnPlainText } from "../../../src/integrations/telegram/watsonMirrorFormat.js";
import { watsonApprovalLine } from "../../../src/reports/watsonFindingMd.js";
import { row } from "../../../src/reports/csv.js";
import type { Finding } from "../../../src/analysis/stateTypes.js";

// #2712: which mirrored proposals get Apply / Reject buttons, the callback data, and the approver's name.

const base = { id: "wp-1", turnId: "wt-1", status: "pending" as const };
const finding = (extra: Record<string, unknown> = {}): WatsonProposal =>
  ({
    ...base,
    kind: "finding_new",
    targetId: "f-1",
    after: { id: "f-1", title: "Beacon", severity: "High", description: "C2 to 203.0.113.9" },
    pasteLineEvents: [],
    ...extra,
  }) as unknown as WatsonProposal;
const of = (kind: string, extra: Record<string, unknown> = {}): WatsonProposal =>
  ({ ...base, kind, targetId: "t", ...extra }) as unknown as WatsonProposal;

describe("telegramApprovable", () => {
  it("allows only the low-risk case writes the user chose", () => {
    expect(telegramApprovable(finding())).toBe(true);
    expect(
      telegramApprovable(of("next_step_new", { after: { action: "Pull logs", priority: "high" } })),
    ).toBe(true);
    expect(telegramApprovable(of("report_text", { field: "conclusions", before: "", after: "Done." }))).toBe(
      true,
    );
    const q = { question: "Initial access?", status: "answered", answer: "Phishing" };
    expect(telegramApprovable(of("question_new", { after: q }))).toBe(true);
    expect(telegramApprovable(of("question_update", { after: q }))).toBe(true);
  });

  it("denies launches, hunts, searches, promotions, reviews and changes", () => {
    for (const kind of [
      "velo_launch",
      "cs_search",
      "event_promote",
      "finding_review",
      "finding_update",
      "next_step_update",
      "something_new",
    ]) {
      expect(telegramApprovable(of(kind, { after: { title: "x" } })), kind).toBe(false);
    }
  });

  it("denies a decided proposal and a missing one", () => {
    expect(telegramApprovable(finding({ status: "applied" }))).toBe(false);
    expect(telegramApprovable(finding({ status: "rejected" }))).toBe(false);
    expect(telegramApprovable(undefined)).toBe(false);
  });

  it("denies a finding that would add pasted lines to the forensic timeline", () => {
    expect(telegramApprovable(finding({ pasteLineEvents: [{ id: "e" }] }))).toBe(false);
    const cited = finding();
    (cited as unknown as { after: Record<string, unknown> }).after.citedPasteLines = [
      { pasteId: "p", line: 1 },
    ];
    expect(telegramApprovable(cited)).toBe(false);
  });

  it("denies a proposal whose change is too long to show in full", () => {
    const long = "x".repeat(MIRROR_PREVIEW_MAX + 1);
    expect(telegramApprovable(of("report_text", { field: "conclusions", before: "", after: long }))).toBe(
      false,
    );
  });
});

describe("proposalPreview", () => {
  it("shows the change itself", () => {
    expect(proposalPreview(finding())).toBe("Severity High. C2 to 203.0.113.9");
    expect(proposalPreview(of("report_text", { after: "New conclusions" }))).toBe("New conclusions");
    expect(
      proposalPreview(of("question_update", { after: { status: "answered", answer: "Phishing" } })),
    ).toBe("Status answered. Answer: Phishing");
  });
});

describe("callback data", () => {
  it("round-trips within Telegram's 64-byte limit", () => {
    const token = newActionToken();
    expect(token).toMatch(/^[A-Za-z0-9_-]{16}$/);
    const data = encodeMirrorCallback("apply", token);
    expect(Buffer.byteLength(data)).toBeLessThanOrEqual(64);
    expect(parseMirrorCallback(data)).toEqual({ action: "apply", token });
    expect(parseMirrorCallback(encodeMirrorCallback("reject", token))).toEqual({ action: "reject", token });
  });

  it("refuses forged, garbled and undo data", () => {
    for (const bad of [
      undefined,
      42,
      "",
      "wm:u:AAAAAAAAAAAAAAAA",
      "wm:a:short",
      "wm:a:AAAAAAAAAAAAAAAA:extra",
      "wm:a:AAAAAAAA/AAAAAAA",
      "apply wp-1",
    ]) {
      expect(parseMirrorCallback(bad), String(bad)).toBeUndefined();
    }
  });

  it("labels buttons with a number only, never case content", () => {
    const kb = buildMirrorKeyboard([
      { n: 1, token: "A".repeat(16) },
      { n: 2, token: "B".repeat(16) },
    ]);
    expect(kb?.inline_keyboard.map((r) => r.map((b) => b.text))).toEqual([
      ["Apply 1", "Reject 1"],
      ["Apply 2", "Reject 2"],
    ]);
    expect(buildMirrorKeyboard([])).toBeUndefined();
  });
});

describe("telegramActor", () => {
  it("names the Telegram user and always marks the channel", () => {
    expect(telegramActor({ id: 7, username: "alice_ir", first_name: "Alice" })).toBe(
      "@alice_ir (via Telegram)",
    );
    expect(telegramActor({ id: 7, first_name: "Alice", last_name: "Doe" })).toBe("Alice Doe (via Telegram)");
    expect(telegramActor({ id: 7 })).toBe("7 (via Telegram)");
    expect(telegramActor(undefined)).toBe("unknown (via Telegram)");
  });

  it("cannot pose as Watson or hide behind control characters", () => {
    expect(telegramActor({ id: 7, first_name: "Watson" })).toBe("Watson (via Telegram)");
    expect(telegramActor({ id: 7, first_name: "Watson (Auto)" })).not.toBe("Watson (Auto)");
    expect(telegramActor({ id: 7, first_name: "Bob‮​\nEvil" })).toBe("Bob Evil (via Telegram)");
    expect(telegramActor({ id: 7, username: "bad name!", first_name: "x".repeat(200) })).toBe(
      `${"x".repeat(48)} (via Telegram)`,
    );
  });

  it("reads the numeric id strictly", () => {
    expect(presserId({ id: 555 })).toBe("555");
    expect(presserId({ id: "555" })).toBe("555");
    expect(presserId({ id: 1.5 })).toBeUndefined();
    expect(presserId({ id: "555; drop" })).toBeUndefined();
    expect(presserId({})).toBeUndefined();
  });
});

describe("the Telegram actor downstream", () => {
  it("is escaped in the report's approval line and formula-guarded in CSV", () => {
    const actor = telegramActor({ id: 7, first_name: "*[x](http://evil.example)* | y" });
    const line = watsonApprovalLine({ approvedBy: actor } as Finding);
    expect(line).not.toContain("[x](http://evil.example)");
    expect(line).toContain("(via Telegram)");
    expect(row([telegramActor({ id: 7, username: "alice_ir" })])).toMatch(/^"?'@alice_ir/);
  });

  it("names the approver on the mirrored decision note", () => {
    const text = turnPlainText(
      {
        id: "wt-n",
        at: "2026-11-25T10:00:00Z",
        role: "system",
        actor: "@alice_ir (via Telegram)",
        text: "Applied it",
      },
      [],
    );
    expect(text).toBe("Note (@alice_ir (via Telegram)):\nApplied it");
  });
});
