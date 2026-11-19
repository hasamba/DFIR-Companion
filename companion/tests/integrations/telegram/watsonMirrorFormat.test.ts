import { describe, expect, it } from "vitest";
import {
  MIRROR_CHUNK_MAX,
  buildMirrorMessages,
  escapeMirrorHtml,
  mirrorFooter,
  replaceWorkstationRoots,
  turnPlainText,
  workstationRoots,
} from "../../../src/integrations/telegram/watsonMirrorFormat.js";
import type { WatsonProposal, WatsonTurn } from "../../../src/analysis/ai/watson/types.js";

// #2647: the Telegram mirror's formatter. Pure: a Watson turn becomes plain text, workstation roots
// are replaced, the text is escaped for Telegram's HTML mode and split into messages that always end
// with the dashboard footer.

const turn = (over: Partial<WatsonTurn>): WatsonTurn => ({
  id: "wt-1",
  at: "2026-11-19T10:00:00.000Z",
  role: "watson",
  text: "",
  ...over,
});

describe("escapeMirrorHtml", () => {
  it("escapes tags, both quote kinds and ampersands", () => {
    expect(escapeMirrorHtml(`<script>alert("x")</script> & 'y'`)).toBe(
      "&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt; &amp; &#39;y&#39;",
    );
  });

  it("turns a bidi override into a visible marker", () => {
    const out = escapeMirrorHtml("cod.\u202Escr");
    expect(out).not.toContain("\u202E");
    expect(out).toContain("&lt;RLO&gt;");
  });
});

describe("replaceWorkstationRoots", () => {
  const roots = workstationRoots({
    casesRoot: "/home/analyst/dfir/cases",
    dataDir: "/home/analyst/dfir",
    installDirs: ["/opt/companion"],
  });

  it("replaces the cases root with <case> and the data and install dirs with <companion>", () => {
    const out = replaceWorkstationRoots(
      "read /home/analyst/dfir/cases/INC-1/imports/a.json and /home/analyst/dfir/notifications/x and /opt/companion/dist/x.js",
      roots,
    );
    expect(out).toBe(
      "read <case>/INC-1/imports/a.json and <companion>/notifications/x and <companion>/dist/x.js",
    );
  });

  it("keeps evidence paths from the artifacts", () => {
    const text = String.raw`ran C:\Windows\Temp\x.ps1 and /tmp/.hidden/beacon`;
    expect(replaceWorkstationRoots(text, roots)).toBe(text);
  });

  it("matches a root only at a path boundary", () => {
    expect(replaceWorkstationRoots("/opt/companionship/file", roots)).toBe("/opt/companionship/file");
  });

  it("matches Windows roots in either slash direction and any case", () => {
    const win = workstationRoots({
      casesRoot: String.raw`C:\Users\an\dfir\cases`,
      dataDir: "",
      installDirs: [],
    });
    expect(replaceWorkstationRoots(String.raw`c:\users\AN\dfir\cases\INC-1\x`, win)).toBe(
      String.raw`<case>\INC-1\x`,
    );
    expect(replaceWorkstationRoots("C:/Users/an/dfir/cases/INC-1", win)).toBe("<case>/INC-1");
  });

  it("never treats a filesystem root as a workstation root", () => {
    const r = workstationRoots({ casesRoot: "/", dataDir: "C:\\", installDirs: ["", "/"] });
    expect(r).toEqual([]);
    expect(replaceWorkstationRoots("/etc/passwd", r)).toBe("/etc/passwd");
  });
});

describe("turnPlainText", () => {
  it("writes the analyst's question with the actor", () => {
    const t = turn({ role: "analyst", actor: "42 via telegram", text: "what ran?" });
    expect(turnPlainText(t, [])).toBe("Analyst (42 via telegram):\nwhat ran?");
  });

  it("writes Watson's answer with the status line, the answer, Next and learned", () => {
    const t = turn({
      text: "I looked at the prefetch.",
      learned: "the beacon ran at 10:02",
      answer: {
        question: "q",
        status: "partial",
        answer: "PsExec moved laterally",
        pointer: "collect host B",
        relatedEventIds: [],
      },
    });
    expect(turnPlainText(t, [])).toBe(
      "Watson:\nI looked at the prefetch.\n[partial] PsExec moved laterally\nNext: collect host B\nLearned: the beacon ran at 10:02",
    );
  });

  it("writes one line per proposal and a fallback when the proposal left the chat", () => {
    const proposals = [
      { id: "p1", turnId: "wt-1", status: "pending", kind: "velo_launch", title: "Collect prefetch" },
      {
        id: "p2",
        turnId: "wt-1",
        status: "pending",
        kind: "question_new",
        questionId: "q1",
        after: { question: "Who logged on?" },
      },
      {
        id: "p3",
        turnId: "wt-1",
        status: "pending",
        kind: "finding_new",
        targetId: "f1",
        after: { title: "Beacon" },
      },
      {
        id: "p4",
        turnId: "wt-1",
        status: "pending",
        kind: "next_step_new",
        targetId: "s1",
        after: { action: "Pull evtx" },
      },
    ] as unknown as WatsonProposal[];
    const t = turn({ text: "ok", proposalIds: ["p1", "p2", "p3", "p4", "gone"] });
    expect(turnPlainText(t, proposals).split("\n").slice(2)).toEqual([
      "Watson proposes: Velociraptor collection: Collect prefetch",
      "Watson proposes: new key question: Who logged on?",
      "Watson proposes: new finding: Beacon",
      "Watson proposes: new next step: Pull evtx",
      "Watson proposes: a change (open the dashboard to see it)",
    ]);
  });

  it("labels system notes and keeps the Velociraptor note as one line", () => {
    expect(turnPlainText(turn({ role: "system", text: "Watson reacted to: import" }), [])).toBe(
      "Note:\nWatson reacted to: import",
    );
  });
});

describe("mirrorFooter", () => {
  it("links to the case when a public dashboard URL is set", () => {
    expect(mirrorFooter("INC-1", "https://dfir.example.test/")).toBe(
      '<a href="https://dfir.example.test/dashboard?caseId=INC-1">Open case INC-1 in the dashboard</a>',
    );
  });

  it("says where to look when there is no public URL", () => {
    expect(mirrorFooter("INC-1", undefined)).toBe("Open case INC-1 in the dashboard");
  });

  it("escapes a quote in the link attribute", () => {
    expect(mirrorFooter("INC-1", `https://x.test/"onmouseover="`)).not.toContain(`"onmouseover`);
  });
});

describe("buildMirrorMessages", () => {
  const footer = mirrorFooter("INC-1", "https://dfir.example.test");

  it("splits a 10,000-character turn into ordered messages, each valid and with the footer", () => {
    const raw = `${"A".repeat(5000)}<script>"\u202E${"B".repeat(5000)}`;
    const msgs = buildMirrorMessages(raw, footer);
    expect(msgs.length).toBeGreaterThan(2);
    for (const m of msgs) {
      expect(m.endsWith(footer)).toBe(true);
      expect(m.length).toBeLessThanOrEqual(4096);
      // No entity is cut: every & starts a whole entity.
      expect(m.replace(/&(amp|lt|gt|quot|#39);/g, "")).not.toContain("&");
      expect(m).not.toContain("<script>");
      expect(m).not.toContain("\u202E");
    }
    const body = msgs.map((m) => m.slice(0, m.length - footer.length).trimEnd()).join("");
    expect(body).toContain("&lt;script&gt;&quot;&lt;RLO&gt;");
    expect(
      body
        .replace(/&[a-z#0-9]+;/g, "")
        .replace(/RLO/g, "")
        .replace(/script/g, ""),
    ).toMatch(/^A+B+$/);
  });

  it("keeps each chunk within the escaped budget even when every character expands", () => {
    const msgs = buildMirrorMessages("<".repeat(3000), footer);
    for (const m of msgs) expect(m.length - footer.length).toBeLessThanOrEqual(MIRROR_CHUNK_MAX + 2);
    expect(msgs.length).toBe(4); // 3000 × "&lt;" = 12,000 escaped characters
  });

  it("splits on line boundaries when lines fit", () => {
    const lines = Array.from({ length: 150 }, (_, i) => `line ${i} ${"x".repeat(30)}`);
    const msgs = buildMirrorMessages(lines.join("\n"), footer);
    expect(msgs.length).toBe(2);
    const first = msgs[0]
      .slice(0, msgs[0].length - footer.length)
      .trimEnd()
      .split("\n");
    expect(first.at(-1)).toMatch(/^line \d+ x+$/);
  });

  it("sends one message for short text", () => {
    expect(buildMirrorMessages("hello", footer)).toEqual([`hello\n\n${footer}`]);
  });
});
