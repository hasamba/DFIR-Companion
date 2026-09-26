import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { runInNewContext } from "node:vm";
import { callsWithin, functionsOf, scriptFromSource } from "../helpers/dashboardAst.js";

// #1594: the finding card's "Other commands in this session" line. render() has no behavioural
// harness, so the line's builder is lifted out of the source and run on its own, and render's
// obligation — to call it with the FP-filtered, scope-projected row ids — is checked on the AST.
const SOURCE = readFileSync(new URL("../../../public/js/dashboard-render.js", import.meta.url), "utf8");

type Line = (f: unknown, visible: Set<string>) => string;

function lineBuilder(): Line {
  const start = SOURCE.indexOf("const SESSION_COMMANDS_SHOWN");
  const end = SOURCE.indexOf("function render(rawState)");
  if (start === -1 || end === -1) throw new Error("sessionCommandsLine not found in dashboard-render.js");
  const esc = (s: unknown) => String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  const escAttr = (s: unknown) => esc(s).replace(/"/g, "&quot;");
  const sandbox: { esc: typeof esc; escAttr: typeof escAttr; out?: Line } = { esc, escAttr };
  runInNewContext(`${SOURCE.slice(start, end)}; out = sessionCommandsLine;`, sandbox);
  if (!sandbox.out) throw new Error("sessionCommandsLine did not evaluate");
  return sandbox.out;
}

const cmd = (i: number, text = `cmd${i} /x`) => ({
  eventId: `e${i}`,
  timestamp: "2026-05-11T09:04:22.000Z",
  host: "ws01",
  kind: "process",
  text,
});

describe("dashboard session-command line (#1594)", () => {
  const line = lineBuilder();

  it("is empty with no note, or when every noted row is hidden", () => {
    expect(line({}, new Set())).toBe("");
    expect(line({ sessionCommands: [cmd(1)] }, new Set(["other"]))).toBe("");
  });

  it("escapes the command and shows only visible rows", () => {
    const html = line({ sessionCommands: [cmd(1, "<img src=x onerror=alert(1)>"), cmd(2)] }, new Set(["e1"]));
    expect(html).toContain("&lt;img src=x onerror=alert(1)&gt;");
    expect(html).not.toContain("<img");
    expect(html).not.toContain("cmd2");
    expect(html).toContain("2026-05-11 09:04:22");
  });

  it("spells out twelve and counts the rest", () => {
    const all = Array.from({ length: 15 }, (_, i) => cmd(i));
    const html = line({ sessionCommands: all }, new Set(all.map((c) => c.eventId)));
    expect(html).toContain("cmd11 /x");
    expect(html).not.toContain("cmd12 /x");
    expect(html).toContain("and 3 more in the timeline");
  });

  it("adds the notes the synthesis capped to the count (#1683)", () => {
    const html = line({ sessionCommands: [cmd(1)], sessionCommandsMore: 13 }, new Set(["e1"]));
    expect(html).toContain("and 13 more in the timeline");
  });

  it("render() calls it", () => {
    const fn = functionsOf(scriptFromSource("dashboard-render.js", SOURCE)).find(
      (f) => f.name === "render" && f.declaration,
    );
    expect(fn && callsWithin(fn.node).has("sessionCommandsLine")).toBe(true);
  });
});
