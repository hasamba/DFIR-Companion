import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp, mkdir, writeFile, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import {
  McpServerStore, isToolAllowed, DEFAULT_DELIVERY, type McpServer,
} from "../../src/integrations/mcp/mcpServerStore.js";

let store: McpServerStore;
let file: string;

beforeEach(async () => {
  const dir = await mkdtemp(join(tmpdir(), "dfir-mcpstore-"));
  file = join(dir, "nested", "mcp-servers.json");   // nested: the store creates its own directory
  store = new McpServerStore(file);
});

describe("McpServerStore CRUD", () => {
  // The id is Claude Code's name for the server, not a slug of an analyst-chosen label — that name
  // is what `claude mcp list` reports and what mcp__<name>__<tool> is built from.
  it("keys on the Claude Code server name", async () => {
    const added = await store.add({ id: "sift-mcp", allowedTools: ["run_command"] });

    expect(added).toMatchObject({ id: "sift-mcp", label: "sift-mcp", enabled: true, allowedTools: ["run_command"] });
    expect(await store.load()).toEqual([added]);
  });

  it("holds no URL and no token — those live in Claude Code", async () => {
    const added = await store.add({ id: "sift-mcp" });
    expect(added).not.toHaveProperty("url");
    expect(JSON.stringify(added)).not.toMatch(/token/i);
  });

  it("returns an empty list before anything is stored", async () => {
    expect(await store.load()).toEqual([]);
  });

  it("uses the id as the label when none is given, and keeps one that is", async () => {
    expect((await store.add({ id: "sift-mcp" })).label).toBe("sift-mcp");
    expect((await store.add({ id: "remnux", label: "REMnux sandbox" })).label).toBe("REMnux sandbox");
  });

  it("replaces rather than duplicates when the same server is added again", async () => {
    await store.add({ id: "sift-mcp", allowedTools: ["run_command"] });
    await store.add({ id: "sift-mcp", allowedTools: ["check_tools"] });

    const list = await store.load();
    expect(list).toHaveLength(1);
    expect(list[0].allowedTools).toEqual(["check_tools"]);
  });

  it("gets one server by id, and null for an unknown one", async () => {
    await store.add({ id: "sift-mcp" });
    expect(await store.get("sift-mcp")).toMatchObject({ id: "sift-mcp" });
    expect(await store.get("nope")).toBeNull();
  });

  it("updates fields while keeping the id, even when the label changes", async () => {
    await store.add({ id: "sift-mcp" });

    const updated = await store.update("sift-mcp", { label: "SIFT workstation", enabled: false });

    expect(updated).toMatchObject({ id: "sift-mcp", label: "SIFT workstation", enabled: false });
  });

  it("returns null when updating a server that is not there", async () => {
    expect(await store.update("ghost", { label: "x" })).toBeNull();
  });

  it("removes a server and reports whether it removed anything", async () => {
    await store.add({ id: "sift-mcp" });

    expect(await store.remove("sift-mcp")).toBe(true);
    expect(await store.remove("sift-mcp")).toBe(false);
    expect(await store.load()).toEqual([]);
  });

  it("requires a server name", async () => {
    await expect(store.add({ id: "" })).rejects.toThrow(/server name is required/);
  });

  it("refuses a name that is not a plausible Claude Code server name", async () => {
    await expect(store.add({ id: "../etc/passwd" })).rejects.toThrow(/not a valid Claude Code server name/);
    await expect(store.add({ id: "a;b" })).rejects.toThrow(/not a valid/);
  });

  // Real Claude Code names include these shapes.
  it("accepts names with dots, dashes and spaces", async () => {
    await expect(store.add({ id: "windows-triage-mcp" })).resolves.toBeTruthy();
    await expect(store.add({ id: "claude.ai Google Drive" })).resolves.toBeTruthy();
  });

  it("accepts allowed tools as a comma or space separated string", async () => {
    const added = await store.add({ id: "sift-mcp", allowedTools: "run_command, check_tools suggest_tools" });
    expect(added.allowedTools).toEqual(["run_command", "check_tools", "suggest_tools"]);
  });

  it("stores allowed commands, reduced to basenames", async () => {
    const added = await store.add({ id: "sift-mcp", allowedCommands: "/usr/bin/grep, vol.py" });
    // "/usr/bin/grep" and "grep" must not be two different rules — mcpGuard compares on basename.
    expect(added.allowedCommands).toEqual(["grep", "vol.py"]);
  });

  it("keeps allowed commands across an update that does not mention them", async () => {
    await store.add({ id: "sift-mcp", allowedCommands: ["vol.py"] });
    expect((await store.update("sift-mcp", { label: "SIFT box" }))?.allowedCommands).toEqual(["vol.py"]);
  });

  it("defaults agent use to off", async () => {
    expect((await store.add({ id: "sift-mcp" })).agentEnabled).toBe(false);
  });
});

describe("McpServerStore file handling", () => {
  it("drops a malformed entry on read instead of handing it to the runner", async () => {
    await store.add({ id: "sift-mcp" });
    const list = JSON.parse(await readFile(file, "utf8")) as unknown[];
    await writeFile(file, JSON.stringify([...list, {}, "nonsense", null]), "utf8");

    expect((await store.load()).map((s) => s.id)).toEqual(["sift-mcp"]);
  });

  it("survives a file that is not an array", async () => {
    await store.add({ id: "sift-mcp" });
    await writeFile(file, JSON.stringify({ not: "an array" }), "utf8");
    expect(await store.load()).toEqual([]);
  });

  it("fills in defaults for fields a hand-edited file left out", async () => {
    await mkdir(dirname(file), { recursive: true });
    await writeFile(file, JSON.stringify([{ id: "sift-mcp" }]), "utf8");

    const [server] = await store.load();
    expect(server).toMatchObject({
      enabled: true, allowedTools: [], allowedCommands: [], agentEnabled: false, timeoutMs: 300_000,
    });
  });
});

describe("McpServerStore delivery config", () => {
  const SCP = { mode: "scp" as const, host: "sift.lab", user: "analyst", remoteDir: "/cases/incoming" };

  it("defaults to remote-path with nothing configured", async () => {
    expect((await store.add({ id: "sift-mcp" })).delivery)
      .toMatchObject({ mode: "remote-path", port: 22, timeoutMs: 3_600_000 });
  });

  it("stores an scp block", async () => {
    expect((await store.add({ id: "sift-mcp", delivery: SCP })).delivery)
      .toMatchObject({ mode: "scp", host: "sift.lab", user: "analyst", remoteDir: "/cases/incoming" });
  });

  it("fills defaults around a partial block", async () => {
    const added = await store.add({ id: "sift-mcp", delivery: { mode: "scp", host: "sift.lab", remoteDir: "/tmp/x" } });
    expect(added.delivery).toMatchObject({ port: 22, user: "", identityFile: "" });
  });

  it("requires a host and a remote directory for scp", async () => {
    await expect(store.add({ id: "a", delivery: { mode: "scp", remoteDir: "/x" } })).rejects.toThrow(/needs a host/);
    await expect(store.add({ id: "b", delivery: { mode: "scp", host: "sift.lab" } })).rejects.toThrow(/needs a remote staging directory/);
  });

  // user@host reaches ssh unquoted, so anything with shell meaning is refused at save time.
  it("refuses a host or user that could carry shell meaning", async () => {
    await expect(store.add({ id: "a", delivery: { ...SCP, host: "sift.lab; rm -rf /" } }))
      .rejects.toThrow(/host .* may only contain/);
    await expect(store.add({ id: "b", delivery: { ...SCP, user: "an$(whoami)" } }))
      .rejects.toThrow(/user .* may only contain/);
  });

  it("requires the remote directory to be an absolute POSIX path", async () => {
    await expect(store.add({ id: "a", delivery: { ...SCP, remoteDir: "relative/dir" } }))
      .rejects.toThrow(/must be an absolute POSIX path/);
    await expect(store.add({ id: "b", delivery: { ...SCP, remoteDir: "/cases/$(x)" } }))
      .rejects.toThrow(/must be an absolute POSIX path/);
  });

  it("rejects an impossible port", async () => {
    await expect(store.add({ id: "a", delivery: { ...SCP, port: 70000 } })).rejects.toThrow(/not a valid port/);
  });

  // One prefix alone silently maps everything to the wrong place.
  it("requires both halves of a shared-path rewrite, or neither", async () => {
    await expect(store.add({ id: "a", delivery: { mode: "remote-path", localPrefix: "/srv" } }))
      .rejects.toThrow(/both a local prefix and a remote prefix/);
    await expect(store.add({ id: "b", delivery: { mode: "remote-path", localPrefix: "/srv", remotePrefix: "/mnt" } }))
      .resolves.toBeTruthy();
  });

  it("merges a delivery update field-wise instead of resetting the rest", async () => {
    await store.add({ id: "sift-mcp", delivery: { ...SCP, identityFile: "/home/dfir/.ssh/lab" } });

    const updated = await store.update("sift-mcp", { delivery: { remoteDir: "/cases/staging" } });

    expect(updated?.delivery).toMatchObject({
      mode: "scp", host: "sift.lab", identityFile: "/home/dfir/.ssh/lab", remoteDir: "/cases/staging",
    });
  });

  it("validates on update, leaving the stored block untouched when it fails", async () => {
    await store.add({ id: "sift-mcp", delivery: SCP });

    await expect(store.update("sift-mcp", { delivery: { host: "evil;host" } })).rejects.toThrow(/may only contain/);
    expect((await store.load())[0].delivery.host).toBe("sift.lab");
  });
});

describe("isToolAllowed", () => {
  const server = (allowedTools: string[]): McpServer =>
    ({
      id: "sift-mcp", label: "SIFT", enabled: true,
      allowedTools, allowedCommands: [], agentEnabled: false, timeoutMs: 1000, delivery: DEFAULT_DELIVERY,
    });

  it("allows a tool that was named", () => {
    expect(isToolAllowed(server(["run_command"]), "run_command")).toBe(true);
  });

  it("denies a tool that was not named", () => {
    expect(isToolAllowed(server(["run_command"]), "check_tools")).toBe(false);
  });

  // The control exists to stop a registered server widening its own reach by advertising new
  // tools. "Empty means allow everything" would leave exactly that unmitigated.
  it("denies everything when the allowlist is empty", () => {
    expect(isToolAllowed(server([]), "run_command")).toBe(false);
  });
});
