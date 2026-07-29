import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp, mkdir, writeFile, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import {
  McpServerStore, isToolAllowed, tokenEnvKey, slugifyServerLabel, type McpServer,
} from "../../src/integrations/mcp/mcpServerStore.js";

let store: McpServerStore;
let file: string;

const LAN_URL = "http://192.168.1.50:8080/mcp";

beforeEach(async () => {
  const dir = await mkdtemp(join(tmpdir(), "dfir-mcpstore-"));
  file = join(dir, "nested", "mcp-servers.json");   // nested: the store creates its own directory
  store = new McpServerStore(file);
});

describe("McpServerStore CRUD", () => {
  it("adds a server and reads it back", async () => {
    const added = await store.add({ label: "SIFT", url: LAN_URL, allowedTools: ["pslist"] });

    expect(added).toMatchObject({ id: "sift", label: "SIFT", url: LAN_URL, enabled: true, allowedTools: ["pslist"] });
    expect(await store.load()).toEqual([added]);
  });

  it("returns an empty list before anything is stored", async () => {
    expect(await store.load()).toEqual([]);
  });

  it("replaces rather than duplicates when a label slugifies to an existing id", async () => {
    await store.add({ label: "SIFT", url: LAN_URL });
    await store.add({ label: "sift", url: "https://sift.lab.example/mcp" });

    const list = await store.load();
    expect(list).toHaveLength(1);
    expect(list[0].url).toBe("https://sift.lab.example/mcp");
  });

  it("gets one server by id, and null for an unknown one", async () => {
    await store.add({ label: "SIFT", url: LAN_URL });
    expect(await store.get("sift")).toMatchObject({ id: "sift" });
    expect(await store.get("nope")).toBeNull();
  });

  it("updates fields while keeping the id, even when the label changes", async () => {
    await store.add({ label: "SIFT", url: LAN_URL });

    const updated = await store.update("sift", { label: "SIFT workstation", enabled: false });

    expect(updated).toMatchObject({ id: "sift", label: "SIFT workstation", enabled: false });
    expect((await store.load())[0].id).toBe("sift");
  });

  it("returns null when updating a server that is not there", async () => {
    expect(await store.update("ghost", { label: "x" })).toBeNull();
  });

  it("removes a server and reports whether it removed anything", async () => {
    await store.add({ label: "SIFT", url: LAN_URL });

    expect(await store.remove("sift")).toBe(true);
    expect(await store.remove("sift")).toBe(false);
    expect(await store.load()).toEqual([]);
  });

  it("requires a label and a URL", async () => {
    await expect(store.add({ label: "", url: LAN_URL })).rejects.toThrow(/label is required/);
    await expect(store.add({ label: "SIFT", url: "" })).rejects.toThrow(/URL is required/);
  });

  it("strips a trailing slash so the endpoint is stored one way", async () => {
    const added = await store.add({ label: "SIFT", url: "http://192.168.1.50:8080/mcp/" });
    expect(added.url).toBe("http://192.168.1.50:8080/mcp");
  });

  it("accepts allowed tools as a comma or space separated string", async () => {
    const added = await store.add({ label: "SIFT", url: LAN_URL, allowedTools: "pslist, malfind netscan" });
    expect(added.allowedTools).toEqual(["pslist", "malfind", "netscan"]);
  });

  it("stores allowed commands, reduced to basenames", async () => {
    const added = await store.add({ label: "SIFT", url: LAN_URL, allowedCommands: "/usr/bin/grep, vol.py" });
    // "/usr/bin/grep" and "grep" must not be two different rules — mcpGuard compares on basename.
    expect(added.allowedCommands).toEqual(["grep", "vol.py"]);
  });

  it("keeps allowed commands across an update that does not mention them", async () => {
    await store.add({ label: "SIFT", url: LAN_URL, allowedCommands: ["vol.py"] });
    const updated = await store.update("sift", { label: "SIFT box" });
    expect(updated?.allowedCommands).toEqual(["vol.py"]);
  });
});

describe("McpServerStore URL validation", () => {
  // The deployment this feature is for: a bearer-token server on the operator's own LAN.
  it("accepts http to a private-network host", async () => {
    await expect(store.add({ label: "SIFT", url: "http://10.0.0.5:8080/mcp" })).resolves.toBeTruthy();
    await expect(store.add({ label: "REMnux", url: "http://192.168.1.7/mcp" })).resolves.toBeTruthy();
  });

  it("accepts http to loopback", async () => {
    await expect(store.add({ label: "local", url: "http://127.0.0.1:9000/mcp" })).resolves.toBeTruthy();
  });

  it("rejects cleartext http to a public host", async () => {
    await expect(store.add({ label: "hosted", url: "http://mcp.example.com/mcp" }))
      .rejects.toThrow(/cleartext/);
  });

  it("accepts https anywhere", async () => {
    await expect(store.add({ label: "hosted", url: "https://mcp.example.com/mcp" })).resolves.toBeTruthy();
  });

  it("rejects a URL that is not a URL", async () => {
    await expect(store.add({ label: "broken", url: "not a url" })).rejects.toThrow(/not a valid URL/);
  });

  it("validates on update too, and leaves the stored server untouched when it fails", async () => {
    await store.add({ label: "SIFT", url: LAN_URL });

    await expect(store.update("sift", { url: "http://mcp.example.com/mcp" })).rejects.toThrow(/cleartext/);
    expect((await store.load())[0].url).toBe(LAN_URL);
  });
});

describe("McpServerStore file handling", () => {
  it("drops a malformed entry on read instead of handing it to the client", async () => {
    await store.add({ label: "SIFT", url: LAN_URL });
    const list = JSON.parse(await readFile(file, "utf8")) as unknown[];
    await writeFile(file, JSON.stringify([...list, { id: "broken" }, "nonsense", null]), "utf8");

    expect((await store.load()).map((s) => s.id)).toEqual(["sift"]);
  });

  it("survives a file that is not an array", async () => {
    await store.add({ label: "SIFT", url: LAN_URL });
    await writeFile(file, JSON.stringify({ not: "an array" }), "utf8");
    expect(await store.load()).toEqual([]);
  });

  it("fills in defaults for fields a hand-edited file left out", async () => {
    await mkdir(dirname(file), { recursive: true });
    await writeFile(file, JSON.stringify([{ id: "sift", label: "SIFT", url: LAN_URL }]), "utf8");

    const [server] = await store.load();
    expect(server).toMatchObject({ enabled: true, allowedTools: [], allowedCommands: [], timeoutMs: 300_000 });
  });
});

describe("tokenEnvKey", () => {
  it("derives the env key from the server id", () => {
    expect(tokenEnvKey("sift")).toBe("DFIR_MCP_SIFT_TOKEN");
  });

  it("flattens punctuation so the key is a legal env name", () => {
    expect(tokenEnvKey("windows-triage")).toBe("DFIR_MCP_WINDOWS_TRIAGE_TOKEN");
  });
});

describe("slugifyServerLabel", () => {
  it("slugifies a label", () => {
    expect(slugifyServerLabel("SIFT Workstation")).toBe("sift-workstation");
  });

  it("falls back to a generated id when a label slugifies to nothing", () => {
    expect(slugifyServerLabel("!!!")).toMatch(/^server-[0-9a-f]{8}$/);
  });
});

describe("isToolAllowed", () => {
  const server = (allowedTools: string[]): McpServer =>
    ({ id: "sift", label: "SIFT", url: LAN_URL, enabled: true, allowedTools, allowedCommands: [], timeoutMs: 1000 });

  it("allows a tool that was named", () => {
    expect(isToolAllowed(server(["pslist"]), "pslist")).toBe(true);
  });

  it("denies a tool that was not named", () => {
    expect(isToolAllowed(server(["pslist"]), "malfind")).toBe(false);
  });

  // The control exists to stop a registered server widening its own reach by advertising new
  // tools. "Empty means allow everything" would leave exactly that unmitigated.
  it("denies everything when the allowlist is empty", () => {
    expect(isToolAllowed(server([]), "pslist")).toBe(false);
  });
});
