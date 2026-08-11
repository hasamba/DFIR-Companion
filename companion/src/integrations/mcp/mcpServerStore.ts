import { readFile, mkdir } from "node:fs/promises";
import { existsSync } from "node:fs";
import { dirname, basename } from "node:path";
import { z } from "zod";
import { atomicWrite } from "../../storage/atomicWrite.js";

// POLICY for the MCP servers Claude Code is configured with (#296).
//
// Deliberately NOT a place to configure a server. There is no URL here and no token: the operator
// configures their MCP servers once, in Claude Code, and Claude Code holds the credentials. This
// store answers a different question — of the servers Claude Code already has, which may the
// Companion point case evidence at, what may they run, and how does the evidence reach them.
//
// `id` is therefore the server's name AS CLAUDE CODE KNOWS IT ("sift-mcp"), not a slug of a label
// the analyst invented. That is what `claude mcp list` reports and what `mcp__<name>__<tool>` is
// built from, so anything else would need a mapping that could silently go stale.
//
// An entry here for a server Claude Code does not have is harmless — it simply never resolves. The
// dashboard shows both lists side by side so the mismatch is visible rather than mysterious.

/**
 * How evidence reaches this server's host (§6). Flat with a `mode` discriminator rather than a
 * union, so a hand-edited file with a half-filled block still reads back with defaults instead of
 * collapsing the whole server entry.
 *
 * This stays the Companion's job even though the calls do not: Claude Code cannot move a 16 GB
 * memory image onto an analysis box, and MCP has no file-transfer primitive.
 */
export const mcpDeliverySchema = z.object({
  mode: z.enum(["remote-path", "scp"]).catch("remote-path"),
  // scp
  host: z.string().catch(""),
  user: z.string().catch(""),
  port: z.number().catch(22),
  identityFile: z.string().catch(""),
  remoteDir: z.string().catch(""),
  // Its own timeout, an hour by default: a disk image copy is not a 300-second operation, and
  // bounding it by the call timeout would kill every transfer that mattered.
  timeoutMs: z.number().catch(3_600_000),
  // remote-path
  localPrefix: z.string().catch(""),
  remotePrefix: z.string().catch(""),
});
export type McpDelivery = z.infer<typeof mcpDeliverySchema>;

export const DEFAULT_DELIVERY: McpDelivery = {
  mode: "remote-path",
  host: "",
  user: "",
  port: 22,
  identityFile: "",
  remoteDir: "",
  timeoutMs: 3_600_000,
  localPrefix: "",
  remotePrefix: "",
};

/**
 * A conservative charset for the parts of an scp/ssh invocation that are NOT shell-quoted.
 *
 * `user@host` reaches ssh unquoted, and scp's `host:path` destination is historically expanded by a
 * shell on the far side (modern OpenSSH uses SFTP and does not, but the registry should not depend
 * on the remote version). Restricting these to characters with no shell meaning removes the question
 * entirely, at the cost of rejecting exotic-but-legal values a staging host will not have.
 */
const SAFE_HOSTPART = /^[A-Za-z0-9._-]+$/;
const SAFE_REMOTE_DIR = /^\/[A-Za-z0-9._\-/]*$/;

/** Validate a delivery block. Returns an error message when unusable, null when fine. */
export function validateDelivery(d: McpDelivery): string | null {
  if (d.mode === "scp") {
    if (!d.host.trim()) return "scp delivery needs a host";
    if (!SAFE_HOSTPART.test(d.host))
      return `delivery host "${d.host}" may only contain letters, digits, dot, dash and underscore`;
    if (d.user && !SAFE_HOSTPART.test(d.user))
      return `delivery user "${d.user}" may only contain letters, digits, dot, dash and underscore`;
    if (!d.remoteDir.trim()) return "scp delivery needs a remote staging directory";
    if (!SAFE_REMOTE_DIR.test(d.remoteDir))
      return `remote directory "${d.remoteDir}" must be an absolute POSIX path of letters, digits, dot, dash, underscore and slash`;
    if (!Number.isInteger(d.port) || d.port < 1 || d.port > 65535)
      return `delivery port ${d.port} is not a valid port`;
    return null;
  }
  // remote-path: a rewrite needs both halves or neither. One alone silently maps everything to the
  // wrong place, which is worse than refusing to save it.
  if (Boolean(d.localPrefix) !== Boolean(d.remotePrefix)) {
    return "a shared-path rewrite needs both a local prefix and a remote prefix, or neither";
  }
  return null;
}

export const mcpServerSchema = z.object({
  /** The server's name in Claude Code — the key `claude mcp list` reports and `mcp__<id>__` uses. */
  id: z.string(),
  /** Display only; defaults to the id. */
  label: z.string().catch(""),
  enabled: z.boolean().catch(true),
  // OPTIONAL narrowing. Empty — the default — means every tool this server offers, which is what
  // Claude Code already permits when the operator uses it directly. See isToolAllowed.
  allowedTools: z.array(z.string()).catch([]),
  // OPTIONAL narrowing for a command-runner tool, by basename. Empty means no command restriction.
  allowedCommands: z.array(z.string()).catch([]),
  // Legacy field retained so existing policy files still parse. `enabled` is now the permission
  // boundary for both plain-English and manual use; see mcpAgentRunner's security note.
  agentEnabled: z.boolean().catch(false),
  /** Bounds one tool call. A real Volatility run outlives it, which is why the call is a job (§7). */
  timeoutMs: z.number().catch(300_000),
  delivery: mcpDeliverySchema.catch(DEFAULT_DELIVERY),
});
export type McpServer = z.infer<typeof mcpServerSchema>;

export interface McpServerInput {
  /** The Claude Code server name. Required — this is the join key, not a free-text label. */
  id: string;
  label?: string;
  enabled?: boolean;
  allowedTools?: string[] | string; // array or a comma/space-separated string
  allowedCommands?: string[] | string; // likewise
  agentEnabled?: boolean;
  timeoutMs?: number;
  delivery?: Partial<McpDelivery>;
}

/**
 * Claude Code server names are used verbatim in `mcp__<name>__<tool>` and reach a shell nowhere,
 * but they do become filenames and JSON keys, so keep them to a sane shape.
 */
const SAFE_SERVER_ID = /^[A-Za-z0-9][A-Za-z0-9._ -]{0,80}$/;

/**
 * Whether this server may be asked to run `toolName`. An empty allowlist means every tool it offers.
 *
 * This deliberately reverses the earlier deny-by-default. That default made sense when the Companion
 * WAS the MCP client: it held the URL and the token, so allowing a server granted reach that existed
 * nowhere else, and the operator had to say what they were granting.
 *
 * Claude Code holds the credentials now. When the operator runs `claude` themselves they can call
 * any tool on any server they configured, with no allowlist — so requiring one here enforced a
 * stricter policy than their own daily use, and made them describe the same server twice. The
 * grant point is Claude Code's configuration; this is optional narrowing on top of it.
 */
export function isToolAllowed(server: McpServer, toolName: string): boolean {
  return server.allowedTools.length === 0 || server.allowedTools.includes(toolName);
}

function normalizeNames(input: string[] | string | undefined): string[] {
  const parts = Array.isArray(input) ? input : String(input ?? "").split(/[,\s]+/);
  const out: string[] = [];
  for (const p of parts) {
    const t = String(p ?? "").trim();
    if (t && !out.includes(t)) out.push(t);
  }
  return out;
}

function fromInput(input: McpServerInput, id: string): McpServer {
  return {
    id,
    label:
      String(input.label ?? "")
        .trim()
        .slice(0, 120) || id,
    enabled: input.enabled !== false,
    allowedTools: normalizeNames(input.allowedTools),
    // Stored by basename, the same form mcpGuard compares against, so "/usr/bin/grep" and "grep"
    // are not two different rules.
    allowedCommands: normalizeNames(input.allowedCommands).map((c) => basename(c)),
    agentEnabled: input.agentEnabled === true,
    timeoutMs: Number(input.timeoutMs) > 0 ? Number(input.timeoutMs) : 300_000,
    delivery: mcpDeliverySchema
      .catch(DEFAULT_DELIVERY)
      .parse({ ...DEFAULT_DELIVERY, ...(input.delivery ?? {}) }),
  };
}

export class McpServerStore {
  constructor(private readonly file: string) {}

  async load(): Promise<McpServer[]> {
    try {
      const raw = JSON.parse(await readFile(this.file, "utf8")) as unknown;
      if (!Array.isArray(raw)) return [];
      // Re-validate on read so a hand-edited file cannot inject a malformed entry into the runner.
      return raw
        .map((r) => {
          const p = mcpServerSchema.safeParse(r);
          return p.success ? p.data : null;
        })
        .filter((s): s is McpServer => s !== null && !!s.id);
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return [];
      throw err;
    }
  }

  async get(id: string): Promise<McpServer | null> {
    return (await this.load()).find((s) => s.id === id) ?? null;
  }

  private async save(list: McpServer[]): Promise<void> {
    const dir = dirname(this.file);
    if (dir && !existsSync(dir)) await mkdir(dir, { recursive: true });
    await atomicWrite(this.file, JSON.stringify(list, null, 2));
  }

  /** Add policy for a Claude Code server, or replace what is already there for that name. */
  async add(input: McpServerInput): Promise<McpServer> {
    const id = String(input.id ?? "").trim();
    if (!id) throw new Error("a Claude Code server name is required");
    if (!SAFE_SERVER_ID.test(id)) throw new Error(`"${id}" is not a valid Claude Code server name`);
    const server = fromInput(input, id);
    const deliveryError = validateDelivery(server.delivery);
    if (deliveryError) throw new Error(deliveryError);

    const list = await this.load();
    const next = list.some((s) => s.id === id)
      ? list.map((s) => (s.id === id ? server : s))
      : [...list, server];
    await this.save(next);
    return server;
  }

  async update(id: string, patch: Partial<McpServerInput>): Promise<McpServer | null> {
    const list = await this.load();
    const cur = list.find((s) => s.id === id);
    if (!cur) return null;
    const merged = fromInput(
      {
        id,
        label: patch.label ?? cur.label,
        enabled: patch.enabled ?? cur.enabled,
        allowedTools: patch.allowedTools ?? cur.allowedTools,
        allowedCommands: patch.allowedCommands ?? cur.allowedCommands,
        agentEnabled: patch.agentEnabled ?? cur.agentEnabled,
        timeoutMs: patch.timeoutMs ?? cur.timeoutMs,
        // Merged field-wise so changing one delivery setting does not reset the rest to defaults.
        delivery: { ...cur.delivery, ...(patch.delivery ?? {}) },
      },
      id,
    );
    const deliveryError = validateDelivery(merged.delivery);
    if (deliveryError) throw new Error(deliveryError);
    await this.save(list.map((s) => (s.id === id ? merged : s)));
    return merged;
  }

  async remove(id: string): Promise<boolean> {
    const list = await this.load();
    const next = list.filter((s) => s.id !== id);
    if (next.length === list.length) return false;
    await this.save(next);
    return true;
  }
}
