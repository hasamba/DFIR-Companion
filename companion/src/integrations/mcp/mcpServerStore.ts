import { readFile, mkdir } from "node:fs/promises";
import { existsSync } from "node:fs";
import { dirname, basename } from "node:path";
import { randomUUID } from "node:crypto";
import { z } from "zod";
import { atomicWrite } from "../../storage/atomicWrite.js";
import { validateBaseUrl } from "../../providers/urlValidation.js";

// Analyst-registered MCP servers (#296) — the SIFT / REMnux / windows-triage boxes an operator
// already runs on their own network, so case evidence can be pointed at them from inside the
// companion. GLOBAL + shared across cases, exactly like CustomToolStore: a variable-length list
// belongs in a JSON store rather than fixed .env keys.
//
// Same ownership rule as the external-tool runner: the analyst owns the tooling. The companion
// does not bundle, install, host or update any MCP server, it only calls the ones it is told about.
//
// Deliberately NOT here yet: the §6 delivery block (how a multi-gigabyte image gets onto the
// analysis host). Every field below is re-validated on read with a `.catch()` default, so adding
// `delivery` in phase 2 reads old files without a migration.

/**
 * How evidence reaches this server's host (§6). Flat with a `mode` discriminator rather than a
 * union, so a hand-edited file with a half-filled block still reads back with defaults instead of
 * collapsing the whole server entry.
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
  mode: "remote-path", host: "", user: "", port: 22, identityFile: "", remoteDir: "",
  timeoutMs: 3_600_000, localPrefix: "", remotePrefix: "",
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
    if (!SAFE_HOSTPART.test(d.host)) return `delivery host "${d.host}" may only contain letters, digits, dot, dash and underscore`;
    if (d.user && !SAFE_HOSTPART.test(d.user)) return `delivery user "${d.user}" may only contain letters, digits, dot, dash and underscore`;
    if (!d.remoteDir.trim()) return "scp delivery needs a remote staging directory";
    if (!SAFE_REMOTE_DIR.test(d.remoteDir)) return `remote directory "${d.remoteDir}" must be an absolute POSIX path of letters, digits, dot, dash, underscore and slash`;
    if (!Number.isInteger(d.port) || d.port < 1 || d.port > 65535) return `delivery port ${d.port} is not a valid port`;
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
  id: z.string(),
  label: z.string(),
  url: z.string(),
  enabled: z.boolean().catch(true),
  // The tools this server may be asked to RUN. See isToolAllowed for why an empty list denies.
  allowedTools: z.array(z.string()).catch([]),
  // The binaries a command-runner tool on this server may invoke, by basename. Only consulted when
  // a call actually carries a command argument — see mcpGuard.assertCallAllowed, which explains why
  // allowedTools alone cannot bound a server whose one useful tool runs arbitrary argv.
  allowedCommands: z.array(z.string()).catch([]),
  // Whether an autonomous agent loop (§7 Mode 2) may use this server. Separate from `enabled`, and
  // deliberately not implied by it: the agent path cannot enforce allowedCommands (see
  // mcpAgentRunner's header), so exposing a server to it grants strictly more than a manual run.
  agentEnabled: z.boolean().catch(false),
  // Matches ToolConfig's default. A real Volatility run outlives it, which is why the call is a
  // JobManager job rather than a request (§7) — this bounds the individual HTTP round-trip.
  timeoutMs: z.number().catch(300_000),
  delivery: mcpDeliverySchema.catch(DEFAULT_DELIVERY),
});
export type McpServer = z.infer<typeof mcpServerSchema>;

export interface McpServerInput {
  label: string;
  url: string;
  enabled?: boolean;
  allowedTools?: string[] | string;      // array or a comma/space-separated string
  allowedCommands?: string[] | string;   // likewise
  agentEnabled?: boolean;
  timeoutMs?: number;
  delivery?: Partial<McpDelivery>;
}

/** Stable slug id from the server label, so re-adding the same name updates rather than duplicates. */
export function slugifyServerLabel(label: string): string {
  const s = String(label ?? "").trim().toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 60);
  return s || `server-${randomUUID().slice(0, 8)}`;
}

/**
 * Where this server's bearer token lives. Tokens are NOT stored in the registry JSON: that file is
 * ordinary case-adjacent config an analyst may copy or commit, whereas .env is already the
 * companion's secret store. Deriving the key from the id rather than storing it means the registry
 * cannot be edited to point at some OTHER key's value.
 *
 * `_TOKEN` is already in envManager's SECRET_SUFFIXES, so redaction in GET /settings/env is free.
 */
export function tokenEnvKey(id: string): string {
  return `DFIR_MCP_${String(id ?? "").toUpperCase().replace(/[^A-Z0-9]/g, "_")}_TOKEN`;
}

/**
 * Whether this server may be asked to run `toolName`.
 *
 * An EMPTY allowlist denies everything. That is the opposite of the usual "empty means unrestricted"
 * default, and it is the whole point of the control (§10): the threat is a registered server
 * advertising new tools after the fact and thereby widening its own reach. "Empty means allow all"
 * would leave exactly that threat unmitigated, so a tool has to be named before it can be run.
 *
 * tools/list is deliberately NOT gated by this — an analyst has to be able to see what a server
 * offers in order to choose what to allow.
 */
export function isToolAllowed(server: McpServer, toolName: string): boolean {
  return server.allowedTools.includes(toolName);
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
    label: String(input.label ?? "").trim().slice(0, 120),
    url: String(input.url ?? "").trim().replace(/\/+$/, ""),
    enabled: input.enabled !== false,
    agentEnabled: input.agentEnabled === true,
    allowedTools: normalizeNames(input.allowedTools),
    // Stored by basename, the same form mcpGuard compares against, so "/usr/bin/grep" and "grep"
    // are not two different rules.
    allowedCommands: normalizeNames(input.allowedCommands).map((c) => basename(c)),
    timeoutMs: Number(input.timeoutMs) > 0 ? Number(input.timeoutMs) : 300_000,
    // Parsed through the schema so a partial block from the dashboard gets every default filled,
    // and a garbage one falls back rather than being stored half-formed.
    delivery: mcpDeliverySchema.catch(DEFAULT_DELIVERY).parse({ ...DEFAULT_DELIVERY, ...(input.delivery ?? {}) }),
  };
}

export class McpServerStore {
  constructor(private readonly file: string) {}

  async load(): Promise<McpServer[]> {
    try {
      const raw = JSON.parse(await readFile(this.file, "utf8")) as unknown;
      if (!Array.isArray(raw)) return [];
      // Re-validate on read so a hand-edited file cannot inject a malformed server into the client.
      return raw
        .map((r) => { const p = mcpServerSchema.safeParse(r); return p.success ? p.data : null; })
        .filter((s): s is McpServer => s !== null && !!s.id && !!s.label && !!s.url);
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

  /**
   * Add (or, when the label slugifies to an existing id, replace) a server.
   *
   * The URL goes through the same validateBaseUrl every AI provider base URL does. That already
   * permits http:// to an RFC1918 host — precisely the LAN deployment these servers use — while
   * rejecting cleartext to a public one. Its top-of-file note on what URL validation can and cannot
   * prevent applies here unchanged: this stops the accidental case, not a deliberately hostile URL.
   */
  async add(input: McpServerInput): Promise<McpServer> {
    const label = String(input.label ?? "").trim();
    const url = String(input.url ?? "").trim();
    if (!label) throw new Error("a server label is required");
    if (!url) throw new Error("a server URL is required");
    const urlError = validateBaseUrl(url);
    if (urlError) throw new Error(urlError);

    const id = slugifyServerLabel(label);
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
    const url = patch.url !== undefined ? String(patch.url).trim() : cur.url;
    const urlError = validateBaseUrl(url);
    if (urlError) throw new Error(urlError);
    const merged = fromInput({
      label: patch.label ?? cur.label,
      url,
      enabled: patch.enabled ?? cur.enabled,
      agentEnabled: patch.agentEnabled ?? cur.agentEnabled,
      allowedTools: patch.allowedTools ?? cur.allowedTools,
      allowedCommands: patch.allowedCommands ?? cur.allowedCommands,
      timeoutMs: patch.timeoutMs ?? cur.timeoutMs,
      // Merged field-wise so changing one delivery setting does not reset the rest to defaults.
      delivery: { ...cur.delivery, ...(patch.delivery ?? {}) },
    }, id);   // keep the same id — a label change does not re-slug an existing server
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
