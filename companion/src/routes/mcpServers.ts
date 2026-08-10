import type { Express, Request, Response } from "express";
import type { RouteContext } from "./context.js";
import { reloadEnvPrefix } from "../settings/envManager.js";
import { listServers, listTools, type McpBridgeServer } from "../integrations/mcp/mcpBridge.js";

// The MCP server REGISTRY: which servers exist, what they are allowed to do, what Claude Code says
// they offer, and the refresh affordance that re-reads DFIR_MCP_* settings.
//
// Lifted out of routes/mcp.ts, which the file-size ledger had frozen at 845 lines. The seam is
// ownership of state: everything left in that module RUNS something against a case — a tool, an
// upload, an agent prompt — and reads the registry as configuration. These routes are the only
// writers of it, and the only users of the two caches below.
//
// `discovered` and `toolsByServer` move WITH the routes rather than being shared back. They are
// caches of what Claude Code last reported, invalidated by POST /mcp/reconnect, and leaving them
// behind would have meant two modules mutating one cache with no owner — the arrangement that makes
// a stale picker hint impossible to attribute.
//
// MOVED VERBATIM: route bodies, status codes and the 200-with-ok:false posture are unchanged.

export function registerMcpServerRoutes(app: Express, ctx: RouteContext): void {
  const { options } = ctx;
  /** Whatever Claude Code last reported from `claude mcp list`, or null before the first discovery. */
  let discovered: { at: string; servers: McpBridgeServer[]; error?: string } | null = null;
  /** Tool names per server, as Claude Code last reported them. A picker hint, never a gate. */
  const toolsByServer = new Map<string, string[]>();
  const claudeBin = process.env.DFIR_AI_CLAUDE_CODE_BIN;
  const claudeModel = process.env.DFIR_MCP_MODEL;

  // Policy plus whatever Claude Code last reported. Never spawns anything: discovery is a cached
  // `claude mcp list`, so opening the Settings tab cannot hang behind a slow MCP server starting up.
  app.get("/mcp/status", async (_req: Request, res: Response) => {
    if (!options.mcpServerStore)
      return res.status(501).json({ enabled: false, servers: [], claudeCode: null });
    const servers = await options.mcpServerStore.load();
    const byName = new Map((discovered?.servers ?? []).map((d) => [d.name, d]));
    return res.status(200).json({
      enabled: true,
      // What Claude Code has, so the dashboard can offer real names instead of asking for free text
      // and can show a policy entry whose server has since disappeared.
      claudeCode: discovered
        ? { at: discovered.at, error: discovered.error ?? null, servers: discovered.servers }
        : null,
      servers: servers.map((s) => {
        const seen = byName.get(s.id);
        return {
          id: s.id,
          label: s.label,
          enabled: s.enabled,
          agentEnabled: s.agentEnabled,
          allowedTools: s.allowedTools,
          allowedCommands: s.allowedCommands,
          timeoutMs: s.timeoutMs,
          // How evidence reaches it (§6). No secrets — an ssh key is a path, never a value.
          delivery: s.delivery,
          // null = Claude Code has not been asked yet; false = asked, and it has no such server.
          knownToClaudeCode: discovered ? !!seen : null,
          connected: seen ? seen.connected : null,
          status: seen ? seen.status : null,
          // What the server offers, when it has been asked. Populates the run form's tool picker;
          // the allowlist, when set, narrows what may actually run.
          tools: toolsByServer.get(s.id) ?? [],
        };
      }),
    });
  });

  app.get("/mcp/servers", async (_req: Request, res: Response) => {
    if (!options.mcpServerStore) return res.status(501).json({ error: "MCP servers not enabled" });
    return res.status(200).json({ servers: await options.mcpServerStore.load() });
  });

  app.post("/mcp/servers", async (req: Request, res: Response) => {
    if (!options.mcpServerStore) return res.status(501).json({ error: "MCP servers not enabled" });
    try {
      const server = await options.mcpServerStore.add(req.body ?? {});
      return res.status(201).json({ ok: true, server });
    } catch (err) {
      return res.status(400).json({ ok: false, error: (err as Error).message });
    }
  });

  app.put("/mcp/servers/:id", async (req: Request, res: Response) => {
    if (!options.mcpServerStore) return res.status(501).json({ error: "MCP servers not enabled" });
    try {
      const server = await options.mcpServerStore.update(req.params.id, req.body ?? {});
      if (!server) return res.status(404).json({ error: `MCP server "${req.params.id}" not found` });
      return res.status(200).json({ ok: true, server });
    } catch (err) {
      return res.status(400).json({ ok: false, error: (err as Error).message });
    }
  });

  app.delete("/mcp/servers/:id", async (req: Request, res: Response) => {
    if (!options.mcpServerStore) return res.status(501).json({ error: "MCP servers not enabled" });
    const removed = await options.mcpServerStore.remove(req.params.id);
    return res.status(200).json({ ok: true, removed });
  });

  /**
   * Ask Claude Code which MCP servers it is configured with, and whether each is answering.
   *
   * This is the whole of discovery: the Companion has no URL to connect to and no token to present,
   * so "is it reachable" is a question only Claude Code can answer. The reply carries names and
   * health and nothing else — `claude mcp list` prints each server's full command line, which for an
   * mcp-remote entry contains a bearer token, and mcpBridge drops that portion before it gets here.
   *
   * A failure answers 200 with `ok: false`, not 5xx: the request succeeded and the answer is "Claude
   * Code could not tell us", which the UI renders. Same posture as /tools/reconnect.
   */
  app.post("/mcp/discover", async (_req: Request, res: Response) => {
    if (!options.mcpServerStore) return res.status(501).json({ error: "MCP servers not enabled" });
    try {
      const found = await listServers({
        ...(options.mcpClaudeRunner ? { runner: options.mcpClaudeRunner } : {}),
        ...(claudeBin ? { bin: claudeBin } : {}),
      });
      discovered = { at: new Date().toISOString(), servers: found };
      return res.status(200).json({ ok: true, servers: found });
    } catch (err) {
      const error = (err as Error).message;
      discovered = { at: new Date().toISOString(), servers: [], error };
      return res.status(200).json({ ok: false, error });
    }
  });

  /**
   * Ask Claude Code which tools a server offers, and cache the answer for the picker.
   *
   * A hint, not a gate: `claude mcp list` reports servers but not their tools, and the Companion
   * cannot ask the server itself, so this is a model answer. The run form accepts a hand-typed tool
   * name regardless, and the allowlist — when an operator sets one — is what actually bounds a call.
   *
   * 200 with ok:false when Claude Code cannot answer, same posture as /mcp/discover.
   */
  app.post("/mcp/servers/:id/tools", async (req: Request, res: Response) => {
    if (!options.mcpServerStore) return res.status(501).json({ error: "MCP servers not enabled" });
    const server = await options.mcpServerStore.get(req.params.id);
    if (!server) return res.status(404).json({ error: `MCP server "${req.params.id}" not found` });
    try {
      const tools = await listTools({
        server: server.id,
        ...(options.mcpClaudeRunner ? { runner: options.mcpClaudeRunner } : {}),
        ...(claudeBin ? { bin: claudeBin } : {}),
        ...(claudeModel ? { model: claudeModel } : {}),
      });
      toolsByServer.set(server.id, tools);
      return res.status(200).json({ ok: true, server: server.id, tools });
    } catch (err) {
      return res.status(200).json({ ok: false, server: server.id, error: (err as Error).message });
    }
  });

  // Kept as the dashboard's "refresh" affordance. There is no token to reload any more — Claude Code
  // holds those — so this re-reads DFIR_MCP_* (model/flag settings) and drops the cached discovery so
  // the next status reflects a server added to Claude Code since.
  app.post("/mcp/reconnect", async (_req: Request, res: Response) => {
    try {
      const applied = await reloadEnvPrefix("DFIR_MCP_");
      discovered = null;
      toolsByServer.clear();
      return res.status(200).json({ ok: true, enabled: !!options.mcpServerStore, applied });
    } catch (err) {
      return res.status(500).json({ ok: false, error: (err as Error).message });
    }
  });
}
