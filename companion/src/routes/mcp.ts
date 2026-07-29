import type { Express, Request, Response } from "express";
import { reloadEnvPrefix } from "../settings/envManager.js";
import { McpClient } from "../integrations/mcp/mcpClient.js";
import { createMcpHttpTransport } from "../integrations/mcp/mcpHttpTransport.js";
import { tokenEnvKey, type McpServer } from "../integrations/mcp/mcpServerStore.js";
import type { McpToolInfo } from "../integrations/mcp/mcpProtocol.js";
import type { RouteContext } from "./context.js";

/**
 * MCP server registry + probe routes (#296, phase 1). Mirrors the external-tool surface rather than
 * inventing a new one — an MCP server is another place an analyst's tooling lives, so it is
 * configured the way custom tools are: /mcp/status parallels /tools/status, the /mcp/servers CRUD
 * parallels /tools/custom, and /mcp/reconnect parallels /tools/reconnect.
 *
 * Phase 1 is registry + reachability only. Running a tool against case evidence needs the delivery
 * layer (§6) and a JobManager job (§7), and lands in phase 3.
 */
export function registerMcpRoutes(app: Express, ctx: RouteContext): void {
  const { options } = ctx;

  /**
   * Last known reachability per server. Domain-local rather than on RouteContext: nothing outside
   * this module needs it, and it is cache, not state — an empty map after a restart just means the
   * next /mcp/status reports "never checked" until something probes.
   */
  const probes = new Map<string, { ok: boolean; at: string; error?: string; tools: McpToolInfo[] }>();

  // Injected in tests so no route test opens a socket; the real one is undici (see mcpHttpTransport).
  const transport = options.mcpTransport ?? createMcpHttpTransport();

  const clientFor = (server: McpServer): McpClient => new McpClient({
    url: server.url,
    transport,
    // Read live from env rather than captured at registration, so POST /mcp/reconnect applies a
    // token saved in Settings without a restart.
    token: process.env[tokenEnvKey(server.id)] || undefined,
    timeoutMs: server.timeoutMs,
  });

  // Configured servers and what is known about them. Never touches the network — reachability comes
  // from the probe cache, so opening the Settings tab cannot hang on an unreachable lab host.
  app.get("/mcp/status", async (_req: Request, res: Response) => {
    if (!options.mcpServerStore) return res.status(501).json({ enabled: false, servers: [] });
    const servers = await options.mcpServerStore.load();
    return res.status(200).json({
      enabled: true,
      servers: servers.map((s) => {
        const probe = probes.get(s.id);
        return {
          id: s.id,
          label: s.label,
          url: s.url,
          enabled: s.enabled,
          allowedTools: s.allowedTools,
          allowedCommands: s.allowedCommands,
          // A server whose permitted tools take a command argument grants execution of whatever
          // that command names, so the UI can warn before the first run rather than after.
          timeoutMs: s.timeoutMs,
          // The KEY, never the value — the token itself stays in .env behind envManager's redaction.
          tokenEnvKey: tokenEnvKey(s.id),
          hasToken: !!process.env[tokenEnvKey(s.id)],
          reachable: probe ? probe.ok : null,   // null = never probed
          checkedAt: probe?.at ?? null,
          error: probe?.error ?? null,
          tools: (probe?.tools ?? []).map((t) => ({ name: t.name, description: t.description })),
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
      return res.status(201).json({ ok: true, server, tokenEnvKey: tokenEnvKey(server.id) });
    } catch (err) {
      return res.status(400).json({ ok: false, error: (err as Error).message });
    }
  });

  app.put("/mcp/servers/:id", async (req: Request, res: Response) => {
    if (!options.mcpServerStore) return res.status(501).json({ error: "MCP servers not enabled" });
    try {
      const server = await options.mcpServerStore.update(req.params.id, req.body ?? {});
      if (!server) return res.status(404).json({ error: `MCP server "${req.params.id}" not found` });
      // The endpoint or token key may have moved; what was known about the old one no longer holds.
      probes.delete(req.params.id);
      return res.status(200).json({ ok: true, server });
    } catch (err) {
      return res.status(400).json({ ok: false, error: (err as Error).message });
    }
  });

  app.delete("/mcp/servers/:id", async (req: Request, res: Response) => {
    if (!options.mcpServerStore) return res.status(501).json({ error: "MCP servers not enabled" });
    const removed = await options.mcpServerStore.remove(req.params.id);
    probes.delete(req.params.id);
    return res.status(200).json({ ok: true, removed });
  });

  /**
   * Handshake with one server and list what it offers — phase 1's verifiable outcome (§12), and how
   * an analyst finds the tool names to put in `allowedTools`.
   *
   * A disabled server is still probeable on purpose: checking that a URL and token work before
   * turning it on is exactly when this is most useful.
   *
   * An unreachable server answers 200 with `ok: false`, not 5xx — the request succeeded, and the
   * answer is "that host is not talking to us", which the UI renders. Same posture as
   * /tools/reconnect, which is likewise always 200.
   */
  app.post("/mcp/servers/:id/probe", async (req: Request, res: Response) => {
    if (!options.mcpServerStore) return res.status(501).json({ error: "MCP servers not enabled" });
    const server = await options.mcpServerStore.get(req.params.id);
    if (!server) return res.status(404).json({ error: `MCP server "${req.params.id}" not found` });

    const client = clientFor(server);
    try {
      const info = await client.initialize();
      const tools = await client.listTools();
      probes.set(server.id, { ok: true, at: new Date().toISOString(), tools });
      return res.status(200).json({ ok: true, server: server.id, info, tools });
    } catch (err) {
      const error = (err as Error).message;
      probes.set(server.id, { ok: false, at: new Date().toISOString(), error, tools: [] });
      return res.status(200).json({ ok: false, server: server.id, error });
    } finally {
      // Best-effort inside the client; a dangling session must not fail an otherwise fine probe.
      await client.close();
    }
  });

  // Re-read DFIR_MCP_* from .env so a token saved via the dashboard applies WITHOUT a restart —
  // the same #1-gotcha fix /tools/reconnect provides. Tokens are read per call, so there is nothing
  // to rebuild; the cached reachability is dropped because a new token may change the answer.
  app.post("/mcp/reconnect", async (_req: Request, res: Response) => {
    try {
      const applied = await reloadEnvPrefix("DFIR_MCP_");
      probes.clear();
      return res.status(200).json({ ok: true, enabled: !!options.mcpServerStore, applied });
    } catch (err) {
      return res.status(500).json({ ok: false, error: (err as Error).message });
    }
  });
}
