import type { Express, Request, Response } from "express";
import { join, basename } from "node:path";
import { mkdir, mkdtemp, writeFile, readFile, rm } from "node:fs/promises";
import { reloadEnvPrefix } from "../settings/envManager.js";
import { McpClient } from "../integrations/mcp/mcpClient.js";
import { createMcpHttpTransport } from "../integrations/mcp/mcpHttpTransport.js";
import { spawnTransferRunner } from "../integrations/mcp/mcpDelivery.js";
import { runMcpTool } from "../integrations/mcp/mcpRun.js";
import { runMcpAgent } from "../integrations/mcp/mcpAgentRunner.js";
import { mergeDelta } from "../analysis/stateMerge.js";
import { deltaSchema, type AnalysisDelta } from "../analysis/responseSchema.js";
import { tokenEnvKey, type McpServer } from "../integrations/mcp/mcpServerStore.js";
import { resolveContainedPath } from "../integrations/tools/runToolImport.js";
import { logActivity } from "../analysis/activityLog.js";
import type { McpToolInfo } from "../integrations/mcp/mcpProtocol.js";
import type { InvestigationState } from "../analysis/stateTypes.js";
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
  const { store, options, recordImportFailure, ingestStreamed, pushImportCheckpoint } = ctx;

  /**
   * Last known reachability per server. Domain-local rather than on RouteContext: nothing outside
   * this module needs it, and it is cache, not state — an empty map after a restart just means the
   * next /mcp/status reports "never checked" until something probes.
   */
  const probes = new Map<string, { ok: boolean; at: string; error?: string; tools: McpToolInfo[] }>();

  // Injected in tests so no route test opens a socket; the real one is undici (see mcpHttpTransport).
  const transport = options.mcpTransport ?? createMcpHttpTransport();
  // Likewise for the file push — tests inject rather than spawning scp.
  const transferRunner = options.mcpTransferRunner ?? spawnTransferRunner();

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
          // How evidence reaches it (§6). No secrets in here — an ssh key is a path, never a value.
          delivery: s.delivery,
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

  /**
   * Everything a run needs, or an HTTP failure. Shared by the on-disk and upload routes so their
   * refusals cannot drift apart.
   */
  async function resolveRun(req: Request, res: Response): Promise<{ server: McpServer; tool: string; args: Record<string, unknown> } | null> {
    const caseId = req.params.id;
    if (!options.mcpServerStore) { res.status(501).json({ error: "MCP servers not enabled" }); return null; }
    if (!(await store.caseExists(caseId))) { res.status(404).json({ error: `case ${caseId} does not exist` }); return null; }
    // Same write guard as every other evidence route: a closed or archived case takes no new imports.
    const caseMeta = await store.getCaseMeta(caseId).catch(() => null);
    if (caseMeta?.status === "closed" || caseMeta?.status === "archived") {
      const action = caseMeta.status === "archived" ? "restore it" : "reopen it";
      res.status(423).json({ error: `Case "${caseId}" is ${caseMeta.status} — ${action} before running a tool` });
      return null;
    }
    const server = await options.mcpServerStore.get(req.params.serverId);
    if (!server) { res.status(400).json({ error: `unknown MCP server "${req.params.serverId}"` }); return null; }
    if (!server.enabled) { res.status(400).json({ error: `MCP server "${server.id}" is disabled` }); return null; }
    const tool = typeof req.body?.tool === "string" ? req.body.tool.trim() : "";
    if (!tool) { res.status(400).json({ error: "tool is required" }); return null; }
    const args = (req.body?.args ?? {}) as Record<string, unknown>;
    if (typeof args !== "object" || Array.isArray(args)) { res.status(400).json({ error: "args must be an object" }); return null; }
    return { server, tool, args };
  }

  /**
   * Ingest one tool's output through the same chain as every other import, with an undo checkpoint.
   * Shared by the direct run and the approve-a-preview path so the two cannot diverge in what they
   * write or what they make reversible.
   */
  async function ingestMcpOutput(
    caseId: string, serverId: string, tool: string, label: string,
    kind: string, text: string, outName: string,
  ): Promise<{ addedEvents: number; addedIocs: number }> {
    let before: InvestigationState | null = null;
    if (options.stateStore) { try { before = await options.stateStore.load(caseId); } catch { /* keep null */ } }
    const r = await ingestStreamed(caseId, kind, text, outName);
    // An MCP tool can produce reference data as readily as evidence — a capability listing looks
    // exactly like a Volatility table to any detector — so the checkpoint matters more here than on
    // a path where the input was chosen from disk. One click puts the case back.
    if (before && (r.addedEvents > 0 || r.addedIocs > 0)) {
      await pushImportCheckpoint(caseId, before, `MCP: ${serverId}/${tool}`);
    }
    void label;
    return r;
  }

  /**
   * Merge an agent's delta into case state, with an undo checkpoint.
   *
   * Goes through mergeDelta — the same path every other AI response takes — rather than the import
   * chain, because a delta is already findings/IOCs/events and has no file format to detect. The
   * delta was schema-validated and stripped of `extractedFrom` in the runner: everything the agent
   * saw came from tool output, which is untrusted.
   */
  async function applyAgentDelta(
    caseId: string, serverLabel: string, delta: AnalysisDelta,
  ): Promise<{ findings: number; iocs: number; events: number }> {
    if (!options.stateStore) throw new Error("state store not configured");
    const before = await options.stateStore.load(caseId);
    const merged = mergeDelta(before, delta, {
      windowSequence: 0,
      timestamp: new Date().toISOString(),
      sourceScreenshots: [],
    });
    await options.stateStore.save(merged);
    const counts = {
      findings: merged.findings.length - before.findings.length,
      iocs: merged.iocs.length - before.iocs.length,
      events: merged.forensicTimeline.length - before.forensicTimeline.length,
    };
    if (counts.findings > 0 || counts.iocs > 0 || counts.events > 0) {
      await pushImportCheckpoint(caseId, before, `MCP agent: ${serverLabel}`);
    }
    options.onState?.(merged);
    return counts;
  }

  /** The kind an agent preview is staged under; it is a delta, not a file any importer detects. */
  const AGENT_DELTA_KIND = "mcp-agent-delta";

  // A job id is the preview's filename, and it arrives from the client on the approve/discard
  // routes. Only the shape JobManager mints is accepted, so nothing can walk out of the directory.
  const isJobId = (v: string): boolean => /^job_\d+$/.test(v);
  const previewDir = (caseId: string): string => join(store.caseDir(caseId), ".mcpwork", "preview");

  interface StagedPreview { server: string; tool: string; label: string; kind: string; outName: string }

  async function stagePreview(caseId: string, jobId: string, p: StagedPreview & { text: string }): Promise<void> {
    if (!isJobId(jobId)) return;
    const dir = previewDir(caseId);
    await mkdir(dir, { recursive: true });
    const { text, ...meta } = p;
    await writeFile(join(dir, `${jobId}.out`), text, "utf8");
    await writeFile(join(dir, `${jobId}.json`), JSON.stringify(meta), "utf8");
  }

  async function readPreview(caseId: string, jobId: string): Promise<(StagedPreview & { text: string }) | null> {
    if (!isJobId(jobId)) return null;
    const dir = previewDir(caseId);
    try {
      const meta = JSON.parse(await readFile(join(dir, `${jobId}.json`), "utf8")) as StagedPreview;
      return { ...meta, text: await readFile(join(dir, `${jobId}.out`), "utf8") };
    } catch {
      return null;
    }
  }

  async function dropPreview(caseId: string, jobId: string): Promise<void> {
    if (!isJobId(jobId)) return;
    const dir = previewDir(caseId);
    await rm(join(dir, `${jobId}.out`), { force: true }).catch(() => { /* best-effort */ });
    await rm(join(dir, `${jobId}.json`), { force: true }).catch(() => { /* best-effort */ });
  }

  /**
   * Deliver, call, ingest — under a job, in the background.
   *
   * Backgrounded rather than awaited because this is the one import path with no useful upper bound:
   * ToolConfig's 300s default does not survive Volatility on a real memory image (§7). The job
   * carries the progress, the WS broadcast and the cancel button; `onDone` releases anything the
   * caller staged, once the run is genuinely finished rather than when the request returned.
   */
  function startRun(
    caseId: string, server: McpServer, tool: string, args: Record<string, unknown>,
    targetPath: string | undefined, label: string, preview: boolean, onDone?: () => Promise<void>,
  ): string | null {
    const job = options.jobManager?.register({
      caseId, kind: "mcp", label: `${server.id}/${tool}${preview ? " (preview)" : ""}`, detail: "starting", cancellable: true,
    });

    void (async () => {
      try {
        const outcome = await runMcpTool({
          server,
          client: clientFor(server),
          transferRunner,
          signal: job?.signal,
          onProgress: (detail) => { if (job) options.jobManager?.progress(job.jobId, 0, 1, detail); },
          // Where recordTransfer (#231) meets its producer: evidence leaving this box for an
          // analysis host is the canonical `transferred` event, and the chain records it before the
          // tool ever runs.
          recordTransfer: options.custodyStore && targetPath
            ? async (destination) => {
              await options.custodyStore!.recordTransfer(caseId, {
                artifactPaths: [targetPath],
                transferredBy: "analyst",
                destination,
                trigger: `mcp:${server.id}`,
              });
            }
            : undefined,
        }, { tool, args, targetPath });

        // §8's rough edge: the tool-runner's generic "could not detect the tool output's format"
        // names neither the server nor the tool, and with several of each configured that is most
        // of what the analyst needs to know. Both refusals below name them.
        //
        // The two cases really are different. Detection falls unstructured prose through to the
        // generic "log" kind, so "unknown" here means the output was EMPTY — telling someone their
        // output is in an unrecognized format when there was no output sends them debugging the
        // wrong thing.
        if (!outcome.text.trim()) {
          throw new Error(`${server.id}/${tool}: returned no output — nothing to import`);
        }
        const outName = `${basename(targetPath ?? tool)}.${server.id}-${tool}.out`;
        const kind = ctx.resolveImportKind()(outName, outcome.text);
        if (kind === "unknown") {
          throw new Error(
            `${server.id}/${tool}: returned ${outcome.text.length} byte(s) in no recognized format` +
            ` — have the tool emit JSON, or add a custom importer for it`,
          );
        }

        if (preview) {
          // Held on disk rather than re-run on approval: importing must not mean executing the tool
          // a second time. That would double the cost of a Volatility run and, for a tool with side
          // effects, do the thing twice.
          await stagePreview(caseId, job?.jobId ?? "", { server: server.id, tool, label, kind, outName, text: outcome.text });
          if (job) options.jobManager?.finish(job.jobId);
          logActivity(options.activityLogStore, options.onActivity, caseId, {
            category: "import", action: "mcp-preview",
            detail: `${server.id}/${tool} on ${label} → ${outcome.text.length} byte(s), detected as "${kind}" — awaiting review`
              + (outcome.destination ? ` (evidence sent to ${outcome.destination})` : ""),
          });
          return;
        }

        const r = await ingestMcpOutput(caseId, server.id, tool, label, kind, outcome.text, outName);
        if (job) options.jobManager?.finish(job.jobId);
        logActivity(options.activityLogStore, options.onActivity, caseId, {
          category: "import", action: "mcp-run",
          detail: `${server.id}/${tool} on ${label} → ${r.addedEvents} event(s), ${r.addedIocs} IOC(s)`
            + (outcome.destination ? ` (evidence sent to ${outcome.destination})` : ""),
        });
      } catch (err) {
        if (job) options.jobManager?.fail(job.jobId, err);
        recordImportFailure(caseId, `mcp:${server.id}/${tool}`, label, err);
        logActivity(options.activityLogStore, options.onActivity, caseId, {
          category: "import", action: "mcp-run",
          detail: `${server.id}/${tool} on ${label} FAILED: ${(err as Error).message}`,
        });
      } finally {
        await onDone?.().catch(() => { /* best-effort */ });
      }
    })();

    return job?.jobId ?? null;
  }

  /**
   * Run a tool against a file already inside the case directory. Body:
   * `{ tool, args, targetPath? }`, where `<target>` anywhere in `args` becomes the path the
   * analysis host sees once delivery has run.
   */
  app.post("/cases/:id/mcp/:serverId/run", async (req: Request, res: Response) => {
    const resolved = await resolveRun(req, res);
    if (!resolved) return;
    const caseId = req.params.id;

    let targetPath: string | undefined;
    const raw = typeof req.body?.targetPath === "string" ? req.body.targetPath.trim() : "";
    if (raw) {
      try {
        targetPath = resolveContainedPath(store.caseDir(caseId), raw);
      } catch (err) {
        return res.status(400).json({ error: (err as Error).message });
      }
    }

    const preview = req.body?.preview === true;
    const jobId = startRun(caseId, resolved.server, resolved.tool, resolved.args, targetPath, raw || resolved.tool, preview);
    return res.status(202).json({ ok: true, jobId, server: resolved.server.id, tool: resolved.tool, preview });
  });

  /**
   * What a preview run produced, for the analyst to judge before any of it reaches the case.
   *
   * This exists because an MCP tool can return reference data as readily as evidence — a capability
   * listing is structurally identical to a Volatility table, so no detector can tell them apart —
   * and the only reliable judge of which one arrived is the person who asked for it.
   *
   * The body is capped: a preview can be tens of megabytes and the point is to recognize the shape
   * of the thing, which the first few kilobytes settle.
   */
  const PREVIEW_CHARS = 8 * 1024;
  app.get("/cases/:id/mcp/preview/:jobId", async (req: Request, res: Response) => {
    if (!options.mcpServerStore) return res.status(501).json({ error: "MCP servers not enabled" });
    if (!(await store.caseExists(req.params.id))) return res.status(404).json({ error: `case ${req.params.id} does not exist` });
    const p = await readPreview(req.params.id, req.params.jobId);
    if (!p) return res.status(404).json({ error: "no preview for that run — it may have been imported, discarded, or lost to a restart" });
    return res.status(200).json({
      server: p.server, tool: p.tool, kind: p.kind, bytes: p.text.length,
      text: p.text.slice(0, PREVIEW_CHARS), truncated: p.text.length > PREVIEW_CHARS,
    });
  });

  /** Approve a preview: ingest exactly the bytes already fetched, then drop the staged copy. */
  app.post("/cases/:id/mcp/preview/:jobId/import", async (req: Request, res: Response) => {
    const caseId = req.params.id;
    if (!options.mcpServerStore) return res.status(501).json({ error: "MCP servers not enabled" });
    if (!(await store.caseExists(caseId))) return res.status(404).json({ error: `case ${caseId} does not exist` });
    const caseMeta = await store.getCaseMeta(caseId).catch(() => null);
    if (caseMeta?.status === "closed" || caseMeta?.status === "archived") {
      const action = caseMeta.status === "archived" ? "restore it" : "reopen it";
      return res.status(423).json({ error: `Case "${caseId}" is ${caseMeta.status} — ${action} before importing` });
    }
    const p = await readPreview(caseId, req.params.jobId);
    if (!p) return res.status(404).json({ error: "no preview for that run — it may have been imported, discarded, or lost to a restart" });
    try {
      // An agent preview holds a delta, not tool output — merge it rather than routing it through
      // importers that have no format to detect.
      if (p.kind === AGENT_DELTA_KIND) {
        const r = await applyAgentDelta(caseId, p.tool, deltaSchema.parse(JSON.parse(p.text)));
        await dropPreview(caseId, req.params.jobId);
        logActivity(options.activityLogStore, options.onActivity, caseId, {
          category: "ai", action: "mcp-agent",
          detail: `agent on ${p.tool} imported after review → ${r.findings} finding(s), ${r.iocs} IOC(s), ${r.events} event(s)`,
        });
        return res.status(200).json({ ok: true, addedEvents: r.events, addedIocs: r.iocs, addedFindings: r.findings });
      }
      const r = await ingestMcpOutput(caseId, p.server, p.tool, p.label, p.kind, p.text, p.outName);
      await dropPreview(caseId, req.params.jobId);
      logActivity(options.activityLogStore, options.onActivity, caseId, {
        category: "import", action: "mcp-run",
        detail: `${p.server}/${p.tool} on ${p.label} imported after review → ${r.addedEvents} event(s), ${r.addedIocs} IOC(s)`,
      });
      return res.status(200).json({ ok: true, addedEvents: r.addedEvents, addedIocs: r.addedIocs });
    } catch (err) {
      recordImportFailure(caseId, `mcp:${p.server}/${p.tool}`, p.label, err);
      return res.status(400).json({ ok: false, error: (err as Error).message });
    }
  });

  /** Reject a preview: the fetched output is thrown away and the case is untouched. */
  app.delete("/cases/:id/mcp/preview/:jobId", async (req: Request, res: Response) => {
    if (!options.mcpServerStore) return res.status(501).json({ error: "MCP servers not enabled" });
    if (!(await store.caseExists(req.params.id))) return res.status(404).json({ error: `case ${req.params.id} does not exist` });
    const p = await readPreview(req.params.id, req.params.jobId);
    await dropPreview(req.params.id, req.params.jobId);
    if (p) {
      logActivity(options.activityLogStore, options.onActivity, req.params.id, {
        category: "import", action: "mcp-preview",
        detail: `${p.server}/${p.tool} on ${p.label} discarded after review — nothing imported`,
      });
    }
    return res.status(200).json({ ok: true, discarded: !!p });
  });

  /**
   * Run a tool against bytes uploaded from the dashboard — the small-binary path, for a sample the
   * browser holds and the server has no path to. Staged into a fresh per-upload dir INSIDE the case
   * so path containment holds, and removed once the job finishes, not when this request returns.
   */
  app.post("/cases/:id/mcp/:serverId/run-upload", async (req: Request, res: Response) => {
    const resolved = await resolveRun(req, res);
    if (!resolved) return;
    const caseId = req.params.id;

    const filename = String(req.body?.filename ?? "").trim();
    const dataBase64 = typeof req.body?.dataBase64 === "string" ? req.body.dataBase64 : "";
    if (!filename || !dataBase64) return res.status(400).json({ error: "filename and dataBase64 are required" });

    const work = join(store.caseDir(caseId), ".mcpwork");
    const safe = basename(filename).replace(/[^\w.\-]+/g, "_").slice(0, 120) || "raw.bin";
    let stageDir = "";
    try {
      await mkdir(work, { recursive: true });
      stageDir = await mkdtemp(join(work, "up-"));
      const staged = join(stageDir, safe);
      await writeFile(staged, Buffer.from(dataBase64, "base64"));

      const dir = stageDir;
      const preview = req.body?.preview === true;
      const jobId = startRun(
        caseId, resolved.server, resolved.tool, resolved.args, staged, filename, preview,
        () => rm(dir, { recursive: true, force: true }),
      );
      return res.status(202).json({ ok: true, jobId, server: resolved.server.id, tool: resolved.tool, preview });
    } catch (err) {
      if (stageDir) await rm(stageDir, { recursive: true, force: true }).catch(() => { /* best-effort */ });
      return res.status(400).json({ ok: false, error: (err as Error).message });
    }
  });

  /**
   * Agentic mode (§7 Mode 2), behind DFIR_MCP_AGENT_ENABLED. Body: `{ prompt, servers?, preview? }`.
   *
   * Two independent opt-ins, because this grants more than a manual run: the feature flag, and
   * `agentEnabled` on each server. Enabling the feature does not expose any server, and registering
   * a server does not expose it to the agent. mcpAgentRunner's header explains why — the companion
   * is not the MCP client in this mode, so the command allowlist cannot be enforced.
   *
   * Preview is honoured here too, and matters more: an autonomous loop decides for itself what to
   * report, so reading it before it lands is worth more than on a single deterministic call.
   */
  app.post("/cases/:id/mcp/agent", async (req: Request, res: Response) => {
    const caseId = req.params.id;
    if (!options.mcpServerStore) return res.status(501).json({ error: "MCP servers not enabled" });
    if (!/^(1|true|on|yes)$/i.test(String(process.env.DFIR_MCP_AGENT_ENABLED ?? "").trim())) {
      return res.status(501).json({ error: "agentic MCP mode is off — set DFIR_MCP_AGENT_ENABLED=on to enable it" });
    }
    if (!(await store.caseExists(caseId))) return res.status(404).json({ error: `case ${caseId} does not exist` });
    const caseMeta = await store.getCaseMeta(caseId).catch(() => null);
    if (caseMeta?.status === "closed" || caseMeta?.status === "archived") {
      const action = caseMeta.status === "archived" ? "restore it" : "reopen it";
      return res.status(423).json({ error: `Case "${caseId}" is ${caseMeta.status} — ${action} before running the agent` });
    }
    const prompt = typeof req.body?.prompt === "string" ? req.body.prompt.trim() : "";
    if (!prompt) return res.status(400).json({ error: "prompt is required" });

    const wanted = Array.isArray(req.body?.servers) ? (req.body.servers as unknown[]).map(String) : null;
    const all = await options.mcpServerStore.load();
    const servers = all.filter((s) => s.enabled && s.agentEnabled && (!wanted || wanted.includes(s.id)));
    if (servers.length === 0) {
      return res.status(400).json({ error: "no agent-enabled MCP servers — turn on agent use for a server first" });
    }
    if (servers.every((s) => s.allowedTools.length === 0)) {
      return res.status(400).json({ error: "the selected server(s) have no allowed tools — name the tools the agent may use" });
    }

    const preview = req.body?.preview === true;
    const job = options.jobManager?.register({
      caseId, kind: "mcp", label: `agent (${servers.map((s) => s.id).join(", ")})${preview ? " (preview)" : ""}`,
      detail: "starting", cancellable: true,
    });

    void (async () => {
      try {
        const tokens: Record<string, string | undefined> = {};
        for (const s of servers) tokens[s.id] = process.env[tokenEnvKey(s.id)];
        const result = await runMcpAgent({
          servers, tokens, prompt,
          workDir: join(store.caseDir(caseId), ".mcpwork"),
          bin: process.env.DFIR_AI_CLAUDE_CODE_BIN,
          model: process.env.DFIR_MCP_AGENT_MODEL,
          ...(options.mcpAgentRunner ? { runner: options.mcpAgentRunner } : {}),
          ...(job?.signal ? { signal: job.signal } : {}),
        });

        if (preview) {
          await stagePreview(caseId, job?.jobId ?? "", {
            server: "agent", tool: servers.map((s) => s.id).join("+"), label: prompt.slice(0, 80),
            kind: AGENT_DELTA_KIND, outName: `agent.${Date.now()}.json`, text: JSON.stringify(result.delta, null, 2),
          });
          if (job) options.jobManager?.finish(job.jobId);
          logActivity(options.activityLogStore, options.onActivity, caseId, {
            category: "ai", action: "mcp-agent",
            detail: `agent on ${servers.map((s) => s.id).join(", ")} → awaiting review`,
          });
          return;
        }

        const r = await applyAgentDelta(caseId, servers.map((s) => s.id).join(", "), result.delta);
        if (job) options.jobManager?.finish(job.jobId);
        logActivity(options.activityLogStore, options.onActivity, caseId, {
          category: "ai", action: "mcp-agent",
          detail: `agent on ${servers.map((s) => s.id).join(", ")} → ${r.findings} finding(s), ${r.iocs} IOC(s), ${r.events} event(s)`,
        });
      } catch (err) {
        if (job) options.jobManager?.fail(job.jobId, err);
        logActivity(options.activityLogStore, options.onActivity, caseId, {
          category: "ai", action: "mcp-agent",
          detail: `agent on ${servers.map((s) => s.id).join(", ")} FAILED: ${(err as Error).message}`,
        });
      }
    })();

    return res.status(202).json({ ok: true, jobId: job?.jobId ?? null, servers: servers.map((s) => s.id), preview });
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
