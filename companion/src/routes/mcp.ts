import type { Express, Request, Response } from "express";
import { join, basename } from "node:path";
import { randomUUID } from "node:crypto";
import { mkdir, mkdtemp, writeFile, readFile, rm } from "node:fs/promises";
import { reloadEnvPrefix } from "../settings/envManager.js";
import { listServers, type McpBridgeServer } from "../integrations/mcp/mcpBridge.js";
import { spawnTransferRunner } from "../integrations/mcp/mcpDelivery.js";
import { runMcpTool } from "../integrations/mcp/mcpRun.js";
import { runMcpAgent } from "../integrations/mcp/mcpAgentRunner.js";
import { mergeDelta } from "../analysis/stateMerge.js";
import { deltaSchema, type AnalysisDelta } from "../analysis/responseSchema.js";
import type { McpServer } from "../integrations/mcp/mcpServerStore.js";
import { resolveContainedPath } from "../integrations/tools/runToolImport.js";
import { logActivity } from "../analysis/activityLog.js";
import type { InvestigationState } from "../analysis/stateTypes.js";
import type { RouteContext } from "./context.js";

/**
 * MCP policy + run routes (#296).
 *
 * The Companion does not speak MCP and stores no server URL or token: Claude Code is configured with
 * the operator's servers and holds their credentials, and every call goes through it. What lives
 * here is policy — of the servers Claude Code has, which the Companion may point case evidence at,
 * which tools they may run, which binaries those tools may invoke, and how evidence reaches them.
 *
 * /mcp/status therefore reports two things side by side: what Claude Code is configured with, and
 * what the Companion has policy for. A name in one and not the other is visible rather than
 * mysterious.
 */
export function registerMcpRoutes(app: Express, ctx: RouteContext): void {
  const { store, options, recordImportFailure, ingestStreamed, pushImportCheckpoint } = ctx;

  /**
   * What Claude Code last reported. Domain-local rather than on RouteContext: nothing outside this
   * module needs it, and it is cache, not state — empty after a restart just means /mcp/status says
   * "not checked" until something refreshes it.
   */
  let discovered: { at: string; servers: McpBridgeServer[]; error?: string } | null = null;

  // Injected in tests so no route test spawns the CLI or scp.
  const transferRunner = options.mcpTransferRunner ?? spawnTransferRunner();
  const claudeBin = process.env.DFIR_AI_CLAUDE_CODE_BIN;
  const claudeModel = process.env.DFIR_MCP_MODEL;

  // Policy plus whatever Claude Code last reported. Never spawns anything: discovery is a cached
  // `claude mcp list`, so opening the Settings tab cannot hang behind a slow MCP server starting up.
  app.get("/mcp/status", async (_req: Request, res: Response) => {
    if (!options.mcpServerStore) return res.status(501).json({ enabled: false, servers: [], claudeCode: null });
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

  interface StagedPreview { server: string; tool: string; label: string; kind: string; outName: string; runId?: string }

  /**
   * Identifies THIS process. JobManager numbers jobs from 1 on every start, and a preview is named
   * after its job, so without this a restart makes job_1's stale file answer for a brand-new job_1 —
   * observed in testing, serving a previous run's output as if it were the current one.
   */
  const RUN_ID = randomUUID();

  async function stagePreview(caseId: string, jobId: string, p: StagedPreview & { text: string }): Promise<void> {
    if (!isJobId(jobId)) return;
    const dir = previewDir(caseId);
    await mkdir(dir, { recursive: true });
    const { text, ...rest } = p;
    const meta: StagedPreview = { ...rest, runId: RUN_ID };
    await writeFile(join(dir, `${jobId}.out`), text, "utf8");
    await writeFile(join(dir, `${jobId}.json`), JSON.stringify(meta), "utf8");
  }

  async function readPreview(caseId: string, jobId: string): Promise<(StagedPreview & { text: string }) | null> {
    if (!isJobId(jobId)) return null;
    const dir = previewDir(caseId);
    try {
      const meta = JSON.parse(await readFile(join(dir, `${jobId}.json`), "utf8")) as StagedPreview;
      // A preview from a previous process is not this job's — drop it rather than serve it.
      if (meta.runId !== RUN_ID) { await dropPreview(caseId, jobId); return null; }
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
          ...(options.mcpClaudeRunner ? { claudeRunner: options.mcpClaudeRunner } : {}),
          ...(claudeBin ? { claudeBin } : {}),
          ...(claudeModel ? { model: claudeModel } : {}),
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
        const result = await runMcpAgent({
          servers, prompt,
          ...(claudeBin ? { bin: claudeBin } : {}),
          ...(process.env.DFIR_MCP_AGENT_MODEL ? { model: process.env.DFIR_MCP_AGENT_MODEL } : {}),
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

  // Kept as the dashboard's "refresh" affordance. There is no token to reload any more — Claude Code
  // holds those — so this re-reads DFIR_MCP_* (model/flag settings) and drops the cached discovery so
  // the next status reflects a server added to Claude Code since.
  app.post("/mcp/reconnect", async (_req: Request, res: Response) => {
    try {
      const applied = await reloadEnvPrefix("DFIR_MCP_");
      discovered = null;
      return res.status(200).json({ ok: true, enabled: !!options.mcpServerStore, applied });
    } catch (err) {
      return res.status(500).json({ ok: false, error: (err as Error).message });
    }
  });
}
