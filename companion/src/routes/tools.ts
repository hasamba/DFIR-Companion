import type { Express, Request, Response } from "express";
import { join, basename } from "node:path";
import { writeFile, rm, mkdir, mkdtemp } from "node:fs/promises";
import { reloadEnvPrefix } from "../settings/envManager.js";
import {
  TOOL_DEFS,
  uploadExtensionAccepted,
  uploadExtensionOf,
  type ToolId,
} from "../integrations/tools/toolConfig.js";
import { updateToolRules } from "../integrations/tools/runToolImport.js";
import { resolveForensicMinSeverity } from "../analysis/forensicGate.js";
import { logActivity } from "../analysis/activityLog.js";
import type { Severity } from "../analysis/stateTypes.js";
import type { RouteContext } from "./context.js";

/**
 * External-tool runner + forensic-gate routes: the top-level /tools* config/registry and custom-tool
 * CRUD (#211), the per-case /cases/:id/tools/:toolId/{run,run-upload,update-rules} runner endpoints,
 * and the per-case /cases/:id/forensic-gate severity-cut config.
 *
 * Pure structural move out of createApp (see routes/system.ts for the conventions). The tool-runner
 * machinery itself stays in createApp — the drop-folder auto-run poller and the drop batch route
 * (/cases/:id/drop/run-pending) also drive it, so this module reaches it through the RouteContext
 * members it was graduated onto: runToolAndIngest + reloadCustomTools (stable methods) and the
 * liveToolConfigs + customTools live accessors (call ctx.liveToolConfigs()/ctx.customTools() INSIDE
 * the handler). NOTE: /cases/:id/drop/run-pending is NOT here — it belongs to the drop-folder domain
 * and stays in createApp even though it sits amid the tool routes.
 */
export function registerToolsRoutes(app: Express, ctx: RouteContext): void {
  const { store, options, recordImportFailure, runToolAndIngest, reloadCustomTools } = ctx;

  // A tool id is known when it's a configured built-in or a defined custom tool. Rebuilt here (the
  // createApp original read its closure `customTools`); the live custom-tool list comes from ctx.
  const isKnownTool = (toolId: string): boolean =>
    toolId in TOOL_DEFS || ctx.customTools().some((t) => t.id === toolId);

  // How this tool is reached. Custom tools are always local binaries, so anything not a built-in
  // is "spawn". Used to decide whether the toolRunner (the PROCESS SPAWNER) is required — an HTTP
  // tool like SO-CRATES must work on a machine with no local forensic binaries installed.
  const transportOf = (toolId: string): "spawn" | "http" =>
    toolId in TOOL_DEFS ? TOOL_DEFS[toolId as ToolId].transport : "spawn";

  // The raw extensions this tool claims. Built-ins declare them statically; a custom tool carries the
  // analyst's list. Empty for a tool that claims none (YARA) — see uploadExtensionAccepted.
  const extensionsOf = (toolId: string): string[] =>
    toolId in TOOL_DEFS
      ? TOOL_DEFS[toolId as ToolId].extensions
      : (ctx.customTools().find((t) => t.id === toolId)?.extensions ?? []);

  // ── External forensic tools (#211) ────────────────────────────────────────────────────────────
  // Per-tool configured/auto-run status for the Settings → Tools tab (no secret values). Derived LIVE
  // from env so it reflects settings just saved + reconnected.
  app.get("/tools/status", (_req: Request, res: Response) => {
    const configured = ctx.liveToolConfigs()();
    const builtins = (Object.keys(TOOL_DEFS) as ToolId[]).map((id) => {
      const cfg = configured.get(id);
      return {
        id,
        label: TOOL_DEFS[id].label,
        repoUrl: TOOL_DEFS[id].repoUrl,
        importKind: TOOL_DEFS[id].importKind,
        transport: TOOL_DEFS[id].transport,
        extensions: TOOL_DEFS[id].extensions,
        configured: !!cfg,
        autoRun: cfg?.autoRun ?? false,
        hasUpdate: !!cfg?.updateCommand,
        custom: false,
      };
    });
    const custom = ctx.customTools().map((t) => ({
      id: t.id,
      label: t.name,
      importKind: "auto",
      transport: "spawn" as const,
      extensions: t.extensions,
      configured: true,
      autoRun: t.autoRun,
      hasUpdate: !!(t.updateCommand && t.updateCommand.trim()),
      custom: true,
    }));
    res.status(200).json({ enabled: !!options.toolRunner, tools: [...builtins, ...custom] });
  });

  // Re-read DFIR_TOOL_* from .env (settings saved via the dashboard only write the file) so the tool
  // paths/args/toggles apply WITHOUT the #1-gotcha restart. The runner is stateless (binary is a per-call
  // arg) so there's nothing to rebuild — the next liveToolConfigs() sees the reloaded env. Always 200.
  app.post("/tools/reconnect", async (_req: Request, res: Response) => {
    try {
      const applied = await reloadEnvPrefix("DFIR_TOOL_");
      const configured = [...ctx.liveToolConfigs()().keys()];
      return res.status(200).json({ ok: true, enabled: !!options.toolRunner, configured, applied });
    } catch (err) {
      return res.status(500).json({ ok: false, error: (err as Error).message });
    }
  });

  // Manually run a configured tool against a raw file on disk (the drop-folder banner's "Run <tool>", or
  // any case-relative path) and ingest its output through the normal import chain. 501 when tools are off,
  // 400 on a bad tool id / path (containment enforced by resolveContainedPath).
  app.post("/cases/:id/tools/:toolId/run", async (req: Request, res: Response) => {
    const caseId = req.params.id;
    const toolId = req.params.toolId;
    if (!isKnownTool(toolId)) return res.status(400).json({ error: `unknown tool "${toolId}"` });
    if (transportOf(toolId) === "spawn" && !options.toolRunner) {
      return res.status(501).json({ error: "external tools not configured" });
    }
    if (!(await store.caseExists(caseId)))
      return res.status(404).json({ error: `case ${caseId} does not exist` });
    const path = typeof req.body?.path === "string" ? req.body.path.trim() : "";
    if (!path) return res.status(400).json({ error: "path is required" });
    try {
      const r = await runToolAndIngest(caseId, toolId, path, {
        undoLabel: `Tool: ${toolId} — ${basename(path)}`,
      });
      return res
        .status(200)
        .json({
          ok: true,
          tool: toolId,
          storedName: r.storedName,
          addedEvents: r.addedEvents,
          addedIocs: r.addedIocs,
          analyzed: r.analyzed,
        });
    } catch (err) {
      recordImportFailure(caseId, toolId, path, err);
      return res.status(400).json({ ok: false, error: (err as Error).message });
    }
  });

  // Run a tool against a raw file UPLOADED from the dashboard Import dialog (the browser has the bytes
  // but the server can't read an arbitrary local path, and a binary can't go through the text /import
  // body). The bytes are staged into a server-owned dir INSIDE the case (so path-containment holds),
  // the ORIGINAL is preserved byte-for-byte as evidence, the tool runs, and its output is imported.
  // The staging dir is scratch and is deleted either way.
  //
  // Preserving the original is #688. Before it, the raw upload was deleted after the parse and the
  // case held only one tool's opinion of evidence that no longer existed — so the parse could never
  // be reproduced, re-examined, or re-run through a second parser. For files too large for the body
  // cap the analyst uses the drop folder instead, which has always kept the original in _processed/.
  // 501 tools off / 400 bad tool or input. #211
  app.post("/cases/:id/tools/:toolId/run-upload", async (req: Request, res: Response) => {
    const caseId = req.params.id;
    const toolId = req.params.toolId;
    if (!isKnownTool(toolId)) return res.status(400).json({ error: `unknown tool "${toolId}"` });
    if (transportOf(toolId) === "spawn" && !options.toolRunner) {
      return res.status(501).json({ error: "external tools not configured" });
    }
    if (!(await store.caseExists(caseId)))
      return res.status(404).json({ error: `case ${caseId} does not exist` });
    const filename = String(req.body?.filename ?? "").trim();
    const dataBase64 = typeof req.body?.dataBase64 === "string" ? req.body.dataBase64 : "";
    if (!filename || !dataBase64)
      return res.status(400).json({ error: "filename and dataBase64 are required" });
    if (!ctx.liveToolConfigs()().get(toolId))
      return res.status(400).json({ error: `tool "${toolId}" is not configured` });

    // HTTP tools never touch disk here — the bytes go straight to the service, and a zip is
    // extracted first. Returns job ids rather than counts: the analysis is asynchronous.
    if (transportOf(toolId) === "http") {
      try {
        const r = await ctx.startSocratesAnalysis(caseId, {
          data: Buffer.from(dataBase64, "base64"),
          filename,
          zipPassword: typeof req.body?.zipPassword === "string" ? req.body.zipPassword : undefined,
        });
        return res.status(200).json({ ok: true, tool: toolId, ...r });
      } catch (err) {
        recordImportFailure(caseId, toolId, filename, err);
        return res.status(400).json({ ok: false, error: (err as Error).message });
      }
    }
    // Refuse a file this parser does not claim, BEFORE anything touches disk (#673). These extensions
    // already decide which tools the Import dialog offers for a file (dashboard-values.js
    // `toolsForExt`), so until now the server was trusting a rule only the client enforced — a direct
    // API caller could hand a .txt to Hayabusa and get a parser crash instead of an answer. Refusing
    // first also means no evidence is preserved for a run that was never going to work.
    //
    // SPAWN ONLY, deliberately: the http branch above has already returned. SO-CRATES claims a long
    // list but exists to YARA-scan whatever it is given, including the extensionless, hash-named
    // samples its own toolConfig comment calls out — an extension gate there would reject its job.
    const declared = extensionsOf(toolId);
    if (!uploadExtensionAccepted(declared, filename)) {
      const got = uploadExtensionOf(filename) || "no extension";
      return res.status(400).json({
        error:
          `${toolId} does not accept "${basename(filename)}" (${got}) — it runs on ${declared.join(", ")}. ` +
          `Choose a tool that claims this file type, or import the file directly.`,
      });
    }

    // Stage into a FRESH per-upload dir under the file's ORIGINAL basename (no collisions, so no need to
    // mangle the name) — folder-root tools (Velociraptor --ROOT) detect the EVTX channel from the filename.
    const toolWork = join(store.caseDir(caseId), ".toolwork");
    const safe =
      basename(filename)
        .replace(/[^\w.\-]+/g, "_")
        .slice(0, 120) || "raw.bin";
    let stageDir = "";
    try {
      await mkdir(toolWork, { recursive: true });
      stageDir = await mkdtemp(join(toolWork, "up-"));
      const staged = join(stageDir, safe);
      const bytes = Buffer.from(dataBase64, "base64");
      await writeFile(staged, bytes);
      const r = await runToolAndIngest(caseId, toolId, staged, {
        undoLabel: `Tool: ${toolId} — ${basename(filename)}`,
        preserveOriginal: { bytes, originalName: basename(filename) },
      });
      return res
        .status(200)
        .json({
          ok: true,
          tool: toolId,
          addedEvents: r.addedEvents,
          addedIocs: r.addedIocs,
          analyzed: r.analyzed,
        });
    } catch (err) {
      recordImportFailure(caseId, toolId, filename, err);
      return res.status(400).json({ ok: false, error: (err as Error).message });
    } finally {
      if (stageDir)
        await rm(stageDir, { recursive: true, force: true }).catch(() => {
          /* best-effort cleanup */
        });
    }
  });

  // Run a tool's "update rules" command (Settings → Tools). Does NOT touch case data — a rule update is
  // not evidence; returns the command output for a UI toast. 501 when tools off, 400 when no update
  // command is configured for the tool.
  app.post("/cases/:id/tools/:toolId/update-rules", async (req: Request, res: Response) => {
    const toolId = req.params.toolId;
    if (!options.toolRunner) return res.status(501).json({ error: "external tools not configured" });
    // Confirm the case exists BEFORE spawning anything (#211). The case-password gate deliberately
    // waves nonexistent cases through — a missing case is the downstream route's 404 to report, not
    // the gate's — which left an unauthenticated caller able to reach a process-spawning route by
    // naming a case that was never created. This is that downstream check.
    if (!(await store.getCaseMeta(req.params.id)))
      return res.status(404).json({ error: `case "${req.params.id}" not found` });
    if (!isKnownTool(toolId)) return res.status(400).json({ error: `unknown tool "${toolId}"` });
    const cfg = ctx.liveToolConfigs()().get(toolId);
    if (!cfg) return res.status(400).json({ error: `tool "${toolId}" is not configured` });
    try {
      const output = await updateToolRules(cfg, options.toolRunner);
      return res.status(200).json({ ok: true, tool: toolId, output });
    } catch (err) {
      return res.status(400).json({ ok: false, error: (err as Error).message });
    }
  });

  // In-flight and finished SO-CRATES analyses for this case — polled by the import banner so the
  // analyst sees "analyzing (network)…" rather than a silent gap. SO-CRATES analysis is
  // asynchronous, so the run route returns job ids and the results land here.
  app.get("/cases/:id/socrates/jobs", async (req: Request, res: Response) => {
    if (!(await store.caseExists(req.params.id)))
      return res.status(404).json({ error: `case ${req.params.id} does not exist` });
    return res.status(200).json({ jobs: await ctx.socratesJobStore.list(req.params.id) });
  });

  // Custom tools (#211) — analyst-defined tools (name/binary/command/update/extensions) beyond the
  // built-ins. GLOBAL store; the list is refreshed in memory on each mutation so liveToolConfigs/status
  // reflect it immediately. 501 when the custom-tool store isn't wired.
  app.get("/tools/custom", async (_req: Request, res: Response) => {
    if (!options.customToolStore) return res.status(501).json({ error: "custom tools not enabled" });
    return res.status(200).json({ tools: await options.customToolStore.load() });
  });
  app.post("/tools/custom", async (req: Request, res: Response) => {
    if (!options.customToolStore) return res.status(501).json({ error: "custom tools not enabled" });
    try {
      const tool = await options.customToolStore.add(req.body ?? {});
      await reloadCustomTools();
      return res.status(201).json({ ok: true, tool });
    } catch (err) {
      return res.status(400).json({ ok: false, error: (err as Error).message });
    }
  });
  app.put("/tools/custom/:id", async (req: Request, res: Response) => {
    if (!options.customToolStore) return res.status(501).json({ error: "custom tools not enabled" });
    try {
      const tool = await options.customToolStore.update(req.params.id, req.body ?? {});
      if (!tool) return res.status(404).json({ error: `custom tool "${req.params.id}" not found` });
      await reloadCustomTools();
      return res.status(200).json({ ok: true, tool });
    } catch (err) {
      return res.status(400).json({ ok: false, error: (err as Error).message });
    }
  });
  app.delete("/tools/custom/:id", async (req: Request, res: Response) => {
    if (!options.customToolStore) return res.status(501).json({ error: "custom tools not enabled" });
    const removed = await options.customToolStore.remove(req.params.id);
    await reloadCustomTools();
    return res.status(200).json({ ok: true, removed });
  });

  // Forensic-timeline severity cut: the per-case override for which events stay in the forensic timeline
  // (Low+ by default) vs. are demoted to the super-timeline only. `minSeverity: null` = defer to the
  // global DFIR_FORENSIC_MIN_SEVERITY. GET returns the raw per-case override + the effective (resolved)
  // value; PUT sets/clears it.
  const FORENSIC_GATE_SEVERITIES: readonly Severity[] = ["Critical", "High", "Medium", "Low", "Info"];
  app.get("/cases/:id/forensic-gate", async (req: Request, res: Response) => {
    if (!options.forensicGateControlStore)
      return res.status(501).json({ error: "forensic gate not configured" });
    try {
      const perCase = (await options.forensicGateControlStore.load(req.params.id)).minSeverity ?? null;
      const effective = resolveForensicMinSeverity(
        perCase ?? undefined,
        process.env.DFIR_FORENSIC_MIN_SEVERITY,
      );
      return res.status(200).json({ minSeverity: perCase, effective });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.put("/cases/:id/forensic-gate", async (req: Request, res: Response) => {
    if (!options.forensicGateControlStore)
      return res.status(501).json({ error: "forensic gate not configured" });
    const raw = req.body?.minSeverity;
    // Accept one of the 5 severities, or null/omitted to clear the per-case override.
    const cleared = raw === null || raw === undefined || raw === "";
    if (!cleared && !FORENSIC_GATE_SEVERITIES.includes(raw)) {
      return res
        .status(400)
        .json({ error: `minSeverity must be one of ${FORENSIC_GATE_SEVERITIES.join(", ")} or null` });
    }
    try {
      await options.forensicGateControlStore.set(req.params.id, {
        minSeverity: cleared ? undefined : (raw as Severity),
      });
      options.onForensicGate?.(req.params.id);
      const perCase = (await options.forensicGateControlStore.load(req.params.id)).minSeverity ?? null;
      const effective = resolveForensicMinSeverity(
        perCase ?? undefined,
        process.env.DFIR_FORENSIC_MIN_SEVERITY,
      );
      void logActivity(options.activityLogStore, options.onActivity, req.params.id, {
        category: "settings",
        action: "forensic-gate",
        detail:
          perCase === null
            ? "forensic gate cleared (using global default)"
            : `forensic gate set to ${perCase}`,
      });
      return res.status(200).json({ minSeverity: perCase, effective });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });
}
