import type { Express, Request, Response } from "express";
import { parseMinSeverity } from "../analysis/severityFloor.js";
import { generatePushToken } from "../analysis/pushTokenStore.js";
import { resolvePushAuth } from "../analysis/pushAuth.js";
import { extractPushPayload } from "../analysis/pushPayload.js";
import { parseChannelInput, redactChannel } from "../analysis/notifications.js";
import type { RouteContext } from "./context.js";

/**
 * Push + notification routes: the generic external push-ingest endpoint (#84) with its per-case
 * push-token management, and the global notification channel config (#58).
 *
 * Pure structural move out of createApp (see routes/system.ts for the conventions). The import
 * pipeline itself stays in createApp — this module reaches it through the RouteContext members it
 * was graduated onto: ingestStreamed (stable method) and resolveImportKind (live accessor; call
 * ctx.resolveImportKind() INSIDE the handler). NOTE: the integration-push routes
 * (/cases/:id/push/{iris,timesketch,misp,notion,clickup}) are NOT here — they belong to their own
 * integration domains and stay in createApp.
 */
export function registerPushNotifyRoutes(app: Express, ctx: RouteContext): void {
  const { store, options, serverLogger, hasAiProvider, ingestStreamed } = ctx;

  // Module-private wrapper mirroring createApp's logLine (serverLogger.info), so the moved call
  // sites stay verbatim.
  const logLine = (msg: string): void => serverLogger.info(msg);

  // ── Generic push ingest (#84) ─────────────────────────────────────────────────────────────────
  // An external tool (SIEM webhook, Velociraptor client-event poller, custom script) POSTs an alert
  // payload here with an X-DFIR-Key token. The body is any importDetect-routable shape (artifact-map,
  // SIEM alert, Hayabusa line, { source, events }, raw text…). Runs the SAME import → diff →
  // re-synthesize pipeline as the file Import button; responds 202 immediately, imports in background.
  app.post("/cases/:id/push", async (req: Request, res: Response) => {
    if (!options.pipeline) return res.status(501).json({ error: "AI pipeline not configured" });
    const caseId = req.params.id;
    // Auth: global DFIR_PUSH_TOKEN and/or a per-case token. 403 when push is unconfigured, 401 on a bad key.
    let caseToken: string | undefined;
    if (options.pushTokenStore) { try { caseToken = (await options.pushTokenStore.get(caseId))?.token; } catch { /* none */ } }
    const bearer = (req.get("authorization") || "").replace(/^Bearer\s+/i, "");
    const presented = String(req.get("x-dfir-key") || bearer || "");
    const auth = resolvePushAuth({ globalToken: options.pushToken, caseToken, presented });
    if (!auth.ok) return res.status(auth.status).json({ error: auth.error });

    if (!(await store.caseExists(caseId))) return res.status(404).json({ error: "case not found" });

    const { text, source, filename } = extractPushPayload(req.body);
    if (!text.trim()) return res.status(400).json({ error: "empty push payload" });
    const kind = ctx.resolveImportKind()(filename, text);
    if (kind === "unknown") return res.status(400).json({ error: "could not detect the payload type — not recognized as any supported import shape" });
    if ((kind === "csv" || kind === "log") && !hasAiProvider()) return res.status(501).json({ error: "AI provider not configured for CSV/log analysis" });

    const minSeverity = parseMinSeverity(req.body?.minSeverity);
    logLine(`[push] case ${caseId}: received "${source}" → ${kind}`);
    res.status(202).json({ accepted: true, kind, source });
    // Import in the background; the 202 already went out.
    ingestStreamed(caseId, kind, text, filename, minSeverity)
      .catch((err) => options.onAiStatus?.(caseId, { status: "error", at: new Date().toISOString(), detail: `push import failed: ${(err as Error).message}` }));
  });

  // Per-case push token management (#84). GET returns the case token's existence (NOT the secret on a
  // plain GET — it's shown once on generate) plus whether a global token covers every case and the
  // push URL. POST generates/rotates one; DELETE clears it.
  app.get("/cases/:id/push-token", async (req: Request, res: Response) => {
    const caseId = req.params.id;
    const globalConfigured = !!(options.pushToken && options.pushToken.trim());
    let rec: { token: string; createdAt: string } | null = null;
    if (options.pushTokenStore) { try { rec = await options.pushTokenStore.get(caseId); } catch { /* none */ } }
    const base = (options.dashboardBaseUrl || "").replace(/\/+$/, "");
    return res.status(200).json({
      configured: !!rec,
      token: rec?.token ?? "",          // shown so Settings can display the active token + curl example
      createdAt: rec?.createdAt ?? "",
      globalConfigured,
      storeAvailable: !!options.pushTokenStore,
      pushUrl: `${base}/cases/${encodeURIComponent(caseId)}/push`,
    });
  });

  app.post("/cases/:id/push-token/generate", async (req: Request, res: Response) => {
    if (!options.pushTokenStore) return res.status(501).json({ error: "push token store not configured" });
    const caseId = req.params.id;
    if (!(await store.caseExists(caseId))) return res.status(404).json({ error: "case not found" });
    try {
      const token = generatePushToken();
      const rec = await options.pushTokenStore.set(caseId, token, new Date().toISOString());
      options.onPushToken?.(caseId);
      return res.status(201).json({ token: rec.token, createdAt: rec.createdAt });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.delete("/cases/:id/push-token", async (req: Request, res: Response) => {
    if (!options.pushTokenStore) return res.status(501).json({ error: "push token store not configured" });
    try {
      await options.pushTokenStore.clear(req.params.id);
      options.onPushToken?.(req.params.id);
      return res.status(204).end();
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // ── Notifications (issue #58) ─────────────────────────────────────────────────────────────
  // Global channel config: Slack/Teams webhooks + SMTP email, with per-channel severity threshold
  // and per-event-kind toggles. Opt-in (the store starts empty). Secrets (webhook URLs, SMTP
  // passwords) are REDACTED in every response — the browser only learns whether each is set.

  app.get("/notifications/status", (_req: Request, res: Response) => {
    res.status(200).json({ configured: !!options.notificationStore, emailEnabled: !!options.notifyEmailEnabled });
  });

  app.get("/notifications", async (_req: Request, res: Response) => {
    if (!options.notificationStore) return res.status(200).json([]);
    try {
      return res.status(200).json((await options.notificationStore.load()).map(redactChannel));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.post("/notifications", async (req: Request, res: Response) => {
    if (!options.notificationStore) return res.status(501).json({ error: "notifications not configured" });
    const parsed = parseChannelInput(req.body);
    if (!parsed.ok || !parsed.draft) return res.status(400).json({ error: parsed.error ?? "invalid channel" });
    try {
      const channel = await options.notificationStore.add(parsed.draft);
      logLine(`[notify] channel added: ${channel.type} "${channel.name}" (${channel.id})`);
      return res.status(201).json(redactChannel(channel));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.put("/notifications/:id", async (req: Request, res: Response) => {
    if (!options.notificationStore) return res.status(501).json({ error: "notifications not configured" });
    try {
      const existing = await options.notificationStore.get(req.params.id);
      if (!existing) return res.status(404).json({ error: "notification channel not found" });
      // Pass `existing` so a blank (redacted) webhook URL keeps the saved one.
      const parsed = parseChannelInput(req.body, existing);
      if (!parsed.ok || !parsed.draft) return res.status(400).json({ error: parsed.error ?? "invalid channel" });
      const channel = await options.notificationStore.update(req.params.id, parsed.draft);
      if (!channel) return res.status(404).json({ error: "notification channel not found" });
      return res.status(200).json(redactChannel(channel));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.delete("/notifications/:id", async (req: Request, res: Response) => {
    if (!options.notificationStore) return res.status(501).json({ error: "notifications not configured" });
    try {
      const removed = await options.notificationStore.remove(req.params.id);
      if (!removed) return res.status(404).json({ error: "notification channel not found" });
      return res.status(204).end();
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Send a test notification to one channel ({ channelId }) or all configured channels. Bypasses
  // the enable/threshold/kind filters so a disabled or high-threshold channel can be verified.
  app.post("/notifications/test", async (req: Request, res: Response) => {
    if (!options.notificationStore || !options.notifier) return res.status(501).json({ error: "notifications not configured" });
    try {
      const channelId = typeof req.body?.channelId === "string" ? req.body.channelId : undefined;
      const results = await options.notifier.test(channelId, new Date().toISOString());
      if (!results.length) return res.status(404).json({ error: "no matching channel to test" });
      return res.status(200).json({ results });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });
}
