import type { Express, Request, Response } from "express";
import type { RouteContext } from "./context.js";
import { logActivity } from "../analysis/activityLog.js";
import { reloadEnvPrefix } from "../settings/envManager.js";
import { defaultIrisCaseName } from "../integrations/iris/irisExportStore.js";
import { pushCaseToIris } from "../integrations/iris/irisPush.js";
import {
  pushCaseToTimesketch,
  pushSuperTimelineToTimesketch,
} from "../integrations/timesketch/timesketchPush.js";
import { pushCaseToMisp } from "../integrations/misp/mispPush.js";
import { pushCaseToNotion, type NotionPushTarget } from "../integrations/notion/notionPush.js";
import { parseNotionPageId } from "../integrations/notion/notionClient.js";
import { pushPlaybookToClickUp } from "../integrations/clickup/clickupPush.js";
import { pushFindingToJira, pushFindingsToJira } from "../integrations/jira/jiraPush.js";
import {
  pushFindingToServiceNow,
  pushFindingsToServiceNow,
} from "../integrations/servicenow/servicenowPush.js";
import type { Finding } from "../analysis/stateTypes.js";

// Outbound pushes: everything that sends a case OUT of the Companion to a system of record —
// DFIR-IRIS, Timesketch, MISP, Notion, ClickUp, Jira, ServiceNow — plus the connection-status and
// reconnect endpoints those pushes depend on.
//
// Lifted out of routes/caseLifecycle.ts, which the file-size ledger had frozen at 1204 lines. These
// 417 lines were the largest cohesive block in it and the least related to the rest: caseLifecycle
// is about a case's OWN lifecycle (create, archive, restore, delete, export), while every route here
// is about a third-party system's API, its credentials and its failure modes. Splitting on that seam
// means a Jira change and a case-deletion change stop sharing a file.
//
// MOVED VERBATIM. The route bodies, their status codes and their log lines are unchanged; only the
// registration point moved. logLine/errLine are re-declared here for the same reason caseLifecycle
// declares them — so the moved call sites stay byte-identical rather than being rewritten to
// serverLogger.info at 30 sites.

export function registerCasePushRoutes(app: Express, ctx: RouteContext): void {
  const { store, options, serverLogger, syncPlaybook } = ctx;
  const logLine = (msg: string): void => serverLogger.info(msg);

  // The one answer shape every "Test connection" control in Settings → Integrations reads, so a
  // caller never has to tell a missing credential apart from an unreachable server by parsing prose:
  //
  //   { configured: false, ok: false, error }  the keys are absent — nothing was attempted
  //   { configured: true,  ok: true,  user }   the credentials reached the remote and it answered
  //   { configured: true,  ok: false, error }  the credentials exist and the remote refused / is down
  //
  // Always 200: "the remote rejected our token" is a successful test that reports a failure, not a
  // failed request, and an HTTP error status here would be indistinguishable from the Companion's own.
  //
  // `extra` carries whatever that integration's own /status route reports, because a reconnect can
  // CHANGE it (a Notion default database, a ClickUp default list). Without it the dashboard would
  // keep the state it read at page load and prompt for a target the analyst just configured.
  //
  // `probe` rather than a fixed `client.me()`: MISP has no such call — its reachability check is
  // ping() (GET /servers/getVersion) and returns nothing to name. The probe returns the account
  // label to show, or undefined when the integration cannot report one.
  async function probeConnection<C>(
    res: Response,
    client: C | undefined,
    missingError: string,
    probe: (client: C) => Promise<string | undefined>,
    extra: Record<string, unknown> = {},
  ): Promise<Response> {
    if (!client) return res.status(200).json({ configured: false, ok: false, error: missingError });
    try {
      const user = await probe(client);
      return res.status(200).json({ configured: true, ok: true, user, ...extra });
    } catch (err) {
      return res.status(200).json({ configured: true, ok: false, error: (err as Error).message });
    }
  }

  // Push a case to DFIR-IRIS: find-or-create the case by name, then push assets→assets,
  // IOCs→IOCs, forensic timeline→timeline, executive summary→case summary, everything else→notes.
  // Body: { caseName? } — an explicit override; otherwise the name from the last push is reused
  // (irisExportStore), falling back to "<case id> — <friendly name>" on the very first push.
  app.post("/cases/:id/push/iris", async (req: Request, res: Response) => {
    const irisClient = ctx.irisClient(); // live accessor — POST /iris/reconnect can rebuild it at runtime
    if (!irisClient)
      return res
        .status(501)
        .json({ error: "DFIR-IRIS not configured (set DFIR_IRIS_URL and DFIR_IRIS_KEY)" });
    if (!options.stateStore) return res.status(501).json({ error: "state store not configured" });
    const caseId = req.params.id;
    try {
      const state = await options.stateStore.load(caseId);
      const meta = options.reportMetaStore ? await options.reportMetaStore.load(caseId) : undefined;
      // Push the analyst-curated playbook (status-aware) when available, else the raw next steps.
      const playbookTasks = options.playbookStore ? await syncPlaybook(caseId) : undefined;
      const caseMeta = await store.getCaseMeta(caseId).catch(() => null);
      const saved = options.irisExportStore ? await options.irisExportStore.load(caseId) : { caseName: "" };
      const requested = typeof req.body?.caseName === "string" ? req.body.caseName.trim() : "";
      let targetCaseName: string;
      if (requested) {
        targetCaseName = requested;
      } else if (saved.caseName) {
        targetCaseName = saved.caseName;
      } else {
        // First push under the new naming scheme — check whether this case was already pushed
        // under the OLD bare-case-id scheme (pre-dates the case-name override feature) so we
        // don't fork a duplicate IRIS case; only fall back to the computed default if not.
        const legacy = await irisClient.findCaseByName(caseId).catch(() => null);
        targetCaseName = legacy ? caseId : defaultIrisCaseName(caseId, caseMeta?.name);
      }
      logLine(`[iris] ${caseId} push START -> "${targetCaseName}"`);
      const result = await pushCaseToIris(
        irisClient,
        {
          caseName: targetCaseName,
          state,
          meta,
          playbookTasks: playbookTasks?.length ? playbookTasks : undefined,
        },
        options.irisOptions,
      );
      if (options.irisExportStore) await options.irisExportStore.record(caseId, targetCaseName);
      logLine(
        `[iris] ${caseId} push DONE -> case ${result.caseId} (${result.created ? "created" : "updated"}); ` +
          `assets +${result.assets.added}/${result.assets.existing}, iocs +${result.iocs.added}/${result.iocs.existing}, ` +
          `timeline +${result.timeline.added}/${result.timeline.existing}, tasks +${result.tasks.added}/${result.tasks.existing}, ` +
          `notes ${result.notes}, warnings ${result.warnings.length}`,
      );
      void logActivity(options.activityLogStore, options.onActivity, caseId, {
        category: "export",
        action: "push-iris",
        detail: `pushed to DFIR-IRIS case ${result.caseId} (${result.created ? "created" : "updated"})`,
      });
      return res.status(200).json(result);
    } catch (err) {
      logLine(`[iris] ${caseId} push ERROR: ${(err as Error).message}`);
      return res.status(502).json({ error: (err as Error).message });
    }
  });
  // Whether a Timesketch push target is configured (so the dashboard can show/hide the button).
  app.get("/timesketch/status", (_req: Request, res: Response) => {
    res
      .status(200)
      .json({ configured: !!options.timesketchClient, baseUrl: options.timesketchOptions?.baseUrl });
  });

  // Re-read DFIR_TIMESKETCH_* from .env (Settings only writes the file), rebuild the client, and log
  // in to verify connectivity — so the Setup wizard / Settings can connect after configuring Timesketch
  // (or after it comes back online) WITHOUT the #1-gotcha restart. Mirrors /iris/reconnect. Always 200;
  // the body says whether it's configured and reachable.
  app.post("/timesketch/reconnect", async (_req: Request, res: Response) => {
    try {
      await reloadEnvPrefix("DFIR_TIMESKETCH_");
      options.timesketchClient = ctx.rebuildTimesketchClient();
      if (!options.timesketchClient) {
        return res.status(200).json({
          configured: false,
          ok: false,
          error: "DFIR_TIMESKETCH_URL, DFIR_TIMESKETCH_USER and DFIR_TIMESKETCH_PASSWORD are not all set",
        });
      }
      try {
        await options.timesketchClient.login();
        return res.status(200).json({ configured: true, ok: true, baseUrl: process.env.DFIR_TIMESKETCH_URL });
      } catch (err) {
        return res.status(200).json({
          configured: true,
          ok: false,
          baseUrl: process.env.DFIR_TIMESKETCH_URL,
          error: (err as Error).message,
        });
      }
    } catch (err) {
      return res.status(500).json({ configured: false, ok: false, error: (err as Error).message });
    }
  });

  // Push a case to Timesketch: log in, find-or-create the sketch by name (= the Companion case id),
  // then upload the forensic timeline as a timeline. The managed timeline is clean-replaced so a
  // re-push never duplicates events.
  app.post("/cases/:id/push/timesketch", async (req: Request, res: Response) => {
    if (!options.timesketchClient)
      return res.status(501).json({
        error:
          "Timesketch not configured (set DFIR_TIMESKETCH_URL, DFIR_TIMESKETCH_USER and DFIR_TIMESKETCH_PASSWORD)",
      });
    if (!options.reportWriter) return res.status(501).json({ error: "report writer not configured" });
    const caseId = req.params.id;
    try {
      const state = await options.reportWriter.filteredState(caseId);
      logLine(`[timesketch] ${caseId} push START`);
      const result = await pushCaseToTimesketch(
        options.timesketchClient,
        { sketchName: caseId, state },
        options.timesketchOptions,
      );
      logLine(
        `[timesketch] ${caseId} push DONE -> sketch ${result.sketchId} (${result.created ? "created" : "updated"}); ` +
          `timeline "${result.timelineName}" events ${result.events}${result.replacedTimeline ? " (replaced)" : ""}, warnings ${result.warnings.length}`,
      );
      void logActivity(options.activityLogStore, options.onActivity, caseId, {
        category: "export",
        action: "push-timesketch",
        detail: `pushed to Timesketch sketch ${result.sketchId} (${result.created ? "created" : "updated"})`,
      });
      return res.status(200).json(result);
    } catch (err) {
      logLine(`[timesketch] ${caseId} push ERROR: ${(err as Error).message}`);
      return res.status(502).json({ error: (err as Error).message });
    }
  });

  // Push the super-timeline (forensic timeline + raw host-triage artifacts) to Timesketch: same
  // sketch as the forensic push (named after the case id), but a SEPARATE timeline inside it
  // ("DFIR Companion super timeline") so the two pushes never clean-replace each other. NOT
  // scope/false-positive filtered — the super-timeline is the raw complete record.
  app.post("/cases/:id/push/timesketch-super", async (req: Request, res: Response) => {
    if (!options.timesketchClient)
      return res.status(501).json({
        error:
          "Timesketch not configured (set DFIR_TIMESKETCH_URL, DFIR_TIMESKETCH_USER and DFIR_TIMESKETCH_PASSWORD)",
      });
    if (!options.superTimelineStore) return res.status(501).json({ error: "super-timeline not configured" });
    const caseId = req.params.id;
    try {
      const events = await options.superTimelineStore.all(caseId);
      logLine(`[timesketch] ${caseId} super-timeline push START`);
      const result = await pushSuperTimelineToTimesketch(
        options.timesketchClient,
        { sketchName: caseId, events },
        options.timesketchOptions,
      );
      logLine(
        `[timesketch] ${caseId} super-timeline push DONE -> sketch ${result.sketchId} (${result.created ? "created" : "updated"}); ` +
          `timeline "${result.timelineName}" events ${result.events}${result.replacedTimeline ? " (replaced)" : ""}, warnings ${result.warnings.length}`,
      );
      void logActivity(options.activityLogStore, options.onActivity, caseId, {
        category: "export",
        action: "push-timesketch-super",
        detail: `pushed super-timeline to Timesketch sketch ${result.sketchId} (${result.created ? "created" : "updated"})`,
      });
      return res.status(200).json(result);
    } catch (err) {
      logLine(`[timesketch] ${caseId} super-timeline push ERROR: ${(err as Error).message}`);
      return res.status(502).json({ error: (err as Error).message });
    }
  });

  // Whether a MISP push target is configured (so the dashboard can show/hide the button).
  app.get("/misp/status", (_req: Request, res: Response) => {
    res.status(200).json({ configured: !!options.mispPushClient, baseUrl: options.mispPushOptions?.baseUrl });
  });

  // Re-read DFIR_MISP_* from .env, rebuild, and run MISP's own connectivity check — the Settings
  // "Test / reconnect" control. The rebuild covers BOTH things those keys feed: the push client
  // probed here and the IOC enrichment provider (rebuildForPrefix rebuilds the provider set for
  // this prefix), which is why the control sits on the Enrichment tab beside the fields.
  //
  // The probe is ping() rather than a me()-style identity call — MISP has none — and its error is
  // passed through untouched: mispConnectivity.ts has already turned undici's "fetch failed" into a
  // sentence naming the URL and the setting at fault, which is the whole value of a test button.
  app.post("/misp/reconnect", async (_req: Request, res: Response) => {
    try {
      await reloadEnvPrefix("DFIR_MISP_");
      ctx.rebuildForPrefix("DFIR_MISP_"); // swaps options.mispPushClient + mispPushOptions + enrichment
      return await probeConnection(
        res,
        options.mispPushClient,
        "MISP not configured (set DFIR_MISP_URL and DFIR_MISP_KEY)",
        async (c) => {
          await c.ping();
          return undefined; // the ping reports reachability only — there is no account to name
        },
        { baseUrl: options.mispPushOptions?.baseUrl },
      );
    } catch (err) {
      return res.status(500).json({ configured: false, ok: false, error: (err as Error).message });
    }
  });

  // Push a case to MISP: find-or-create the event by the idempotency tag, then push IOCs and
  // the forensic timeline as attributes and MITRE techniques as tags. Idempotent: re-push adds
  // only what's missing (attributes deduplicated by value).
  app.post("/cases/:id/push/misp", async (req: Request, res: Response) => {
    if (!options.mispPushClient)
      return res.status(501).json({ error: "MISP not configured (set DFIR_MISP_URL and DFIR_MISP_KEY)" });
    if (!options.stateStore) return res.status(501).json({ error: "state store not configured" });
    const caseId = req.params.id;
    try {
      const state = await options.stateStore.load(caseId);
      logLine(`[misp] ${caseId} push START`);
      const result = await pushCaseToMisp(options.mispPushClient, { caseId, state }, options.mispPushOptions);
      logLine(
        `[misp] ${caseId} push DONE -> event ${result.eventId} (${result.created ? "created" : "updated"}); ` +
          `attributes +${result.attributes.added}/${result.attributes.existing}, timeline +${result.timeline.added}/${result.timeline.existing}, tags +${result.tags}, warnings ${result.warnings.length}`,
      );
      void logActivity(options.activityLogStore, options.onActivity, caseId, {
        category: "export",
        action: "push-misp",
        detail: `pushed to MISP event ${result.eventId} (${result.created ? "created" : "updated"})`,
      });
      return res.status(200).json(result);
    } catch (err) {
      logLine(`[misp] ${caseId} push ERROR: ${(err as Error).message}`);
      return res.status(502).json({ error: (err as Error).message });
    }
  });

  // Whether a Notion export target is configured (so the dashboard can show/hide the option and
  // decide whether to ask for a parent in the "new page" modal).
  app.get("/notion/status", (_req: Request, res: Response) => {
    res.status(200).json({
      configured: !!options.notionClient,
      hasDatabase: !!options.notionOptions?.databaseId,
      hasParent: !!options.notionOptions?.parentPageId,
    });
  });

  // Re-read DFIR_NOTION_* from .env (Settings only writes the file), rebuild the client, and call
  // users/me to verify the token — the Settings "Test connection" control. Mirrors /iris/reconnect,
  // so a token corrected in Settings applies WITHOUT the #1-gotcha restart.
  app.post("/notion/reconnect", async (_req: Request, res: Response) => {
    try {
      await reloadEnvPrefix("DFIR_NOTION_");
      ctx.rebuildForPrefix("DFIR_NOTION_"); // swaps options.notionClient + notionOptions
      return await probeConnection(
        res,
        options.notionClient,
        "Notion not configured (set DFIR_NOTION_TOKEN)",
        async (c) => {
          const me = await c.me();
          return me.name || me.id || undefined;
        },
        {
          hasDatabase: !!options.notionOptions?.databaseId,
          hasParent: !!options.notionOptions?.parentPageId,
        },
      );
    } catch (err) {
      return res.status(500).json({ configured: false, ok: false, error: (err as Error).message });
    }
  });

  // Export a case into a Notion page. The Companion writes ALL its content inside ONE managed
  // toggle block it owns; a re-export refreshes that block and never touches the investigators'
  // own notes/screenshots. Body: { mode: "new"|"existing", page?, parent?, database? }.
  app.post("/cases/:id/push/notion", async (req: Request, res: Response) => {
    if (!options.notionClient)
      return res.status(501).json({ error: "Notion not configured (set DFIR_NOTION_TOKEN)" });
    if (!options.reportWriter) return res.status(501).json({ error: "report writer not configured" });
    if (!options.notionExportStore)
      return res.status(501).json({ error: "notion export store not configured" });
    const caseId = req.params.id;
    const body = req.body ?? {};
    const mode = body.mode === "existing" ? "existing" : "new";

    const target: NotionPushTarget = { mode };
    if (mode === "existing") {
      const pageId = parseNotionPageId(typeof body.page === "string" ? body.page : "");
      if (!pageId)
        return res
          .status(400)
          .json({ error: "could not read a Notion page id from the supplied page URL/ID" });
      target.pageId = pageId;
    } else {
      const parent = typeof body.parent === "string" ? parseNotionPageId(body.parent) : null;
      const database = typeof body.database === "string" ? parseNotionPageId(body.database) : null;
      if (parent) target.parentPageId = parent;
      if (database) target.databaseId = database;
    }

    try {
      const state = await options.reportWriter.filteredState(caseId);
      const meta = options.reportMetaStore ? await options.reportMetaStore.load(caseId) : undefined;
      logLine(`[notion] ${caseId} export START (${mode})`);
      const result = await pushCaseToNotion(
        options.notionClient,
        { caseName: caseId, state, meta },
        target,
        options.notionOptions,
        options.notionExportStore,
      );
      logLine(
        `[notion] ${caseId} export DONE -> page ${result.pageId} (${result.created ? "created" : "updated"}); ` +
          `+${result.blocksAppended} block(s) in ${result.batches} batch(es), archived ${result.blocksArchived}, warnings ${result.warnings.length}`,
      );
      void logActivity(options.activityLogStore, options.onActivity, caseId, {
        category: "export",
        action: "push-notion",
        detail: `pushed to Notion page ${result.pageId} (${result.created ? "created" : "updated"})`,
      });
      return res.status(200).json(result);
    } catch (err) {
      logLine(`[notion] ${caseId} export ERROR: ${(err as Error).message}`);
      return res.status(502).json({ error: (err as Error).message });
    }
  });

  // Whether a ClickUp push target is configured (so the dashboard can show/hide the option).
  app.get("/clickup/status", (_req: Request, res: Response) => {
    res.status(200).json({
      configured: !!options.clickupClient,
      hasDefaultList: !!options.clickupOptions?.defaultListId,
      defaultListId: options.clickupOptions?.defaultListId ?? "",
    });
  });

  // Re-read DFIR_CLICKUP_* from .env, rebuild the client, and call /user to verify the token.
  // Same contract as /notion/reconnect above.
  app.post("/clickup/reconnect", async (_req: Request, res: Response) => {
    try {
      await reloadEnvPrefix("DFIR_CLICKUP_");
      ctx.rebuildForPrefix("DFIR_CLICKUP_"); // swaps options.clickupClient + clickupOptions
      return await probeConnection(
        res,
        options.clickupClient,
        "ClickUp not configured (set DFIR_CLICKUP_TOKEN)",
        async (c) => {
          const me = await c.me();
          return me.username || me.id || undefined;
        },
        { defaultListId: options.clickupOptions?.defaultListId ?? "" },
      );
    } catch (err) {
      return res.status(500).json({ configured: false, ok: false, error: (err as Error).message });
    }
  });

  // Push the Response Playbook to a ClickUp list as tasks. Body { listId? } — falls back to the
  // saved list, then the configured default. Re-export UPDATES the tasks it created (by remembered
  // id) instead of duplicating.
  app.post("/cases/:id/push/clickup", async (req: Request, res: Response) => {
    if (!options.clickupClient)
      return res.status(501).json({ error: "ClickUp not configured (set DFIR_CLICKUP_TOKEN)" });
    if (!options.clickupExportStore)
      return res.status(501).json({ error: "clickup export store not configured" });
    if (!options.playbookStore || !options.stateStore)
      return res.status(501).json({ error: "playbook not configured" });
    const caseId = req.params.id;
    try {
      const saved = await options.clickupExportStore.load(caseId);
      const requested = typeof req.body?.listId === "string" ? req.body.listId.trim() : "";
      const listId = requested || saved.listId || options.clickupOptions?.defaultListId || "";
      if (!listId) return res.status(400).json({ error: "a ClickUp list id is required" });
      const tasks = await syncPlaybook(caseId);
      if (!tasks.length)
        return res.status(400).json({ error: "the playbook is empty — run synthesis or add tasks first" });
      logLine(`[clickup] ${caseId} push START -> list ${listId} (${tasks.length} tasks)`);
      const result = await pushPlaybookToClickUp(
        options.clickupClient,
        { caseId, listId, tasks },
        options.clickupExportStore,
        new Date().toISOString(),
      );
      logLine(
        `[clickup] ${caseId} push DONE: +${result.created} created, ${result.updated} updated, ${result.skipped} skipped, warnings ${result.warnings.length}`,
      );
      void logActivity(options.activityLogStore, options.onActivity, caseId, {
        category: "export",
        action: "push-clickup",
        detail: `pushed playbook to ClickUp list ${listId} — +${result.created} created, ${result.updated} updated`,
      });
      return res.status(200).json(result);
    } catch (err) {
      logLine(`[clickup] ${caseId} push ERROR: ${(err as Error).message}`);
      return res.status(502).json({ error: (err as Error).message });
    }
  });

  // Jira status + finding push (issue #272).
  app.get("/jira/status", (_req: Request, res: Response) => {
    res.status(200).json({
      configured: !!options.jiraClient,
      projectKey: options.jiraOptions?.projectKey ?? "",
      issueType: options.jiraOptions?.issueType ?? "",
    });
  });

  // Verify the Jira credentials by calling /myself — the Settings "Test connection" control.
  // PINGS THE LIVE CLIENT AND DOES NOT RELOAD .env, unlike the Notion/ClickUp routes above: Jira's
  // fields are deliberately read-only in Settings (the dashboard must not be able to move
  // DFIR_JIRA_INSECURE), so its config only ever changes by editing .env and restarting. A reload
  // here would quietly apply a boundary change the UI is not allowed to make.
  app.post("/jira/test", async (_req: Request, res: Response) =>
    probeConnection(
      res,
      options.jiraClient,
      "Jira not configured (set DFIR_JIRA_URL, DFIR_JIRA_USER, and DFIR_JIRA_TOKEN in .env, then restart)",
      async (c) => {
        const me = await c.me();
        return me.displayName || me.id || undefined;
      },
    ),
  );

  // Push one finding as a Jira issue. Body { findingId, projectKey?, issueType? } — the project
  // falls back to DFIR_JIRA_PROJECT_KEY. Re-pushing the same finding UPDATES the issue it created
  // (key remembered in `state/jira-export.json`) instead of filing a duplicate.
  app.post("/cases/:id/push/jira", async (req: Request, res: Response) => {
    if (!options.jiraClient)
      return res
        .status(501)
        .json({ error: "Jira not configured (set DFIR_JIRA_URL, DFIR_JIRA_USER, and DFIR_JIRA_TOKEN)" });
    if (!options.jiraExportStore) return res.status(501).json({ error: "jira export store not configured" });
    if (!options.stateStore) return res.status(501).json({ error: "state store not configured" });
    const caseId = req.params.id;
    try {
      const state = await options.stateStore.load(caseId);
      const findingId = typeof req.body?.findingId === "string" ? req.body.findingId : "";
      const finding = state.findings.find((f) => f.id === findingId);
      if (!finding) return res.status(404).json({ error: `finding ${findingId} not found` });
      const projectKey =
        typeof req.body?.projectKey === "string" && req.body.projectKey.trim()
          ? req.body.projectKey.trim()
          : options.jiraOptions?.projectKey;
      if (!projectKey) return res.status(400).json({ error: "a Jira project key is required" });
      logLine(`[jira] ${caseId} finding ${findingId} push START -> project ${projectKey}`);
      const result = await pushFindingToJira(options.jiraClient, options.jiraExportStore, {
        caseId,
        projectKey,
        issueType:
          typeof req.body?.issueType === "string" ? req.body.issueType : options.jiraOptions?.issueType,
        finding,
      });
      logLine(`[jira] ${caseId} finding ${findingId} push DONE -> ${result.issue.key}`);
      void logActivity(options.activityLogStore, options.onActivity, caseId, {
        category: "export",
        action: "push-jira",
        detail: `pushed finding ${findingId} to Jira ${result.issue.key}`,
      });
      return res.status(200).json(result);
    } catch (err) {
      logLine(`[jira] ${caseId} push ERROR: ${(err as Error).message}`);
      return res.status(502).json({ error: (err as Error).message });
    }
  });

  // Push SEVERAL findings as Jira issues in one call (issue #297). Body { findingIds, projectKey?,
  // issueType? }. A finding id the case doesn't have, or one the API refuses, is counted as skipped
  // with the reason kept — the batch runs to the end either way, so a single bad ticket can't cost
  // the analyst the other twenty. Re-push UPDATES, same as the single-finding route.
  app.post("/cases/:id/push/jira/bulk", async (req: Request, res: Response) => {
    if (!options.jiraClient)
      return res
        .status(501)
        .json({ error: "Jira not configured (set DFIR_JIRA_URL, DFIR_JIRA_USER, and DFIR_JIRA_TOKEN)" });
    if (!options.jiraExportStore) return res.status(501).json({ error: "jira export store not configured" });
    if (!options.stateStore) return res.status(501).json({ error: "state store not configured" });
    const caseId = req.params.id;
    const findingIds: string[] = Array.isArray(req.body?.findingIds)
      ? req.body.findingIds.filter((v: unknown): v is string => typeof v === "string" && !!v.trim())
      : [];
    if (!findingIds.length)
      return res.status(400).json({ error: "findingIds is required (a non-empty array of finding ids)" });
    try {
      const state = await options.stateStore.load(caseId);
      const byId = new Map(state.findings.map((f) => [f.id, f]));
      const findings = findingIds.map((fid) => byId.get(fid)).filter((f): f is Finding => !!f);
      const missing = findingIds.filter((fid) => !byId.has(fid));
      const projectKey =
        typeof req.body?.projectKey === "string" && req.body.projectKey.trim()
          ? req.body.projectKey.trim()
          : options.jiraOptions?.projectKey;
      if (!projectKey) return res.status(400).json({ error: "a Jira project key is required" });
      logLine(`[jira] ${caseId} bulk push START -> project ${projectKey} (${findings.length} finding(s))`);
      const result = await pushFindingsToJira(options.jiraClient, options.jiraExportStore, {
        caseId,
        projectKey,
        issueType:
          typeof req.body?.issueType === "string" ? req.body.issueType : options.jiraOptions?.issueType,
        findings,
      });
      const body = {
        ...result,
        skipped: result.skipped + missing.length,
        warnings: [...result.warnings, ...missing.map((fid) => `finding ${fid}: not found in this case`)],
      };
      logLine(
        `[jira] ${caseId} bulk push DONE: +${body.created} created, ${body.updated} updated, ${body.skipped} skipped, warnings ${body.warnings.length}`,
      );
      void logActivity(options.activityLogStore, options.onActivity, caseId, {
        category: "export",
        action: "push-jira",
        detail: `pushed ${findings.length} finding(s) to Jira ${projectKey} — +${body.created} created, ${body.updated} updated`,
      });
      return res.status(200).json(body);
    } catch (err) {
      logLine(`[jira] ${caseId} bulk push ERROR: ${(err as Error).message}`);
      return res.status(502).json({ error: (err as Error).message });
    }
  });

  // ServiceNow status + finding push (issue #272).
  app.get("/servicenow/status", (_req: Request, res: Response) => {
    res.status(200).json({
      configured: !!options.servicenowClient,
      caller: options.servicenowOptions?.caller ?? "",
      category: options.servicenowOptions?.category ?? "",
      subcategory: options.servicenowOptions?.subcategory ?? "",
    });
  });

  // Verify the ServiceNow credentials by reading the authenticated user. Ping-only for the same
  // reason as /jira/test above — the fields are read-only in Settings.
  app.post("/servicenow/test", async (_req: Request, res: Response) =>
    probeConnection(
      res,
      options.servicenowClient,
      "ServiceNow not configured (set DFIR_SERVICENOW_URL, DFIR_SERVICENOW_USER, and DFIR_SERVICENOW_PASSWORD in .env, then restart)",
      async (c) => {
        const me = await c.me();
        return me.userName || me.userId || undefined;
      },
    ),
  );

  // Push one finding as a ServiceNow incident. Body { findingId, caller?, category?, subcategory? }
  // — each falls back to its DFIR_SERVICENOW_* default. Re-pushing the same finding UPDATES the
  // incident it opened (sys_id remembered in `state/servicenow-export.json`), never a duplicate.
  app.post("/cases/:id/push/servicenow", async (req: Request, res: Response) => {
    if (!options.servicenowClient)
      return res.status(501).json({
        error:
          "ServiceNow not configured (set DFIR_SERVICENOW_URL, DFIR_SERVICENOW_USER, and DFIR_SERVICENOW_PASSWORD)",
      });
    if (!options.servicenowExportStore)
      return res.status(501).json({ error: "servicenow export store not configured" });
    if (!options.stateStore) return res.status(501).json({ error: "state store not configured" });
    const caseId = req.params.id;
    try {
      const state = await options.stateStore.load(caseId);
      const findingId = typeof req.body?.findingId === "string" ? req.body.findingId : "";
      const finding = state.findings.find((f) => f.id === findingId);
      if (!finding) return res.status(404).json({ error: `finding ${findingId} not found` });
      logLine(`[servicenow] ${caseId} finding ${findingId} push START`);
      const result = await pushFindingToServiceNow(options.servicenowClient, options.servicenowExportStore, {
        caseId,
        finding,
        caller: typeof req.body?.caller === "string" ? req.body.caller : options.servicenowOptions?.caller,
        category:
          typeof req.body?.category === "string" ? req.body.category : options.servicenowOptions?.category,
        subcategory:
          typeof req.body?.subcategory === "string"
            ? req.body.subcategory
            : options.servicenowOptions?.subcategory,
      });
      logLine(`[servicenow] ${caseId} finding ${findingId} push DONE -> ${result.incident.number}`);
      void logActivity(options.activityLogStore, options.onActivity, caseId, {
        category: "export",
        action: "push-servicenow",
        detail: `pushed finding ${findingId} to ServiceNow ${result.incident.number}`,
      });
      return res.status(200).json(result);
    } catch (err) {
      logLine(`[servicenow] ${caseId} push ERROR: ${(err as Error).message}`);
      return res.status(502).json({ error: (err as Error).message });
    }
  });

  // Push SEVERAL findings as ServiceNow incidents in one call (issue #297). Body { findingIds,
  // caller?, category?, subcategory? }. Same batch contract as the Jira bulk route above: an unknown
  // or refused finding is skipped with the reason kept, the rest still go, and a re-push UPDATES the
  // incidents already opened.
  app.post("/cases/:id/push/servicenow/bulk", async (req: Request, res: Response) => {
    if (!options.servicenowClient)
      return res.status(501).json({
        error:
          "ServiceNow not configured (set DFIR_SERVICENOW_URL, DFIR_SERVICENOW_USER, and DFIR_SERVICENOW_PASSWORD)",
      });
    if (!options.servicenowExportStore)
      return res.status(501).json({ error: "servicenow export store not configured" });
    if (!options.stateStore) return res.status(501).json({ error: "state store not configured" });
    const caseId = req.params.id;
    const findingIds: string[] = Array.isArray(req.body?.findingIds)
      ? req.body.findingIds.filter((v: unknown): v is string => typeof v === "string" && !!v.trim())
      : [];
    if (!findingIds.length)
      return res.status(400).json({ error: "findingIds is required (a non-empty array of finding ids)" });
    try {
      const state = await options.stateStore.load(caseId);
      const byId = new Map(state.findings.map((f) => [f.id, f]));
      const findings = findingIds.map((fid) => byId.get(fid)).filter((f): f is Finding => !!f);
      const missing = findingIds.filter((fid) => !byId.has(fid));
      logLine(`[servicenow] ${caseId} bulk push START (${findings.length} finding(s))`);
      const result = await pushFindingsToServiceNow(options.servicenowClient, options.servicenowExportStore, {
        caseId,
        findings,
        caller: typeof req.body?.caller === "string" ? req.body.caller : options.servicenowOptions?.caller,
        category:
          typeof req.body?.category === "string" ? req.body.category : options.servicenowOptions?.category,
        subcategory:
          typeof req.body?.subcategory === "string"
            ? req.body.subcategory
            : options.servicenowOptions?.subcategory,
      });
      const body = {
        ...result,
        skipped: result.skipped + missing.length,
        warnings: [...result.warnings, ...missing.map((fid) => `finding ${fid}: not found in this case`)],
      };
      logLine(
        `[servicenow] ${caseId} bulk push DONE: +${body.created} created, ${body.updated} updated, ${body.skipped} skipped, warnings ${body.warnings.length}`,
      );
      void logActivity(options.activityLogStore, options.onActivity, caseId, {
        category: "export",
        action: "push-servicenow",
        detail: `pushed ${findings.length} finding(s) to ServiceNow — +${body.created} created, ${body.updated} updated`,
      });
      return res.status(200).json(body);
    } catch (err) {
      logLine(`[servicenow] ${caseId} bulk push ERROR: ${(err as Error).message}`);
      return res.status(502).json({ error: (err as Error).message });
    }
  });
}
