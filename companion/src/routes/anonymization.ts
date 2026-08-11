import type { Express, Request, Response } from "express";
import { logActivity } from "../analysis/activityLog.js";
import { AnonControlStore, type AnonControl } from "../analysis/anonControl.js";
import { CustomEntitiesStore, sanitizeCustomEntities } from "../analysis/anonEntities.js";
import { DiscoveredEntitiesStore } from "../analysis/anonDiscovered.js";
import { PresidioPendingStore } from "../analysis/presidioPending.js";
import { isLocalAiProvider, deriveKnownEntities, type AnonTokenCategory } from "../analysis/anonymize.js";
import { TesseractOcrRunner } from "../analysis/ocrRedact.js";
import { resolveRedactedExportOptions, redactedExportFilename } from "../analysis/redactedExport.js";
import { buildRedactedExport } from "../reports/redactedExportBuilder.js";
import { CustomerStore } from "../analysis/customerStore.js";
import { isValidCaseId } from "../storage/caseStore.js";
import { normalizeHuntPlatform, HUNT_PLATFORMS, type HuntPlatform } from "../analysis/huntPlatforms.js";
import { visionEnv } from "../config/aiEnv.js";
import { sendPipelineError } from "./presidioApproval.js";
import type { RouteContext } from "./context.js";

/**
 * Anonymization domain: per-case anonymization control (the AI-input tokenization toggle +
 * per-category flags), the analyst-managed entity list (auto-discovered ∪ custom ∪ suppressed),
 * the redacted case-package export (#54), on-demand deobfuscation (#97), and plain-English→query
 * translation (#100).
 *
 * Pure structural move out of createApp (see routes/system.ts for the conventions). Nothing here
 * is shared back with createApp beyond two already-graduated members reused via ctx:
 *   - applyDeobfuscationToCase — the shared deobfuscation sweep (owned by createApp; also fired by
 *     the push-ingest seam), graduated for the import domain and reused by POST /deobfuscate here.
 *   - resynthesizeInBackground — the shared post-mutation re-synthesis kick, likewise graduated.
 * Plus the stable ctx surface (store, options, serverLogger).
 *
 * Domain-local state is rebuilt in-module from ctx.store: the three stateless disk-backed stores
 * (anonControl, customEntities, discoveredEntities) each just wrap ctx.store, so a fresh instance
 * reads/writes the SAME files as createApp's — identical construction, no shared mutable handle
 * (the threatIntel store-instance precedent). `visionIsLocal` is a pure env-derived boolean. None
 * of this is referenced elsewhere in createApp, so nothing needed graduating.
 *
 * NOTE: the AI-input tokenization PATH itself (the anonymizer that the pipeline applies on the
 * wire) stays in createApp / the pipeline — this module only owns the ROUTES that read/write the
 * per-case anonymization config + entity lists and the redacted export. The interleaved non-anon
 * routes between these handlers in the original createApp (scope, events, false-positive, etc.)
 * were intentionally left in place.
 */
export function registerAnonymizationRoutes(app: Express, ctx: RouteContext): void {
  const { store, options } = ctx;
  // Module-private wrapper mirroring createApp's logLine (serverLogger.info), so the moved handler
  // bodies keep their original `logLine(...)` calls verbatim.
  const logLine = (msg: string): void => ctx.serverLogger.info(msg);

  // Per-case anonymization control (default ON) + the analyst-added entity list. Screenshots are
  // OCR-redacted (best-effort) when the vision provider is external, so the dashboard warns (anon on
  // + external) that residual text may survive — `screenshotWarning` gates that notice.
  const anonControl = new AnonControlStore(store);
  const customEntities = new CustomEntitiesStore(store);
  const discoveredEntities = new DiscoveredEntitiesStore(store);
  const presidioPending = new PresidioPendingStore(store);
  const visionIsLocal = isLocalAiProvider(
    visionEnv(process.env, "PROVIDER"),
    visionEnv(process.env, "BASE_URL"),
  );
  // Whether the optional Presidio layer is wired. Reported to the dashboard because the anonymization
  // panel otherwise overstates its coverage: PERSON is minted ONLY from Presidio findings, so with
  // Presidio off nothing detects people's names. Derived from the SAME variable startServer reads to
  // build the pipeline's presidio option, and — like `visionIsLocal` — captured once at registration
  // rather than per request, so it reports what the RUNNING pipeline actually got. A later .env edit
  // changes the file, not this process (DFIR_PRESIDIO_ is deliberately absent from /settings/reload's
  // allowlist); claiming otherwise would tell an analyst names are masked when no gate exists.
  const presidioConfigured = (process.env.DFIR_PRESIDIO_URL ?? "").trim() !== "";

  // Anonymization control: GET reports the control + whether screenshots are exposed (anon on +
  // external vision) + whether Presidio is available. POST updates it and, when `enabled` flips,
  // forces a re-synth so conclusions reflect the new wire policy (the skip-if-unchanged hash is keyed
  // on real inputs and won't notice).
  app.get("/cases/:id/anon-control", async (req: Request, res: Response) => {
    try {
      const c = await anonControl.load(req.params.id);
      return res
        .status(200)
        .json({ ...c, screenshotWarning: c.enabled && !visionIsLocal, presidioConfigured });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });
  app.post("/cases/:id/anon-control", async (req: Request, res: Response) => {
    try {
      const cur = await anonControl.load(req.params.id);
      // Only accept KNOWN category keys with BOOLEAN values; anything else keeps the current value.
      // (A blind spread would let `{categories:{IP:null}}` persist a falsy non-boolean and silently
      // disable a category while `enabled` stays true.)
      const reqCats = (req.body?.categories ?? {}) as Record<string, unknown>;
      const categories = { ...cur.categories };
      for (const k of Object.keys(categories) as (keyof AnonControl["categories"])[]) {
        if (typeof reqCats[k] === "boolean") categories[k] = reqCats[k];
      }
      const next: AnonControl = {
        enabled: typeof req.body?.enabled === "boolean" ? req.body.enabled : cur.enabled,
        categories,
        redactSecrets:
          typeof req.body?.redactSecrets === "boolean" ? req.body.redactSecrets : cur.redactSecrets,
      };
      await anonControl.save(req.params.id, next);
      if (next.enabled !== cur.enabled && options.pipeline && options.pipeline.hasSynthesisProvider()) {
        void options.pipeline.synthesize(req.params.id, { force: true }).catch(() => {});
      }
      if (next.enabled !== cur.enabled) {
        void logActivity(options.activityLogStore, options.onActivity, req.params.id, {
          category: "anonymization",
          action: "anon-control",
          detail: `anonymization ${next.enabled ? "enabled" : "disabled"}`,
        });
      }
      return res
        .status(200)
        .json({ ...next, screenshotWarning: next.enabled && !visionIsLocal, presidioConfigured });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // The entities that will be anonymized for a case: `auto` (auto-discovery — derived from the
  // timeline PLUS entities the OCR pass tokenized out of screenshots, grouped by category, with
  // analyst-suppressed values removed) + `custom` (analyst-added) + `suppressed` (removed values).
  // POST replaces the custom list; the /suppress + /unsuppress routes manage auto-discovery removals.
  app.get("/cases/:id/anon-entities", async (req: Request, res: Response) => {
    try {
      const custom = await customEntities.load(req.params.id);
      const disc = await discoveredEntities.load(req.params.id);
      const suppressed = new Set(disc.suppressed);
      const groups: Record<AnonTokenCategory, string[]> = {
        IP: [],
        EXTIP: [],
        EMAIL: [],
        USER: [],
        HOST: [],
        DOMAIN: [],
        PATH: [],
        CMD: [],
        REG: [],
        CARD: [],
        PHONE: [],
        NATID: [],
        PERSON: [],
        OTHER: [],
      };
      if (options.stateStore) {
        const d = deriveKnownEntities(await options.stateStore.load(req.params.id));
        groups.HOST.push(...d.hosts);
        groups.USER.push(...d.accounts);
        groups.DOMAIN.push(...d.internalDomains);
      }
      for (const e of disc.discovered) groups[e.category]?.push(e.value);
      // Per group: drop suppressed values + dedupe case-insensitively (keep first spelling).
      const clean = (arr: string[]): string[] => {
        const seen = new Set<string>();
        const out: string[] = [];
        for (const v of arr) {
          const k = v.toLowerCase();
          if (suppressed.has(k) || seen.has(k)) continue;
          seen.add(k);
          out.push(v);
        }
        return out;
      };
      const auto = {
        hosts: clean(groups.HOST),
        accounts: clean(groups.USER),
        internalDomains: clean(groups.DOMAIN),
        ips: clean(groups.IP),
        extIps: clean(groups.EXTIP),
        emails: clean(groups.EMAIL),
        paths: clean(groups.PATH),
        other: clean(groups.OTHER),
      };
      return res.status(200).json({ auto, custom, suppressed: disc.suppressed });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });
  app.post("/cases/:id/anon-entities", async (req: Request, res: Response) => {
    try {
      const entities = sanitizeCustomEntities(req.body?.entities);
      await customEntities.save(req.params.id, entities);
      return res.status(200).json({ custom: entities });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });
  // Remove a wrong entity from auto-discovery: it's hidden from the list AND never anonymized again
  // (the anonymizer's suppression set), reversible via /unsuppress.
  app.post("/cases/:id/anon-entities/suppress", async (req: Request, res: Response) => {
    try {
      const value = typeof req.body?.value === "string" ? req.body.value.trim() : "";
      if (!value) return res.status(400).json({ error: "value is required" });
      const next = await discoveredEntities.suppress(req.params.id, value);
      return res.status(200).json({ suppressed: next.suppressed });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });
  app.post("/cases/:id/anon-entities/unsuppress", async (req: Request, res: Response) => {
    try {
      const value = typeof req.body?.value === "string" ? req.body.value.trim() : "";
      if (!value) return res.status(400).json({ error: "value is required" });
      const next = await discoveredEntities.unsuppress(req.params.id, value);
      return res.status(200).json({ suppressed: next.suppressed });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Presidio findings awaiting approval (issue: optional Presidio PII gate). The AI call that
  // produced them failed with 409 (see sendPipelineError in presidioApproval.ts); the analyst
  // resolves each value here, then re-runs the action.
  app.get("/cases/:id/presidio-pending", async (req: Request, res: Response) => {
    if (!isValidCaseId(req.params.id)) return res.status(400).json({ error: "invalid case id" });
    try {
      return res.json({ pending: await presidioPending.load(req.params.id) });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Approve ("Hide from AI"): the value joins the case's CUSTOM entity list, so from now on it is
  // tokenized like any other known entity and never prompts again. Distinct from suppress (below)
  // — this path ADDS the value, never vetoes it.
  //
  // Custom rather than `discovered` on purpose. Both feed the anonymizer identically (the pipeline
  // builds `known.custom` from custom ∪ discovered), so masking is unaffected either way — but the
  // dashboard renders them very differently. `discovered` is the AUTO-DETECTED section: read-only,
  // described as what the companion found by itself. Approving is the opposite of automatic: an
  // analyst was shown a value and decided it is PII. That belongs in CUSTOM ENTITIES, which the UI
  // labels "add anything the auto-detection missed" — a precise description of a Presidio finding,
  // since Presidio exists to catch what the built-in patterns cannot. It also leaves the analyst
  // able to edit or remove it afterwards, which the read-only auto list does not.
  //
  // The log line deliberately omits the value itself, same as suppress below — but for the
  // OPPOSITE reason: a suppressed value might still be real PII (the analyst merely judged it a
  // false positive), while an APPROVED value is confirmed PII by definition (approving it is the
  // act of saying "mask this from now on"). These per-case logs live in the case directory and
  // travel with the evidence as part of the audit trail, so writing the confirmed name into them
  // would defeat the whole point of the masking feature.
  app.post("/cases/:id/presidio-pending/approve", async (req: Request, res: Response) => {
    if (!isValidCaseId(req.params.id)) return res.status(400).json({ error: "invalid case id" });
    try {
      const caseId = req.params.id;
      const entities = sanitizeCustomEntities([req.body]);
      if (entities.length === 0) return res.status(400).json({ error: "value is required" });
      // CustomEntitiesStore has no append, so read-modify-write. sanitizeCustomEntities dedupes
      // case-insensitively with first-wins, so re-approving an already-present value is a no-op
      // rather than a duplicate row.
      const existing = await customEntities.load(caseId);
      await customEntities.save(caseId, [...existing, ...entities]);
      const rest = (await presidioPending.load(caseId)).filter(
        (e) => e.value.toLowerCase() !== entities[0].value.toLowerCase(),
      );
      await presidioPending.save(caseId, rest);
      logLine(`[presidio] approved a ${entities[0].category} finding for case ${caseId}`);
      void logActivity(options.activityLogStore, options.onActivity, caseId, {
        category: "anonymization",
        action: "presidio-approve",
        detail: `Approved a Presidio ${entities[0].category} finding for masking`,
      });
      return res.json({ pending: rest });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Never ask again: the value is vetoed at the assign() chokepoint (added to `suppressed`) and
  // hidden from the list. Distinct from approve (above) — this path NEVER adds to `discovered`, so
  // the value is never tokenized. The log line deliberately omits the value itself: the analyst
  // marked it a false positive, but it may still be real PII.
  app.post("/cases/:id/presidio-pending/suppress", async (req: Request, res: Response) => {
    if (!isValidCaseId(req.params.id)) return res.status(400).json({ error: "invalid case id" });
    try {
      const caseId = req.params.id;
      const value = typeof req.body?.value === "string" ? req.body.value.trim() : "";
      if (!value) return res.status(400).json({ error: "value is required" });
      await discoveredEntities.suppress(caseId, value);
      const rest = (await presidioPending.load(caseId)).filter(
        (e) => e.value.toLowerCase() !== value.toLowerCase(),
      );
      await presidioPending.save(caseId, rest);
      logLine(`[presidio] suppressed a finding for case ${caseId}`);
      void logActivity(options.activityLogStore, options.onActivity, caseId, {
        category: "anonymization",
        action: "presidio-suppress",
        detail: "Suppressed a Presidio finding (marked not PII)",
      });
      return res.json({ pending: rest });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Redacted case package (#54): a shareable ZIP for external parties. Internal IPs / hosts /
  // usernames / emails / paths in the report (and CSVs / state JSON) are tokenized, secrets are
  // one-way redacted, screenshot EXIF is stripped, and detectable PII text in screenshots is
  // blurred (best-effort OCR). AI provider keys + per-case config are NEVER included — the package
  // is built from a curated allowlist, not a copy of the case folder. Built fresh per request; the
  // canonical on-disk report (which keeps the REAL values) is never touched. Query flags
  // (?screenshots=0 / ?blur=0 / ?csvs=0 / ?state=0 / ?report=0) opt parts out.
  app.get("/cases/:id/export/redacted", async (req: Request, res: Response) => {
    if (!options.reportWriter || !options.stateStore) {
      return res.status(501).json({ error: "report writer not configured" });
    }
    if (!isValidCaseId(req.params.id)) {
      return res.status(400).json({ error: "invalid case id" });
    }
    try {
      const exportOptions = resolveRedactedExportOptions(req.query);
      const { zip } = await buildRedactedExport(
        {
          store,
          reportWriter: options.reportWriter,
          stateStore: options.stateStore,
          customEntities,
          discoveredEntities,
          // Victim org domains/emails the analyst entered for the exposure check are PII too —
          // feed them to the anonymizer so they're tokenized even when absent from the timeline.
          customerStore: new CustomerStore(store),
          // Victim org NAME: the anonymizer has no free-text detector, so feed meta.organization
          // as a custom OTHER entity so it's tokenized to ANON_OTHER_n wherever it appears (#13).
          reportMetaStore: options.reportMetaStore,
          ocrRunner: options.ocrRunner ?? new TesseractOcrRunner(),
        },
        req.params.id,
        exportOptions,
      );
      // The package carries redacted derivatives rather than the originals, but the evidence still
      // left the instance — so each artifact under custody gets an `exported` event naming the
      // redacted package as its destination (#231).
      await options.custodyStore?.recordExport(req.params.id, {
        exportedBy: "analyst",
        destination: "redacted export package",
      });
      res.type("application/zip");
      res.setHeader("Content-Disposition", `attachment; filename="${redactedExportFilename(req.params.id)}"`);
      res.setHeader("Cache-Control", "private, no-cache");
      return res.send(zip);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // On-demand deobfuscation (#97): scan the case's forensic timeline for obfuscated command
  // lines, decode them, extract hidden IOCs, and re-synthesize so findings reflect the decoded
  // content. Idempotent: already-decoded events are skipped.
  app.post("/cases/:id/deobfuscate", async (req: Request, res: Response) => {
    if (!options.stateStore) return res.status(501).json({ error: "state store not configured" });
    const caseId = req.params.id;
    try {
      const result = await ctx.applyDeobfuscationToCase(caseId);
      if (result.deobfuscated > 0) ctx.resynthesizeInBackground(caseId);
      logLine(
        `[deobfuscate] ${caseId} apply — decoded ${result.deobfuscated} event(s), +${result.newIocs} new IOC(s)`,
      );
      return res.status(200).json(result);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Translate a plain-English hunting request into runnable queries per platform (issue #100).
  // EPHEMERAL (no state change) — the dashboard shows each query for review, copy, and (for the
  // Velociraptor query) one-click deploy via POST /velociraptor/hunt. Body: { request, platforms? }.
  // `platforms` is an optional analyst-chosen subset; both it and the result are bounded by the
  // server's DFIR_HUNT_PLATFORMS allowlist so a disabled platform is never generated.
  app.post("/cases/:id/translate-query", async (req: Request, res: Response) => {
    if (!options.pipeline || !options.pipeline.hasSynthesisProvider())
      return res.status(501).json({ error: "AI provider not configured for query translation" });
    const request = typeof req.body?.request === "string" ? req.body.request.trim() : "";
    if (!request) return res.status(400).json({ error: "request is required" });
    const enabled = options.huntPlatforms ?? [...HUNT_PLATFORMS];
    const bodyPlatforms = Array.isArray(req.body?.platforms)
      ? req.body.platforms
          .map((p: unknown) => normalizeHuntPlatform(typeof p === "string" ? p : ""))
          .filter((p: HuntPlatform | null): p is HuntPlatform => !!p)
      : [];
    const wanted = bodyPlatforms.length ? enabled.filter((p) => bodyPlatforms.includes(p)) : enabled;
    const platforms = wanted.length ? wanted : enabled;
    try {
      const result = await options.pipeline.translateQuery(req.params.id, request, platforms);
      logLine(`[translate-query] produced ${result.queries.length} query/ies for ${req.params.id}`);
      void logActivity(options.activityLogStore, options.onActivity, req.params.id, {
        category: "ai",
        action: "translate-query",
        detail: `translated: "${request.slice(0, 120)}" — ${result.queries.length} quer(y/ies)`,
      });
      return res.status(200).json(result);
    } catch (err) {
      return sendPipelineError(res, err, { caseId: req.params.id, onAiStatus: options.onAiStatus });
    }
  });
}
