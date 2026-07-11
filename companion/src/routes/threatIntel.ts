import { readFile } from "node:fs/promises";
import { randomUUID } from "node:crypto";
import { ZodError } from "zod";
import type { Express, Request, Response } from "express";
import { logActivity } from "../analysis/activityLog.js";
import { EnrichControlStore, resolveEnabledProviders } from "../enrichment/enrichControl.js";
import { enrichIocs } from "../enrichment/enrichService.js";
import { mergeEnrichedSubset } from "../analysis/iocBulkOps.js";
import { deriveIocProvenance } from "../analysis/iocProvenance.js";
import { buildIocProvenanceChains } from "../analysis/iocProvenanceChain.js";
import { parseWhitelistText, toWhitelistCsv, sanitizeRuleInput } from "../analysis/iocWhitelist.js";
import { sanitizeExcludeRuleInput, matchIocToExclude, type IocExcludeRule } from "../analysis/iocExclude.js";
import { ingestNsrlFiles, splitNsrlPaths } from "../analysis/nsrlStore.js";
import { parseNsrlText } from "../analysis/nsrl.js";
import { NsrlDb, saveNsrlDbPath, removeNsrlDbPath } from "../analysis/nsrlDb.js";
import { buildManualIoc } from "../analysis/manualEntry.js";
import { CustomerStore, parseList, sanitizeTargets } from "../analysis/customerStore.js";
import { buildCustomerExposureTargets, CustomerExposureStore, summarizeExposure } from "../analysis/customerExposure.js";
import { FalsePositiveStore } from "../analysis/falsePositive.js";
import type { Tag } from "../analysis/tags.js";
import type { ForensicEvent } from "../analysis/stateTypes.js";
import type { RouteContext } from "./context.js";

/**
 * Threat-intel domain: IOC management (manual add, bulk-enrich, bulk-tag, provenance/sources), the
 * global IOC whitelist + per-case IOC exclude list, threat-intel ENRICHMENT (per-case provider
 * control, one-shot re-scan, provider health), the CISA KEV catalog, NSRL known-good hashes (flat
 * set + RDS SQLite connection), and the customer-exposure / breach-data lookups.
 *
 * Pure structural move out of createApp (see routes/system.ts for the conventions). The enrichment
 * ENGINE stays in createApp because it is driven by a self-managing background reachability poller
 * and by the resynthesize/auto-enrich seams that other domains fire; this module reaches it through
 * the graduated RouteContext members it needs:
 *   - enrichInBackground / autoEnrichIfEnabled / enabledProvidersFor (stable methods) — the shared
 *     enrich gating + engine, still owned by createApp (the reachability poller re-arms them).
 *   - enrichPending() (live accessor) — the Set of cases waiting on a down provider that the
 *     background poller drains; POST /cases/:id/enrich-control mutates the SAME Set.
 *   - nsrlDb() / setNsrlDb() — the NSRL RDS SQLite connection is a MUTABLE shared handle: this
 *     module's POST/DELETE /nsrl/db routes swap it at runtime, and createApp's applyNsrlToCase reads
 *     it, so the read+reassign go through the graduated accessor+setter rather than a captured copy.
 * Plus already-graduated members reused here: enrichHealth() (shared provider reachability cache),
 * applyWhitelistToCase / applyNsrlToCase (the false-positive sweeps), resynthesizeInBackground.
 *
 * Domain-local state is (re)built in-module from ctx.options/ctx.store: the enrich provider catalogue
 * (allProviders/configuredNames/localNames/ALL_KNOWN_PROVIDERS), the stateless per-case stores
 * (enrichControl, customerStore, customerExposureStore, falsePositives), and the exposure provider
 * list — none of it is shared with createApp beyond what's noted above.
 *
 * NOTE: interleaved non-threat-intel routes were intentionally left in createApp (adversary-hints,
 * false-positive*, events, importers*, deobfuscate, scope, api/jobs, synthesize) as were the
 * applyWhitelistToCase / applyNsrlToCase / applyDeobfuscationToCase helpers (graduated ctx members).
 */
export function registerThreatIntelRoutes(app: Express, ctx: RouteContext): void {
  const { store, options } = ctx;
  // Module-private wrapper mirroring createApp's logLine (serverLogger.info), so the moved handler
  // bodies keep their original `logLine(...)` calls verbatim.
  const logLine = (msg: string): void => ctx.serverLogger.info(msg);
  // Serialize the load->save critical section for a case's investigation.json (module-private copy of
  // createApp's non-exported helper; no-op when no StateLock is wired, e.g. tests).
  const runStateExclusive = <T>(caseId: string, fn: () => Promise<T>): Promise<T> =>
    options.stateLock ? options.stateLock.runExclusive(caseId, fn) : fn();

  // Provider classification (from the configured set) — a stable projection of options, identical to
  // the copy createApp keeps for the enrich engine.
  const allProviders = options.enrichmentProviders ?? [];
  const configuredNames = allProviders.map((p) => p.name);
  const localNames = allProviders.filter((p) => p.scope === "local").map((p) => p.name);

  // Stateless per-case stores (each just wraps ctx.store); a fresh instance reads/writes the same
  // files as createApp's, matching the customerExposureStore/reportWriter store-instance precedent.
  const enrichControl = new EnrichControlStore(store);
  const falsePositives = new FalsePositiveStore(store);
  // Customer exposure / breach-data lookups. This is deliberately NOT IOC enrichment:
  // only manually entered customer domains/emails plus observed emails under those customer
  // domains are sent to providers. Remote domains collected as IOCs are never queried here.
  const customerStore = new CustomerStore(store);
  const customerExposureStore = new CustomerExposureStore(store);
  const customerExposureProviders = options.customerExposureProviders ?? [];

  // Full catalogue of every known enrichment provider — shown in the picker regardless of whether
  // the key is configured, so analysts can see what's available and what env var to add.
  const ALL_KNOWN_PROVIDERS: Array<{ name: string; scope: "local" | "external"; keyHint: string }> = [
    { name: "VirusTotal",   scope: "external", keyHint: "DFIR_VT_KEY" },
    { name: "Hunting.ch",   scope: "external", keyHint: "DFIR_HUNTINGCH_KEY" },
    { name: "AbuseIPDB",    scope: "external", keyHint: "DFIR_ABUSEIPDB_KEY" },
    { name: "CrowdStrike",  scope: "external", keyHint: "DFIR_CROWDSTRIKE_CLIENT_ID + _SECRET" },
    { name: "RockyRaccoon", scope: "external", keyHint: "DFIR_ROCKYRACCOON_KEY" },
    { name: "Shodan",       scope: "external", keyHint: "DFIR_SHODAN_KEY" },
    { name: "Hashlookup",   scope: "external", keyHint: "" },
    { name: "Reverse DNS",  scope: "external", keyHint: "" },
    { name: "WHOIS",        scope: "external", keyHint: "" },
    { name: "GeoIP",        scope: "external", keyHint: "" },
    { name: "MISP",         scope: "local",    keyHint: "DFIR_MISP_URL + DFIR_MISP_KEY" },
    { name: "YETI",         scope: "local",    keyHint: "DFIR_YETI_URL + DFIR_YETI_KEY" },
    { name: "OpenCTI",      scope: "local",    keyHint: "DFIR_OPENCTI_URL + DFIR_OPENCTI_KEY" },
  ];

  app.get("/cases/:id/ioc-sources", async (req: Request, res: Response) => {
    if (!options.reportWriter) return res.status(501).json({ error: "report writer not configured" });
    try {
      return res.status(200).json(await options.reportWriter.iocSources(req.params.id));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // #IOC provenance: class each IOC detection-linked (appears in a Low+ event) vs telemetry-only
  // (Info-only). Derived on read over forensic ∪ super events (telemetry-only IOCs live in super
  // under the severity gate). Distinct from the threat-intel verdict. Powers the dashboard IOC badge/filter.
  // Uses RAW (unfiltered) state.load — an IOC is detection-linked if ANY event was Low+, even one
  // later scoped/legit out — so provenance reflects the complete evidence picture, not the report view.
  app.get("/cases/:id/ioc-provenance", async (req: Request, res: Response) => {
    if (!options.stateStore) return res.status(501).json({ error: "state store not configured" });
    try {
      if (!(await store.caseExists(req.params.id))) {
        return res.status(404).json({ error: `case ${req.params.id} does not exist` });
      }
      const state = await options.stateStore.load(req.params.id);
      // The provenance index must see EVERY super event, not one page — query with no filters and a
      // limit past the store cap so pagination returns the full set.
      let superEvents: ForensicEvent[] = [];
      if (options.superTimelineStore) {
        superEvents = (await options.superTimelineStore.query(req.params.id, { limit: Number.MAX_SAFE_INTEGER })).events;
      }
      return res.status(200).json(deriveIocProvenance(state.iocs, [...state.forensicTimeline, ...superEvents]));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // IOC provenance CHAIN (#247): for every IOC, the full story — extraction event(s), enrichment
  // lookups, and citing findings, each timestamped. Distinct from /ioc-provenance above (which only
  // classes detection-linked vs telemetry-only). Extraction is APPROXIMATE (indexed exact-token
  // match against forensic ∪ super events — no importer records which specific event produced an
  // IOC); enrichment + findings legs are authoritative. Powers the dashboard's per-IOC provenance
  // panel + its "export as JSON" button.
  app.get("/cases/:id/ioc-provenance-chain", async (req: Request, res: Response) => {
    if (!options.stateStore) return res.status(501).json({ error: "state store not configured" });
    try {
      if (!(await store.caseExists(req.params.id))) {
        return res.status(404).json({ error: `case ${req.params.id} does not exist` });
      }
      const state = await options.stateStore.load(req.params.id);
      let superEvents: ForensicEvent[] = [];
      if (options.superTimelineStore) {
        superEvents = (await options.superTimelineStore.query(req.params.id, { limit: Number.MAX_SAFE_INTEGER })).events;
      }
      return res.status(200).json(buildIocProvenanceChains(state.iocs, [...state.forensicTimeline, ...superEvents], state.findings));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.get("/cases/:id/customer-exposure", async (req: Request, res: Response) => {
    if (!options.stateStore) return res.status(501).json({ error: "state store not configured" });
    try {
      const state = await options.stateStore.load(req.params.id);
      const targets = await customerStore.load(req.params.id);
      return res.status(200).json({
        anyConfigured: customerExposureProviders.length > 0,
        providers: customerExposureProviders.map((p) => p.name),
        targets,
        effectiveTargets: buildCustomerExposureTargets(state, targets),
        exposure: await customerExposureStore.load(req.params.id),
      });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.put("/cases/:id/customer-exposure/targets", async (req: Request, res: Response) => {
    try {
      const targets = sanitizeTargets(req.body ?? {});
      await customerStore.save(req.params.id, targets);
      return res.status(200).json({ targets });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.post("/cases/:id/customer-exposure/check", async (req: Request, res: Response) => {
    if (!options.stateStore) return res.status(501).json({ error: "state store not configured" });
    if (customerExposureProviders.length === 0) {
      return res.status(501).json({ error: "no customer exposure providers configured (set DFIR_LEAKCHECK_KEY / DFIR_DEHASHED_KEY / DFIR_HIBP_KEY / DFIR_SHODAN_KEY)" });
    }
    const caseId = req.params.id;
    try {
      const state = await options.stateStore.load(caseId);
      const targets = await customerStore.load(caseId);
      // Provider selection (like the enrichment per-source picker): a `providers` list in the
      // request body wins (one-off run), else the saved selection (customer.json), else all
      // configured. A name not matching a configured provider is simply ignored.
      const requested = parseList(req.body?.providers).map((s) => s.trim()).filter(Boolean);
      const selection = requested.length ? requested : (targets.providers?.length ? targets.providers : null);
      const active = selection ? customerExposureProviders.filter((p) => selection.includes(p.name)) : customerExposureProviders;
      if (active.length === 0) return res.status(400).json({ error: "no matching exposure providers selected" });
      options.onAiStatus?.(caseId, { status: "analyzing", phase: "extracting", at: new Date().toISOString(), detail: "checking customer exposure" });
      const summary = await summarizeExposure(state, targets, active, {
        delayMs: options.customerExposureDelayMs,
      });
      await customerExposureStore.save(caseId, summary);
      options.onAiStatus?.(caseId, { status: "idle", at: new Date().toISOString(), detail: `customer exposure: ${summary.results.length} hit(s), ${summary.errors.length} error(s)` });
      logLine(`[exposure] ${caseId} providers=[${summary.providers.join(", ")}] domains=${summary.targets.domains.length} emails=${summary.targets.emails.length} hits=${summary.results.length} errors=${summary.errors.length}`);
      return res.status(200).json(summary);
    } catch (err) {
      options.onAiStatus?.(caseId, { status: "error", at: new Date().toISOString(), detail: (err as Error).message });
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Manually add an IOC the AI didn't catch. Appended to the case IOCs (deduped by value) and
  // enriched if enrichment is enabled for the case.
  app.post("/cases/:id/iocs", async (req: Request, res: Response) => {
    if (!options.stateStore) return res.status(501).json({ error: "state store not configured" });
    const caseId = req.params.id;
    try {
      const ioc = buildManualIoc(req.body);
      const stateStore = options.stateStore;
      let conflict = false;
      await runStateExclusive(caseId, async () => {
        const state = await stateStore.load(caseId);
        if (state.iocs.some((i) => i.value.toLowerCase() === ioc.value.toLowerCase())) { conflict = true; return; }
        const next = { ...state, iocs: [...state.iocs, ioc], updatedAt: new Date().toISOString() };
        await stateStore.save(next);
        options.onState?.(next);
      });
      if (conflict) return res.status(409).json({ error: `IOC already exists: ${ioc.value}` });
      ctx.autoEnrichIfEnabled(caseId);
      logLine(`[manual] ${caseId} added ioc ${ioc.id} (${ioc.type})`);
      return res.status(201).json(ioc);
    } catch (err) {
      if (err instanceof ZodError) return res.status(400).json({ error: err.issues.map((i) => i.message).join("; ") });
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Enrich a specific subset of the case's IOCs — identified by ID — without touching the
  // rest. Runs enrichIocs on the selected subset, then merges the results back. This is the
  // backend for the dashboard bulk-select "Enrich selected" action. Runs in the background
  // (202 accepted) so the caller isn't blocked on N provider round-trips.
  // Body: { iocIds: string[], force?: boolean }
  app.post("/cases/:id/iocs/bulk-enrich", async (req: Request, res: Response) => {
    const providers = options.enrichmentProviders ?? [];
    if (providers.length === 0) return res.status(501).json({ error: "no enrichment providers configured (set DFIR_VT_KEY / DFIR_MB_KEY / DFIR_HUNTINGCH_KEY / DFIR_ABUSEIPDB_KEY / DFIR_CROWDSTRIKE_CLIENT_ID+_SECRET / DFIR_MISP_* / DFIR_YETI_*)" });
    if (!options.stateStore) return res.status(501).json({ error: "state store not configured" });
    const caseId = req.params.id;
    const rawIds = Array.isArray(req.body?.iocIds) ? req.body.iocIds : [];
    const iocIds = (rawIds as unknown[]).map(String).filter(Boolean);
    if (!iocIds.length) return res.status(400).json({ error: "iocIds must be a non-empty array" });
    const force = req.body?.force === true;
    try {
      const state = await options.stateStore.load(caseId);
      const targetSet = new Set<string>(iocIds);
      const subset = state.iocs.filter((i) => targetSet.has(i.id));
      if (subset.length === 0) return res.status(404).json({ error: "none of the specified IOC IDs were found in this case" });
      const enabledProviders = await ctx.enabledProvidersFor(caseId);
      if (enabledProviders.length === 0) return res.status(422).json({ error: "no enrichment providers enabled for this case — enable providers in the enrichment panel first" });
      void (async () => {
        options.onAiStatus?.(caseId, { status: "analyzing", phase: "extracting", at: new Date().toISOString(), detail: `enriching ${subset.length} selected IOC(s)` });
        const { iocs: enrichedSubset, summary } = await enrichIocs(subset, {
          providers: enabledProviders,
          delayMs: options.enrichDelayMs,
          perProviderDelayMs: options.enrichProviderDelayMs,
          maxIocs: options.enrichMaxIocs,
          force,
          health: ctx.enrichHealth(),
          onProgress: (done, total) => options.onAiStatus?.(caseId, {
            status: "analyzing", phase: "extracting", at: new Date().toISOString(),
            detail: `enriching selected IOC ${done}/${total}`,
          }),
        });
        const current = await options.stateStore!.load(caseId);
        const merged = mergeEnrichedSubset(current.iocs, enrichedSubset);
        const next = { ...current, iocs: merged, updatedAt: new Date().toISOString() };
        await options.stateStore!.save(next);
        options.onState?.(next);
        options.onAiStatus?.(caseId, { status: "idle", at: new Date().toISOString(), detail: `enriched ${summary.withHits}/${summary.queried} selected IOC(s) (errors ${summary.errors})` });
        logLine(`[enrich] ${caseId} bulk ids=${iocIds.length} queried=${summary.queried} hits=${summary.withHits} errors=${summary.errors}`);
      })().catch((err) => options.onAiStatus?.(caseId, { status: "error", at: new Date().toISOString(), detail: (err as Error).message }));
      return res.status(202).json({ accepted: true, iocCount: subset.length, providers: enabledProviders.map((p) => p.name) });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Add a triage label to many IOCs in one request. Serializes the TagsStore writes so
  // concurrent requests don't clobber each other's read-modify-write on tags.json.
  // Body: { iocIds: string[], label: string, author?: string }
  app.post("/cases/:id/iocs/bulk-tag", async (req: Request, res: Response) => {
    if (!options.tagsStore) return res.status(501).json({ error: "tags not configured" });
    const rawIds = Array.isArray(req.body?.iocIds) ? req.body.iocIds : [];
    const iocIds = (rawIds as unknown[]).map(String).filter(Boolean);
    const label = typeof req.body?.label === "string" ? req.body.label.trim() : "";
    const author = typeof req.body?.author === "string" ? req.body.author.trim() : "";
    if (!iocIds.length) return res.status(400).json({ error: "iocIds must be a non-empty array" });
    if (!label) return res.status(400).json({ error: "label is required" });
    const caseId = req.params.id;
    try {
      const tags: Tag[] = [];
      for (const id of iocIds) {
        tags.push(await options.tagsStore.add(caseId, { targetType: "ioc", targetId: id, label, author }));
      }
      options.onTags?.(caseId);
      return res.status(200).json(tags);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // ── IOC whitelist (Phase 2 of #35) ─────────────────────────────────────────────────────────
  // A GLOBAL, environment-level set of "known-good" patterns the analyst maintains (internal IP
  // ranges as CIDR, known-good hashes, regexes for internal domains). An IOC matching a rule is
  // auto-marked a FALSE POSITIVE — reusing the false-positive machinery, so it's reversible and
  // shows in the "False Positives" panel. Auto-applied on import; also on demand per case. (The
  // applyWhitelistToCase sweep itself is a graduated ctx member, still owned by createApp.)
  app.get("/ioc-whitelist", async (_req: Request, res: Response) => {
    if (!options.iocWhitelistStore) return res.status(200).json([]);
    try {
      return res.status(200).json(await options.iocWhitelistStore.load());
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Add one rule. Body: { match: "cidr"|"regex"|"exact", pattern, iocType?, note? }
  app.post("/ioc-whitelist", async (req: Request, res: Response) => {
    if (!options.iocWhitelistStore) return res.status(501).json({ error: "IOC whitelist not configured" });
    const input = sanitizeRuleInput(req.body ?? {});
    if (!input) return res.status(400).json({ error: "invalid rule — need match (cidr|regex|exact) and a valid pattern (valid CIDR for cidr, valid regex for regex)" });
    try {
      const rule = await options.iocWhitelistStore.add(input);
      return res.status(201).json(rule);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.delete("/ioc-whitelist/:ruleId", async (req: Request, res: Response) => {
    if (!options.iocWhitelistStore) return res.status(501).json({ error: "IOC whitelist not configured" });
    try {
      const removed = await options.iocWhitelistStore.remove(req.params.ruleId);
      if (!removed) return res.status(404).json({ error: "rule not found" });
      return res.status(200).json({ removed: true });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Import rules from pasted CSV or JSON. Body: { text }. Returns { added, total }.
  app.post("/ioc-whitelist/import", async (req: Request, res: Response) => {
    if (!options.iocWhitelistStore) return res.status(501).json({ error: "IOC whitelist not configured" });
    const text = typeof req.body?.text === "string" ? req.body.text : "";
    if (!text.trim()) return res.status(400).json({ error: "text is required (CSV or JSON)" });
    try {
      const parsed = parseWhitelistText(text);
      if (parsed.length === 0) return res.status(400).json({ error: "no valid rules found — expected JSON array or CSV with a 'pattern' column" });
      const added = await options.iocWhitelistStore.addMany(parsed);
      return res.status(200).json({ added: added.length, parsed: parsed.length, total: (await options.iocWhitelistStore.load()).length });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Export the whitelist as CSV or JSON (?format=csv|json, default json) for backup / sharing.
  app.get("/ioc-whitelist/export", async (req: Request, res: Response) => {
    if (!options.iocWhitelistStore) return res.status(501).json({ error: "IOC whitelist not configured" });
    try {
      const rules = await options.iocWhitelistStore.load();
      if (String(req.query.format) === "csv") {
        res.setHeader("Content-Type", "text/csv");
        res.setHeader("Content-Disposition", 'attachment; filename="ioc-whitelist.csv"');
        return res.status(200).send(toWhitelistCsv(rules));
      }
      res.setHeader("Content-Type", "application/json");
      res.setHeader("Content-Disposition", 'attachment; filename="ioc-whitelist.json"');
      return res.status(200).send(JSON.stringify(rules, null, 2));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // ── IOC exclude list (per-case, PERMANENT) ─────────────────────────────────────────────────
  // Distinct from the IOC whitelist above: a match here is deleted from the case outright (not
  // just marked false-positive) and is filtered at the source for every future import/AI-synthesis
  // delta (see mergeDelta in stateMerge.ts), so it can never reach enrichment either. Scoped to
  // this case only (not global) — the rules live on InvestigationState.iocExcludeRules.

  app.get("/cases/:id/ioc-exclude", async (req: Request, res: Response) => {
    if (!options.stateStore) return res.status(200).json([]);
    try {
      const state = await options.stateStore.load(req.params.id);
      return res.status(200).json(state.iocExcludeRules);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Add one rule and immediately purge any matching IOCs already in this case. Body:
  // { match: "exact"|"suffix"|"regex", pattern, iocType?, note? }. Returns { rule, purged }.
  app.post("/cases/:id/ioc-exclude", async (req: Request, res: Response) => {
    if (!options.stateStore) return res.status(501).json({ error: "state store not configured" });
    const input = sanitizeExcludeRuleInput(req.body ?? {});
    if (!input) return res.status(400).json({ error: "invalid rule — need match (exact|suffix|regex) and a non-empty pattern (valid regex for regex)" });
    const caseId = req.params.id;
    const stateStore = options.stateStore;
    let rule: IocExcludeRule | undefined;
    let purged = 0;
    try {
      await runStateExclusive(caseId, async () => {
        const state = await stateStore.load(caseId);
        rule = { id: randomUUID(), addedAt: new Date().toISOString(), ...input };
        const nextRules = [...state.iocExcludeRules, rule];
        const keptIocs = state.iocs.filter((ioc) => !matchIocToExclude(ioc, nextRules));
        purged = state.iocs.length - keptIocs.length;
        const next = { ...state, iocs: keptIocs, iocExcludeRules: nextRules, updatedAt: new Date().toISOString() };
        await stateStore.save(next);
        options.onState?.(next);
      });
      logLine(`[ioc-exclude] ${caseId} added rule ${rule!.match}:${rule!.pattern} — purged ${purged} IOC(s)`);
      return res.status(201).json({ rule, purged });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Remove a rule. Does NOT restore any IOCs it already purged — exclusion is a one-way operation.
  app.delete("/cases/:id/ioc-exclude/:ruleId", async (req: Request, res: Response) => {
    if (!options.stateStore) return res.status(501).json({ error: "state store not configured" });
    const caseId = req.params.id;
    const stateStore = options.stateStore;
    let removed = false;
    try {
      await runStateExclusive(caseId, async () => {
        const state = await stateStore.load(caseId);
        const nextRules = state.iocExcludeRules.filter((r) => r.id !== req.params.ruleId);
        removed = nextRules.length !== state.iocExcludeRules.length;
        if (!removed) return;
        const next = { ...state, iocExcludeRules: nextRules, updatedAt: new Date().toISOString() };
        await stateStore.save(next);
        options.onState?.(next);
      });
      if (!removed) return res.status(404).json({ error: "rule not found" });
      return res.status(200).json({ removed: true });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Apply the whitelist to THIS case's current IOCs now (the analyst just added rules, or wants to
  // sweep an already-imported case). Marks matches false-positive, then re-synthesizes so they drop.
  app.post("/cases/:id/ioc-whitelist/apply", async (req: Request, res: Response) => {
    if (!options.iocWhitelistStore) return res.status(501).json({ error: "IOC whitelist not configured" });
    if (!options.stateStore) return res.status(501).json({ error: "state store not configured" });
    const caseId = req.params.id;
    try {
      const result = await ctx.applyWhitelistToCase(caseId);
      if (result.added > 0) ctx.resynthesizeInBackground(caseId);
      logLine(`[whitelist] ${caseId} apply — matched ${result.matched}, added ${result.added}`);
      return res.status(200).json({ ...result, legitimate: await falsePositives.load(caseId) });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // ── NSRL known-good hashes (#63) ───────────────────────────────────────────────────────────────
  // A GLOBAL set of known-software file hashes (NIST NSRL / RDS). A forensic event whose file hash —
  // or an IOC whose value — is in the set is a known-good file, auto-marked a FALSE POSITIVE. The
  // applyNsrlToCase sweep is a graduated ctx member (still owned by createApp); the RDS SQLite
  // connection is a mutable shared handle reached via ctx.nsrlDb()/ctx.setNsrlDb().

  // Stats for the Settings → NSRL panel: the flat set count + the RDS DB connection status. Degrades
  // to "not configured" (200) like /ioc-whitelist. `enabled` = either backend is usable.
  app.get("/nsrl", async (_req: Request, res: Response) => {
    const nsrlDb = ctx.nsrlDb();
    const db = nsrlDb ? nsrlDb.status() : { connected: false };
    const dbConfigurable = Boolean(options.nsrlDbConfigFile) && !options.nsrlDbEnvManaged;
    const dbEnvManaged = Boolean(options.nsrlDbEnvManaged);
    if (!options.nsrlStore) return res.status(200).json({ count: 0, enabled: db.connected, db, dbConfigurable, dbEnvManaged });
    try {
      const count = await options.nsrlStore.count();
      return res.status(200).json({ count, enabled: count > 0 || db.connected, db, dbConfigurable, dbEnvManaged });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Connect (or swap) the NSRL RDS SQLite database at runtime. Body: { path } (the RDS .db on the
  // server). Opens read-only, validates it has a sha256/md5 column, persists the path so it survives
  // a restart. Rejected when env-managed (DFIR_NSRL_DB owns the path). Localhost-only tool: opening a
  // path the operator typed is intended (same trust as the env var).
  app.post("/nsrl/db", async (req: Request, res: Response) => {
    if (options.nsrlDbEnvManaged) return res.status(400).json({ error: "the NSRL RDS path is managed by the DFIR_NSRL_DB env var — unset it to configure here" });
    if (!options.nsrlDbConfigFile) return res.status(501).json({ error: "NSRL RDS database not configured" });
    const path = typeof req.body?.path === "string" ? req.body.path.trim() : "";
    if (!path) return res.status(400).json({ error: "path is required (the NSRL RDS .db file on the server)" });
    try {
      const opened = NsrlDb.open(path); // throws on bad file / no usable hash column
      const current = ctx.nsrlDb();
      if (current) current.close();
      ctx.setNsrlDb(opened);
      await saveNsrlDbPath(options.nsrlDbConfigFile, path);
      logLine(`[nsrl] connected RDS DB ${path} — table ${opened.table}, columns ${opened.columns.join("/")}`);
      return res.status(200).json(opened.status());
    } catch (err) {
      return res.status(400).json({ error: `could not open NSRL RDS: ${(err as Error).message}` });
    }
  });

  // Disconnect the RDS database (the flat set is unaffected).
  app.delete("/nsrl/db", async (_req: Request, res: Response) => {
    if (options.nsrlDbEnvManaged) return res.status(400).json({ error: "the NSRL RDS path is managed by the DFIR_NSRL_DB env var" });
    if (!options.nsrlDbConfigFile) return res.status(501).json({ error: "NSRL RDS database not configured" });
    try {
      const current = ctx.nsrlDb();
      if (current) { current.close(); ctx.setNsrlDb(undefined); }
      await removeNsrlDbPath(options.nsrlDbConfigFile);
      logLine(`[nsrl] disconnected RDS DB`);
      return res.status(200).json({ connected: false });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Import known-good hashes from pasted text or a loaded file: NSRLFile.txt (RDS CSV), a hashdeep
  // CSV, or a plain hash-per-line / comma-separated list. Body: { text }. Returns { added, parsed, total }.
  app.post("/nsrl/import", async (req: Request, res: Response) => {
    if (!options.nsrlStore) return res.status(501).json({ error: "NSRL store not configured" });
    const text = typeof req.body?.text === "string" ? req.body.text : "";
    if (!text.trim()) return res.status(400).json({ error: "text is required (NSRL CSV or a hash list)" });
    try {
      const parsed = parseNsrlText(text);
      if (parsed.length === 0) return res.status(400).json({ error: "no valid hashes found — expected MD5/SHA-1/SHA-256 hashes (NSRLFile.txt, a hashdeep CSV, or a hash-per-line list)" });
      const { added, total } = await options.nsrlStore.addMany(parsed);
      logLine(`[nsrl] import — +${added} new (${parsed.length} parsed, ${total} total)`);
      return res.status(200).json({ added, parsed: parsed.length, total });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Load known-good hashes from file(s) on the SERVER's filesystem — the in-UI equivalent of
  // DFIR_NSRL_FILE, for big RDS sets you don't want to paste. Body: { path } (a file path, or several
  // `;`-separated). Best-effort per file (a bad path is reported, not fatal). Loaded hashes persist in
  // the store, so unlike the env var this is a one-shot — no restart, and it survives one. Returns
  // { added, total, files[] }. Localhost-only tool: reading a path the operator typed is intended
  // (same trust as the env var); the response carries counts + errors only, never file contents.
  app.post("/nsrl/import-file", async (req: Request, res: Response) => {
    if (!options.nsrlStore) return res.status(501).json({ error: "NSRL store not configured" });
    const paths = splitNsrlPaths(typeof req.body?.path === "string" ? req.body.path : "");
    if (paths.length === 0) return res.status(400).json({ error: "path is required (a file on the server; ; -separated for multiple)" });
    try {
      const files = await ingestNsrlFiles(options.nsrlStore, paths);
      for (const r of files) logLine(r.error ? `[nsrl] could not load ${r.file}: ${r.error}` : `[nsrl] loaded ${r.file} — +${r.added} new (${r.total} total known-good hashes)`);
      const added = files.reduce((n, r) => n + r.added, 0);
      const total = await options.nsrlStore.count();
      // All paths failed → 400 (nothing loaded), like the paste import's no-valid-hashes 400.
      const allFailed = files.every((r) => r.error);
      return res.status(allFailed ? 400 : 200).json({ added, total, files });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Wipe the set (e.g. swapping in a different RDS release).
  app.post("/nsrl/clear", async (_req: Request, res: Response) => {
    if (!options.nsrlStore) return res.status(501).json({ error: "NSRL store not configured" });
    try {
      await options.nsrlStore.clear();
      return res.status(200).json({ cleared: true, count: 0 });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Export the set as a newline-delimited hash list for backup / sharing.
  app.get("/nsrl/export", async (_req: Request, res: Response) => {
    if (!options.nsrlStore) return res.status(501).json({ error: "NSRL store not configured" });
    try {
      res.setHeader("Content-Type", "text/plain");
      res.setHeader("Content-Disposition", 'attachment; filename="nsrl-known-hashes.txt"');
      return res.status(200).send(await options.nsrlStore.exportText());
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Apply the NSRL set to THIS case now (the analyst just loaded a set, or wants to sweep an
  // already-imported case). Marks matches legitimate, then re-synthesizes so they drop from findings.
  app.post("/cases/:id/nsrl/apply", async (req: Request, res: Response) => {
    if (!options.nsrlStore && !ctx.nsrlDb()) return res.status(501).json({ error: "NSRL not configured (no hash set or RDS database)" });
    if (!options.stateStore) return res.status(501).json({ error: "state store not configured" });
    const caseId = req.params.id;
    try {
      const result = await ctx.applyNsrlToCase(caseId);
      if (result.added > 0) ctx.resynthesizeInBackground(caseId);
      logLine(`[nsrl] ${caseId} apply — matched ${result.matchedIocs} IOC(s) + ${result.matchedEvents} event(s), added ${result.added}`);
      return res.status(200).json({ ...result, legitimate: await falsePositives.load(caseId) });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // CISA KEV catalog routes (issue #99). The catalog is global (like NSRL/whitelist).
  // GET /kev — stats for the Settings → KEV panel.
  // POST /kev/import-url — fetch the CISA feed from a URL (body: { url }).
  // POST /kev/import-file — load the feed from a server-side file path (body: { path }).
  // DELETE /kev — wipe the catalog.
  app.get("/kev", async (_req: Request, res: Response) => {
    if (!options.kevStore) return res.status(200).json({ count: 0, enabled: false });
    try {
      const m = await options.kevStore.meta();
      return res.status(200).json({ ...m, enabled: m.count > 0 });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Fetch the CISA KEV feed from a URL and ingest it. Body: { url? } (defaults to the CISA feed).
  // Passes the raw JSON through so meta() can read catalogVersion/dateReleased.
  app.post("/kev/import-url", async (req: Request, res: Response) => {
    if (!options.kevStore) return res.status(501).json({ error: "KEV store not configured" });
    const CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
    const url = typeof req.body?.url === "string" && req.body.url.trim() ? req.body.url.trim() : CISA_KEV_URL;
    try {
      const resp = await fetch(url, { signal: AbortSignal.timeout(30_000) });
      if (!resp.ok) return res.status(502).json({ error: `fetch failed: HTTP ${resp.status}` });
      const json: unknown = await resp.json();
      const { total } = await options.kevStore.ingestRaw(json);
      if (options.pipeline) options.pipeline.invalidateKevCache();
      logLine(`[kev] imported ${total} entries from ${url}`);
      return res.status(200).json({ total, source: url });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Load the CISA KEV feed JSON from a file on the server filesystem. Body: { path }.
  // Localhost-only tool: reading an operator-specified path is intentional (like NSRL import-file).
  app.post("/kev/import-file", async (req: Request, res: Response) => {
    if (!options.kevStore) return res.status(501).json({ error: "KEV store not configured" });
    const path = typeof req.body?.path === "string" ? req.body.path.trim() : "";
    if (!path) return res.status(400).json({ error: "path is required (a local copy of the CISA KEV JSON)" });
    try {
      const raw = JSON.parse(await readFile(path, "utf8")) as unknown;
      const { total } = await options.kevStore.ingestRaw(raw);
      if (options.pipeline) options.pipeline.invalidateKevCache();
      logLine(`[kev] loaded ${total} entries from file ${path}`);
      return res.status(200).json({ total, source: path });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Wipe the KEV catalog.
  app.delete("/kev", async (_req: Request, res: Response) => {
    if (!options.kevStore) return res.status(501).json({ error: "KEV store not configured" });
    try {
      await options.kevStore.clear();
      if (options.pipeline) options.pipeline.invalidateKevCache();
      logLine(`[kev] catalog cleared`);
      return res.status(200).json({ cleared: true, count: 0 });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Threat-intel enrichment toggle (per case, default OFF for OPSEC). GET reads the
  // current state. POST { enabled } turns it on/off; turning it ON enriches the current
  // IOCs immediately AND auto-enriches any IOCs added later (imports/synthesis).
  // ⚠ Enrichment sends indicators to third-party services (VirusTotal/MalwareBazaar/
  // AbuseIPDB) — that's why it is off until the analyst opts in.
  app.get("/cases/:id/enrich-control", async (req: Request, res: Response) => {
    try {
      const configuredSet = new Set(configuredNames);
      const enabled = new Set(resolveEnabledProviders(await enrichControl.load(req.params.id), configuredNames, localNames));
      return res.status(200).json({
        anyConfigured: allProviders.length > 0,
        // All known providers with scope, configured flag (key present) and enabled flag (on for this case).
        // Configured providers are listed first within each scope group.
        providers: [
          ...ALL_KNOWN_PROVIDERS.filter((p) => configuredSet.has(p.name)),
          ...ALL_KNOWN_PROVIDERS.filter((p) => !configuredSet.has(p.name)),
        ].map((p) => ({
          name: p.name,
          scope: p.scope,
          keyHint: p.keyHint,
          configured: configuredSet.has(p.name),
          enabled: enabled.has(p.name),
        })),
      });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Reachability of the configured providers (for the dashboard's ●up/down dots). Probes each
  // one (cached ~60s, so opening the modal repeatedly is cheap) and reports its last verdict.
  // Providers without a probe() (external SaaS) report ok:true (no health endpoint to test).
  app.get("/enrich-health", async (_req: Request, res: Response) => {
    try {
      const enrichHealth = ctx.enrichHealth();
      const health = await Promise.all(allProviders.map(async (p) => {
        const h = p.probe ? await enrichHealth.check(p) : { ok: true, checkedAt: 0 };
        return { name: p.name, scope: p.scope, probed: Boolean(p.probe), ok: h.ok, detail: h.detail };
      }));
      return res.status(200).json({ providers: health });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Set which providers are enabled for this case. Accepts `{ providers: string[] }`
  // (preferred) or legacy `{ enabled: boolean }`. Saving re-runs enrichment; per-provider
  // caching means only the newly-enabled providers query the existing IOCs.
  app.post("/cases/:id/enrich-control", async (req: Request, res: Response) => {
    if (allProviders.length === 0) return res.status(501).json({ error: "no enrichment providers configured (set DFIR_VT_KEY / DFIR_MB_KEY / DFIR_HUNTINGCH_KEY / DFIR_ABUSEIPDB_KEY / DFIR_CROWDSTRIKE_CLIENT_ID+_SECRET / DFIR_MISP_* / DFIR_YETI_*)" });
    if (!options.stateStore) return res.status(501).json({ error: "state store not configured" });
    const caseId = req.params.id;
    let providers: string[];
    if (Array.isArray(req.body?.providers)) providers = req.body.providers.map(String).filter((n: string) => configuredNames.includes(n));
    else if (typeof req.body?.enabled === "boolean") providers = req.body.enabled ? [...configuredNames] : [];
    else return res.status(400).json({ error: "providers (array of provider names) or enabled (boolean) is required" });
    try {
      await enrichControl.save(caseId, { providers });
      if (providers.length > 0) ctx.enrichInBackground(caseId);   // re-check; cache only queries newly-enabled / un-checked
      else ctx.enrichPending().delete(caseId);                    // disabled — stop the poller from waiting on a down provider for this case
      logActivity(options.activityLogStore, options.onActivity, caseId, {
        category: "enrichment", action: "enrich-control",
        detail: providers.length ? `enrichment enabled: ${providers.join(", ")}` : "enrichment disabled (no providers)",
      });
      return res.status(200).json({ providers });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Manual one-shot re-scan (e.g. force re-query). Honors the same providers; does NOT
  // change the toggle. `{ force: true }` re-queries already-enriched IOCs.
  app.post("/cases/:id/enrich", async (req: Request, res: Response) => {
    const providers = options.enrichmentProviders ?? [];
    if (providers.length === 0) return res.status(501).json({ error: "no enrichment providers configured (set DFIR_VT_KEY / DFIR_MB_KEY / DFIR_HUNTINGCH_KEY / DFIR_ABUSEIPDB_KEY / DFIR_CROWDSTRIKE_CLIENT_ID+_SECRET)" });
    if (!options.stateStore) return res.status(501).json({ error: "state store not configured" });
    const caseId = req.params.id;
    const force = req.body?.force === true || req.query.force === "true";
    try {
      const enabledProviders = await ctx.enabledProvidersFor(caseId);
      if (enabledProviders.length === 0) return res.status(422).json({ error: "no enrichment providers enabled for this case — enable providers in the enrichment panel first" });
      const state = await options.stateStore.load(caseId);
      ctx.enrichInBackground(caseId, force);
      return res.status(202).json({ accepted: true, iocs: state.iocs.length, providers: enabledProviders.map((p) => p.name) });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });
}
