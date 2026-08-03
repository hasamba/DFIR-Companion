/**
 * The maintenance timers a real server run arms at startup: automatic state backup, and periodic
 * evidence re-verification. Lifted out of startServer by #416.
 *
 * THEY REUSE A PATTERN, NOT A CONCERN. The integrity sweep is scheduled beside the backup timer
 * rather than inside BackupManager on purpose: state backups and custody verification are unrelated,
 * and folding one into the other would only couple them. What they share is the shape — an interval,
 * `.unref()`d so it never blocks process exit, doing best-effort work that must never throw into
 * the request path.
 *
 * Both are OPT-OUT by interval: a zero interval arms nothing, which is what createApp-only tests and
 * the scripts/* pipelines get, since they never call this.
 */
import { join } from "node:path";
import { stat } from "node:fs/promises";
import type { CaseStore } from "../storage/caseStore.js";
import { BackupManager, resolveBackupConfig } from "../storage/backupManager.js";
import { EvidenceIntegrityMonitor, resolveIntegrityConfig } from "../analysis/custodyIntegrity.js";
import type { CustodyStore } from "../analysis/custody.js";
import { milestoneEvent } from "../analysis/notifications.js";
import type { Notifier } from "../integrations/notify/notifyDispatch.js";
import { logLine, warnLine } from "../logging/serverLogger.js";
import { seedDemoCase } from "../analysis/seedDemoCase.js";
import { resolveUpdateMode, UPDATE_CHECK_THROTTLE_MS } from "../analysis/updateCheck.js";
import { performUpdateCheck } from "../analysis/updateCheckRun.js";
import type { UpdateCheckStore } from "../analysis/updateCheckStore.js";
import type { VelociraptorClient } from "../integrations/velociraptor/velociraptorApi.js";
import type { VelociraptorClientStore } from "../analysis/velociraptorClientStore.js";

/**
 * Delay before the FIRST evidence-integrity sweep after boot. Long enough to stay out of the startup
 * path (re-hashing every artifact must not sit in it), short enough that Diagnostics reports a real
 * answer rather than "not verified yet" for a whole interval (#231).
 */
const INITIAL_INTEGRITY_SWEEP_DELAY_MS = 60_000;

export interface MaintenanceDeps {
  store: CaseStore;
  custodyStore: CustodyStore;
  notifier: Notifier;
  /** Used to deep-link an integrity alert back to the affected case. */
  dashboardBaseUrl: string;
}

export interface MaintenanceTasks {
  backupManager: BackupManager;
  integrityMonitor: EvidenceIntegrityMonitor;
}

/** Arm both maintenance timers and hand back the two objects createApp also needs in its options. */
export function startMaintenanceTasks({
  store,
  custodyStore,
  notifier,
  dashboardBaseUrl,
}: MaintenanceDeps): MaintenanceTasks {
  // Automatic state backup (#180): snapshot SNAPSHOT_STATE_FILES before synthesis + on a timer.
  const backupConfig = resolveBackupConfig(process.env);
  const backupManager = new BackupManager(store, backupConfig);
  if (backupConfig.intervalMs > 0) {
    // Time-based: only back up cases that have changed since the last scheduled backup.
    const lastScheduledBackupAt = new Map<string, number>();
    const runScheduledBackups = async (): Promise<void> => {
      const cases = await store.listCases().catch(() => []);
      for (const c of cases) {
        const invPath = join(store.stateDir(c.caseId), "investigation.json");
        let mtime: number;
        try {
          mtime = (await stat(invPath)).mtimeMs;
        } catch {
          continue; // case has no investigation.json yet
        }
        const lastAt = lastScheduledBackupAt.get(c.caseId) ?? 0;
        if (mtime > lastAt) {
          try {
            const { prune } = await backupManager.createBackup(c.caseId, "scheduled");
            lastScheduledBackupAt.set(c.caseId, Date.now());
            // The byte cap holds everything it is allowed to delete; when the survivors are all
            // exempt (newest backup, newest pre-synthesis) it cannot be met. Say so rather than
            // silently overrunning — deleting the last recovery point would be the worse bug (#295).
            if (prune.overBudget) {
              logLine(
                `[backup] ${c.caseId} is over the ${backupConfig.maxBytes}-byte budget ` +
                  `(${prune.totalBytes} bytes in backups that cannot be pruned further)`,
              );
            }
          } catch (e) {
            logLine(`[backup] scheduled backup for ${c.caseId} failed: ${(e as Error).message}`);
          }
        }
      }
    };
    const backupTimer = setInterval(() => {
      void runScheduledBackups();
    }, backupConfig.intervalMs);
    backupTimer.unref();
    logLine(
      `[backup] automatic backups every ${backupConfig.intervalMs / 1000}s (retain ${backupConfig.retain}` +
        `${backupConfig.maxBytes > 0 ? `, max ${backupConfig.maxBytes} bytes per case` : ", no byte cap"})`,
    );
  }

  // Periodic evidence re-verification (#231 item 3). Scheduled here beside the backup timer rather
  // than inside BackupManager: it reuses that scheduling PATTERN, but state backups and custody
  // verification are unrelated concerns and folding one into the other would only couple them.
  const integrityConfig = resolveIntegrityConfig(process.env);
  const integrityMonitor = new EvidenceIntegrityMonitor(store, custodyStore, integrityConfig, (sweep) => {
    const problems = [
      sweep.failedArtifacts ? `${sweep.failedArtifacts} artifact(s) failed verification` : "",
      sweep.chainBreaks ? `${sweep.chainBreaks} custody-log chain break(s)` : "",
    ]
      .filter(Boolean)
      .join(", ");
    warnLine(
      `[custody] EVIDENCE INTEGRITY ALERT — ${problems} across ${sweep.problemCases.length} case(s): ${sweep.problemCases.map((c) => c.caseId).join(", ")}`,
    );
    // One notification per affected case, so it lands in that case's feed where an analyst will
    // see it rather than in a global channel nobody is watching. Fully guarded, like onSynth
    // below: notifications are a side channel and must never break the sweep.
    try {
      for (const problem of sweep.problemCases) {
        const url = `${dashboardBaseUrl}/dashboard?caseId=${encodeURIComponent(problem.caseId)}`;
        const event = milestoneEvent(
          problem.caseId,
          "Evidence integrity check FAILED",
          [
            `${problem.mismatches.length} artifact(s) failed verification, ${problem.chainBreaks.length} custody-log chain break(s).`,
            ...problem.mismatches.slice(0, 5).map((m) => `${m.reason}: ${m.artifactPath}`),
          ],
          sweep.finishedAt,
        );
        notifier
          .dispatch({ ...event, url })
          .catch((err) => logLine(`[notify] dispatch error: ${(err as Error).message}`));
      }
    } catch (err) {
      logLine(`[custody] integrity alert dispatch error: ${(err as Error).message}`);
    }
  });
  if (integrityConfig.intervalMs > 0) {
    const integrityTimer = setInterval(() => {
      void integrityMonitor.runSweepIfIdle();
    }, integrityConfig.intervalMs);
    integrityTimer.unref();
    // A first sweep shortly after boot, so Diagnostics reports a real answer instead of "not
    // verified yet" for a whole interval. Delayed rather than inline: re-hashing every artifact
    // must not sit in the startup path.
    const firstSweep = setTimeout(() => {
      void integrityMonitor.runSweepIfIdle();
    }, INITIAL_INTEGRITY_SWEEP_DELAY_MS);
    firstSweep.unref();
    logLine(`[custody] all-cases evidence integrity sweep every ${integrityConfig.intervalMs / 1000}s`);
  }
  if (integrityConfig.onOpenThrottleMs > 0) {
    logLine(
      `[custody] cases verified on open (re-checked after ${integrityConfig.onOpenThrottleMs / 1000}s)`,
    );
  }

  return { backupManager, integrityMonitor };
}

export interface PostListenDeps {
  store: CaseStore;
  demoMode: boolean;
  velociraptorClient?: VelociraptorClient;
  velociraptorClientStore: VelociraptorClientStore;
  updateCheckStore: UpdateCheckStore;
  updateRepo: string;
}

/**
 * The startup work that must wait until the server is listening — because it reaches OUT (to
 * Velociraptor, to GitHub) or writes a case, and neither should sit in the path that gets the port
 * bound. All three are best-effort and every timer is .unref()'d.
 */
export function startPostListenTasks({
  store,
  demoMode,
  velociraptorClient,
  velociraptorClientStore,
  updateCheckStore,
  updateRepo,
}: PostListenDeps): void {
  // Demo mode: seed the demo case immediately on startup so it's always present, then reset it
  // on a fixed interval so visitor edits don't accumulate. Best-effort — a seed failure is logged
  // but never fatal. The timer is .unref()'d so it doesn't block a clean process exit.
  if (demoMode) {
    const resetHours = Math.max(1, Number(process.env.DFIR_DEMO_RESET_HOURS) || 1);
    const seedDemo = (): void => {
      void seedDemoCase(store.casesRoot, { force: true })
        .then((r) =>
          logLine(
            `[demo] demo case seeded — ${r.stats.events} events, ${r.stats.findings} findings, ${r.stats.iocs} IOCs`,
          ),
        )
        .catch((e) => logLine(`[demo] demo case seed failed: ${(e as Error).message}`));
    };
    seedDemo();
    const t = setInterval(seedDemo, resetHours * 60 * 60 * 1000);
    t.unref();
    logLine(`[demo] demo mode active — writes blocked, case resets every ${resetHours}h`);
  }

  // Snapshot the enrolled Velociraptor fleet into the client inventory at startup (#70), so a single-
  // endpoint collection can resolve a host → client_id from the file. RETRY WITH BACKOFF: if the
  // Velociraptor server is down when the companion boots (a common ordering), keep retrying for a while
  // so the inventory self-heals once it comes up — the analyst shouldn't have to restart the companion
  // (Settings → Velociraptor → Reconnect also forces it). Best-effort; timers .unref() so they never
  // block exit. Live monitors self-heal on their own poll timers, so this only covers the inventory.
  if (velociraptorClient) {
    const backoffMs = [0, 30_000, 60_000, 120_000, 300_000, 600_000]; // ~18 min of attempts
    const attempt = (i: number): void => {
      velociraptorClient
        .listClients()
        .then((clients) => velociraptorClientStore.save(clients, new Date().toISOString()))
        .then((inv) => logLine(`[velociraptor] client inventory: ${inv.clients.length} enrolled client(s)`))
        .catch((e) => {
          const next = i + 1;
          if (next < backoffMs.length) {
            logLine(
              `[velociraptor] startup inventory refresh failed (${(e as Error).message}) — retrying in ${backoffMs[next] / 1000}s`,
            );
            const t = setTimeout(() => attempt(next), backoffMs[next]);
            t.unref?.();
          } else {
            logLine(
              `[velociraptor] startup inventory refresh still failing — use Settings → Velociraptor → Reconnect once the server is up`,
            );
          }
        });
    };
    attempt(0);
  }

  // Opt-in update check (issue #127): when enabled (and not env-locked), check GitHub at most
  // once / 24h on startup and on a daily timer. Best-effort, never blocks startup, never throws.
  void (async () => {
    const stored = (await updateCheckStore.load()).enabled;
    const mode = resolveUpdateMode(process.env.DFIR_UPDATE_CHECK, stored);
    if (!mode.enabled || mode.locked) return;
    const runIfStale = async () => {
      const prev = (await updateCheckStore.load()).result;
      if (prev && !prev.error && Date.now() - prev.checkedAt < UPDATE_CHECK_THROTTLE_MS) return;
      await performUpdateCheck({
        store: updateCheckStore,
        repo: updateRepo,
        fetchFn: fetch,
        now: Date.now(),
      });
      logLine(`[update] checked ${updateRepo} for a newer release`);
    };
    await runIfStale().catch((e) => warnLine(`[update] check failed: ${(e as Error).message}`));
    const timer = setInterval(() => {
      void runIfStale().catch(() => {});
    }, UPDATE_CHECK_THROTTLE_MS);
    timer.unref?.();
  })();
}
