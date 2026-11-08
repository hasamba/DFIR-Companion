import { DEFAULT_SETTINGS, MIN_INTERVAL_SECONDS, normalizeCompanionUrl, type Settings } from "./types.js";

/**
 * One writer for the extension settings (#2398).
 *
 * The settings live under one storage key, and the popup, the options page and the keyboard
 * shortcut each used to write the WHOLE object from a copy read earlier. Saving the options page
 * therefore put back the auto-capture state and case it had seen when it opened, undoing any Start,
 * Stop or case change made since. Storage has no transactions, so every change now goes through the
 * service worker, which applies them one at a time and changes only the fields each caller names.
 */

/** The slice of browser storage the writer needs; injected so tests can control ordering. */
export interface SettingsArea {
  get(key: string): Promise<Record<string, unknown>>;
  set(items: Record<string, unknown>): Promise<void>;
}

export interface SettingsWriteResult {
  settings: Settings;
  /** False when a compare-and-set condition no longer held, so nothing was written. */
  applied: boolean;
  /** True when this write turned capture off because no case is selected any more. */
  stoppedForNoCase: boolean;
}

export const SETTINGS_KEY = "settings";

/**
 * The stored values a compare-and-set write requires. A case-list check names the case AND the
 * companion and token it asked, so a late answer from one server cannot clear the case after the
 * analyst pointed the extension at another.
 */
export type SettingsExpectation = Partial<Pick<Settings, "caseId" | "companionUrl" | "serviceToken">>;

const EXPECTABLE: ReadonlyArray<keyof SettingsExpectation> = ["caseId", "companionUrl", "serviceToken"];

/** Keep only string expectations on the known keys; undefined when there are none or one is bad. */
export function sanitizeSettingsExpectation(raw: unknown): SettingsExpectation | undefined | null {
  if (raw === undefined) return undefined;
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return null;
  const input = raw as Record<string, unknown>;
  const out: SettingsExpectation = {};
  for (const key of EXPECTABLE) {
    if (!(key in input)) continue;
    if (typeof input[key] !== "string") return null;
    out[key] = input[key] as string;
  }
  return Object.keys(out).length ? out : null;
}

function meetsExpectation(current: Settings, expect: SettingsExpectation | undefined): boolean {
  if (!expect) return true;
  return EXPECTABLE.every((key) => expect[key] === undefined || current[key] === expect[key]);
}

function withDefaults(stored: unknown): Settings {
  const partial = stored && typeof stored === "object" ? (stored as Partial<Settings>) : {};
  return { ...DEFAULT_SETTINGS, ...partial };
}

/**
 * Keep only the fields a caller may change, typed and normalised the way the popup form is.
 * Returns undefined when the value is not an object or carries a field of the wrong type.
 */
export function sanitizeSettingsPatch(raw: unknown): Partial<Settings> | undefined {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return undefined;
  const input = raw as Record<string, unknown>;
  const patch: Partial<Settings> = {};
  const str = (key: string): string | undefined | null => {
    if (!(key in input)) return undefined;
    return typeof input[key] === "string" ? (input[key] as string) : null;
  };
  const caseId = str("caseId");
  const companionUrl = str("companionUrl");
  const serviceToken = str("serviceToken");
  if (caseId === null || companionUrl === null || serviceToken === null) return undefined;
  if (caseId !== undefined) patch.caseId = caseId.trim();
  if (companionUrl !== undefined) patch.companionUrl = normalizeCompanionUrl(companionUrl);
  if (serviceToken !== undefined) patch.serviceToken = serviceToken.trim();
  if ("intervalSeconds" in input) {
    const n = Number(input.intervalSeconds);
    if (!Number.isFinite(n) || n <= 0) return undefined;
    patch.intervalSeconds = Math.max(MIN_INTERVAL_SECONDS, n);
  }
  if ("running" in input) {
    if (typeof input.running !== "boolean") return undefined;
    patch.running = input.running;
  }
  return patch;
}

/**
 * Apply a patch over the stored settings. Capture is never left ON with no case: a write that
 * would do so turns it off and says so, rather than keeping a recording icon that captures nothing.
 */
export function mergeSettingsPatch(
  stored: unknown,
  patch: Partial<Settings>,
): { settings: Settings; stoppedForNoCase: boolean } {
  const merged = { ...withDefaults(stored), ...patch };
  if (merged.running && !merged.caseId.trim()) {
    return { settings: { ...merged, running: false }, stoppedForNoCase: true };
  }
  return { settings: merged, stoppedForNoCase: false };
}

/** Runs async jobs one after another; a failed job never blocks the ones behind it. */
export class SerialQueue {
  private tail: Promise<unknown> = Promise.resolve();

  run<T>(job: () => Promise<T>): Promise<T> {
    const next = this.tail.then(job, job);
    this.tail = next.catch(() => undefined);
    return next;
  }
}

/** A change computed from the settings current at the moment it runs, or undefined for none. */
export type SettingsTransaction = (current: Settings) => Promise<Partial<Settings> | undefined>;

export class SettingsWriter {
  private readonly queue = new SerialQueue();

  constructor(private readonly area: SettingsArea) {}

  async read(): Promise<Settings> {
    const stored = await this.area.get(SETTINGS_KEY);
    return withDefaults(stored[SETTINGS_KEY]);
  }

  /**
   * Change only the named fields. With `expect`, the write happens only while every named stored
   * value still matches — a case-list check that finished late must not clear a case picked since,
   * or one that is valid on the companion the analyst switched to.
   */
  update(patch: Partial<Settings>, expect?: SettingsExpectation): Promise<SettingsWriteResult> {
    return this.transact(async (current) => (meetsExpectation(current, expect) ? patch : undefined));
  }

  /** Read, decide and write as one step, ordered against every other change. */
  transact(change: SettingsTransaction): Promise<SettingsWriteResult> {
    return this.queue.run(async () => {
      const stored = (await this.area.get(SETTINGS_KEY))[SETTINGS_KEY];
      const current = withDefaults(stored);
      const patch = await change(current);
      if (!patch) return { settings: current, applied: false, stoppedForNoCase: false };
      const { settings, stoppedForNoCase } = mergeSettingsPatch(stored, patch);
      await this.area.set({ [SETTINGS_KEY]: settings });
      return { settings, applied: true, stoppedForNoCase };
    });
  }
}

/**
 * Keeps the capture timer, toolbar icon and badge in line with the stored settings. Each pass
 * reads the settings when it runs, and passes run one at a time, so an older "running" pass can
 * never repaint the icon after a newer "stopped" one.
 */
export class SettingsReconciler {
  private readonly queue = new SerialQueue();
  private runningChangePending = false;

  constructor(
    private readonly readSettings: () => Promise<Settings>,
    private readonly apply: (settings: Settings, runningChanged: boolean) => Promise<void>,
    private readonly onError: (error: unknown) => void = () => undefined,
  ) {}

  request(runningChanged = false): Promise<void> {
    if (runningChanged) this.runningChangePending = true;
    return this.queue.run(async () => {
      const flip = this.runningChangePending;
      this.runningChangePending = false;
      try {
        await this.apply(await this.readSettings(), flip);
      } catch (error) {
        this.onError(error);
      }
    });
  }
}

/** True when a storage change touched the settings in a way the timer or icon must follow. */
export function settingsChangeNeedsReconcile(
  change: { oldValue?: unknown; newValue?: unknown } | undefined,
): { reconcile: boolean; runningChanged: boolean } {
  if (!change) return { reconcile: false, runningChanged: false };
  const before = withDefaults(change.oldValue);
  const after = withDefaults(change.newValue);
  const runningChanged = before.running !== after.running;
  const reconcile = runningChanged || before.intervalSeconds !== after.intervalSeconds || !change.oldValue;
  return { reconcile, runningChanged };
}

/** A settings change may only come from an extension page, never from a content script. */
export function isExtensionPageSender(senderUrl: string | undefined, extensionBaseUrl: string): boolean {
  return typeof senderUrl === "string" && senderUrl.startsWith(extensionBaseUrl);
}
