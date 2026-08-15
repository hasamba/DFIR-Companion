// Hand-written types for the eight public/js/dashboard-*.js helper modules (#415).
//
// Those files are plain JS with no .d.ts, so these are a CLAIM about their surface rather than a
// derivation from it. Two things keep the claim honest:
//
//   - tests/dashboard/dashboardModules.test.ts asserts at runtime that every function each module
//     declares is published, and that every one of the 95 moved names resolves as a global. A
//     signature here for a function that no longer exists fails there, not silently.
//   - the suites that use these interfaces call the functions for real, so a wrong parameter or
//     return shape shows up as a failing assertion rather than a passing cast.
//
// THE SIGNATURES ARE AS PERMISSIVE AS THE JAVASCRIPT REALLY IS, on purpose. `unknown` where a
// helper does `String(x)` on its argument, `| null` where it guards for absence. Tightening them
// past what the code accepts would make the edge cases these suites exist to pin —
// `activityTimeAgo(null)`, `truncate(12345, 3)`, `toolForExt(".evtx", {})` — fail to compile,
// which would be the types lying about the code under test. Where a function is genuinely
// polymorphic the parameter is `unknown` and the test narrows.
//
// This replaced a `Record<string, any>` in the shared loader. That left all ~300 calls in these
// suites unchecked and put an eslint suppression in the one helper every dashboard test imports,
// which is how a deliberately small, fully-enforced rule set erodes.

/** Membership, and nothing else. What a filter helper needs and all it should be given. */
export interface HasOnly {
  has(value: string): boolean;
}

/** A timeline event, as much of one as the helpers actually read. */
export interface EventLike {
  timestamp?: string | null;
  description?: string | null;
  asset?: string | null;
  severity?: string;
  sources?: Array<string | null | undefined> | null;
  mitreTechniques?: string[];
  artifactName?: string;
  relatedFindingIds?: string[];
  sha256?: string;
  md5?: string;
  path?: string;
  processName?: string;
  parentName?: string;
  chainSignature?: string;
}

export interface IocLike {
  id?: string;
  type?: string;
  value?: string;
  enrichments?: Array<{
    source?: string;
    verdict?: string;
    score?: string;
    tags?: string[];
    link?: string;
  }>;
}

export interface FindingLike {
  id?: string | null;
  title?: string | null;
  description?: string | null;
  mitreTechniques?: string[];
}

/** A false-positive mark, whose five text fields are all searched. */
export interface FpMarkLike {
  kind?: string;
  ref?: string;
  label?: string;
  reason?: string;
  note?: string;
}

export interface EscapeApi {
  esc(s: unknown): string;
  escAttr(s: unknown): string;
}

export interface TimeApi {
  isoToUtcInput(iso: string | null | undefined): string;
  utcInputToIso(v: string | null | undefined): string | null;
  lgAgo(iso: string | null | undefined): string;
  veloClientsAge(updatedAt: string | null | undefined): string;
  veloMonAge(iso: string | null | undefined): string;
  relTime(iso: string | null | undefined): string;
  fmtTime(iso: string): string;
  mcpJobDuration(ms: number): string;
  activityTimeAgo(iso: string | null | undefined): string;
  cockpitAge(value: string | null | undefined): string;
  skewOffsetLabel(ms: number): string;
}

export interface TextApi {
  parseRows(text: string, keys: string[]): Array<Record<string, string>>;
  rowsToText(arr: Array<Record<string, string>> | null, keys: string[]): string;
  linesToArray(text: string): string[];
  /** `String(s)` first, so anything goes in. */
  truncate(s: unknown, n: number): string;
  splitEventTitle(desc: string): { title: string; rest: string };
  huntRefang(s: unknown): string;
  egShortHost(v: unknown): string;
  mdToHtml(src: string | null | undefined): string;
  custodyGroupByArtifact<T extends { artifactPath: string }>(records: T[]): Map<string, T[]>;
  clientCommandShape(text: unknown): string;
  clientPatternKey(e: EventLike): string;
  buildClientPrevalence(events: EventLike[] | null): Map<string, { count: number; hosts: Set<string> }>;
  arrayBufferToBase64(buffer: ArrayBufferLike): string;
}

export interface GlyphsApi {
  gearPath(cx: number, cy: number, R: number, r: number, teeth: number): string;
  assetIcon(type: string, cx: number, cy: number, color: string): string;
  legendIcon(type: string): string;
  glyphDataUri(innerSvg: string, size?: number): string;
  evSevColor(sev: string | undefined): string;
  evNodeGlyph(n: { kind?: string; maxSeverity?: string }, x: number, y: number, color: string | null): string;
  tagColor(label: string): string;
  geoSevColor(sev: string | undefined): string;
}

export interface FiltersApi {
  // A HAS-ONLY SHAPE, not Set. The function only ever calls `hidden.has(s)`, and callers hand it
  // DfirFacets.<facet>.matcher() — a frozen read-only view. Typing it as Set forced an
  // `as unknown as Set<string>` at the call site, which is a cast covering for a wrong signature.
  realSourceCount(sources: Array<string | null | undefined> | null, hidden?: HasOnly): number;
  _evMatchesSearch(e: EventLike, q: string): boolean;
  _iocMatchesSearch(i: IocLike, q: string): boolean;
  _findingMatchesSearch(f: FindingLike, q: string): boolean;
  _evMatchesExclude(e: EventLike, terms: Array<string | null | undefined>): boolean;
  _iocMatchesExclude(i: IocLike, terms: Array<string | null | undefined>): boolean;
  _findingMatchesExclude(f: FindingLike, terms: Array<string | null | undefined>): boolean;
  _fpMatchesSearch(m: FpMarkLike, q: string): boolean;
  _fpMatchesExclude(m: FpMarkLike, terms: Array<string | null | undefined>): boolean;
  _evMatchesTimeRange(e: EventLike, from: string | null, to: string | null): boolean;
  isFindingFalsePositive(title: string | null, fpTitles: string[]): boolean;
  isAutoBackfillFinding(f: FindingLike | null): boolean;
  isGapFinding(f: FindingLike | null): boolean;
  findingPassesOriginLens(f: FindingLike | null, hideAuto: boolean, hideGap: boolean): boolean;
  ftOriginOf(e: EventLike): string;
  originFacets(ft: EventLike[] | null): string[];
  isLowSignalEvent(e: EventLike): boolean;
  lowSignalChip(e: EventLike): string;
}

export interface IocApi {
  verdictColor(v: string | undefined): string;
  attackUrl(id: string | null): string | null;
  mitreLinks(ids: string[] | null): string;
  /** `undefined` for an IOC that was never enriched — not "unknown". */
  worstIocVerdict(ioc: IocLike): string | undefined;
  scoreCoversTag(score: string, tag: string | null): boolean;
  enrichBadges(ioc: IocLike): string;
  iocFlagged(i: IocLike): boolean;
  dedupeIocsById(iocs: IocLike[]): IocLike[];
  sortIocsForDisplay(iocs: IocLike[]): IocLike[];
}

/** The two element shapes the value helpers read off a node they are handed. */
export interface ElementLike {
  dataset?: Record<string, string | undefined>;
  getClientRects?(): unknown[];
  hasAttribute?(name: string): boolean;
  querySelector?(sel: string): unknown;
}

export interface JobView {
  job: { id?: string; kind: string; label?: string; status: string };
  cancel?: boolean;
  resume?: boolean;
  detail: string;
}

export interface ValuesApi {
  _workflowInitials(name: string): string;
  pbLocalStats(tasks: Array<{ status: string }>): { total: number; done: number; completionPct: number };
  ticketLabel(target: string | undefined): string;
  veloTimeScopeBody(form: ElementLike): { preset?: string; start?: string; end?: string } | undefined;
  veloTimeScopeIncomplete(form: ElementLike): boolean;
  toolForExt(ext: string, status: unknown): string | null;
  suggestToolForExt(ext: string, status: unknown): string | null;
  toolsForExt(ext: string, status: unknown): Array<{ id: string }>;
  jobMenuView(j: Record<string, unknown>): JobView;
  updateJobRow(row: ElementLike, view: JobView): void;
  deepPassResultKey(cid: string): string;
  swCanvasXY(
    e: { clientX: number; clientY: number },
    canvas: {
      width: number;
      height: number;
      getBoundingClientRect(): { left: number; top: number; width: number; height: number };
    },
  ): { x: number; y: number };
  eventDeepLink(caseId: string, id: string): string;
  rvStatusLabel(workflow: { status?: string } | undefined): string;
  analysisRunLabel(run: {
    kind: string;
    configuration?: { provider?: string; model?: string };
    startedAt: string;
  }): string;
  fileToBase64(file: unknown): Promise<string>;
  paletteVisible(el: ElementLike | null): boolean;
  paletteSectionKeywords(label: string): string[];
  isSectionDataOpen(el: ElementLike): boolean;
  stabHidden(btn: ElementLike, mode: string): boolean;
  wizFieldId(envKey: string): string;
  /**
   * The blanked-credential body the settings pane PUTs back. Spelled out rather than
   * `Record<string, unknown>` because the point of the function is which credential fields it
   * empties, and the tests assert on exactly those.
   */
  ntfChannelToBody(ch: Record<string, unknown>): {
    type?: string;
    name?: string;
    enabled?: boolean;
    minSeverity?: string;
    events?: unknown;
    smtp?: {
      host?: string;
      port?: number;
      secure?: boolean;
      from?: string;
      to?: string[];
      username?: string;
      password?: string;
      rejectUnauthorized?: boolean;
    };
    telegram?: { botToken: string; chatId?: string };
    webhookUrl?: string;
  };
  ntfChatPrefill(chats?: Array<{ chatId: string; caseId?: string }>): {
    value: string;
    options: Array<{ value: string; label: string }>;
  };
  ntfEventsSummary(ev: Record<string, boolean | undefined>): string;
}

export interface FragmentsApi {
  mentionHtml(text: string): string;
  ticketPushChips(id: string): string;
  renderVqlRows(j: { rows?: unknown[]; total?: number; truncated?: boolean }): string;
  askStatusBadge(s: string | undefined): string;
  jobRowHtml(view: JobView): string;
  qaSpan(type: string, val: string, ctx?: { evid?: unknown; iocid?: unknown }): string;
  citeFindings(ids: Array<string | null> | null): string;
  complianceDueBadge(deadline: { status?: string; remainingDays?: number; dueAt?: string } | null): string;
  ceChip(value: string, kind: string, auto: boolean): string;
  evidenceLinks(caseId: string, files: Array<string | null> | null): string;
  cockpitCardControls(card: Record<string, unknown>, parked: boolean): string;
  cockpitCardHtml(card: Record<string, unknown>, parked: boolean): string;
  rvAnnotationRows(
    workflow: { versionId?: string; annotations?: Array<Record<string, unknown>> } | undefined,
  ): string;
  wizRenderFields(fields: Array<{ key: string; label: string; hint?: string; secret?: boolean }>): string;
  caseStatsBarChart(days: Array<{ date: string; imports: number; rows: number }>): string;
  ntfTargetSummary(ch: Record<string, unknown>): string;
}

/** A cell as js/dashboard-state.js publishes it. */
export interface Cell<T> {
  get(): T;
  set(next: T): T;
  subscribe(fn: (value: T) => void): () => void;
}

/** Whatever the server last said. Deliberately loose — the tests care about identity, not shape. */
export type Snapshot = Record<string, unknown> | null;

export interface StateApi {
  DfirState: {
    cell<T>(initial?: T): Cell<T>;
    activeView(): { id?: string; name?: string } | null;
    setActiveView(view: unknown): { id?: string; name?: string } | null;
    onActiveViewChange(fn: (view: unknown) => void): () => void;

    // Tier 1, the case snapshot. One writer each: render() for the first two,
    // renderSuperTimeline() for the third.
    lastState(): Snapshot;
    setLastState(state: Snapshot): Snapshot;
    onLastStateChange(fn: (state: Snapshot) => void): () => void;

    lastFt(): unknown[];
    setLastFt(ft: unknown[]): unknown[];
    onLastFtChange(fn: (ft: unknown[]) => void): () => void;

    lastSuperData(): Snapshot;
    setLastSuperData(data: Snapshot): Snapshot;
    onLastSuperDataChange(fn: (data: Snapshot) => void): () => void;
  };
}

/**
 * One owned set of ids (public/js/dashboard-selection.js).
 *
 * Note the absence of anything returning a Set. Every read is a copy or a scalar, which is the
 * whole point: replace-on-write is only enforceable if the container never leaves the owner.
 */
export interface IdSet {
  has(id: string): boolean;
  count(): number;
  /** A frozen COPY, fresh each call. */
  ids(): readonly string[];
  /** `on` omitted flips, like classList.toggle. Returns the new size. */
  toggle(id: string, on?: boolean): number;
  // All three guard with `ids || []`, so the parameter is optional and nullable here to match.
  // Tightening it would make the "tolerates an empty or absent batch" case fail to compile, which
  // is the type lying about the code rather than checking it.
  /** Union in a batch — select-all, the rubber band. ONE commit. */
  addAll(ids?: Iterable<string> | null): number;
  removeAll(ids?: Iterable<string> | null): number;
  replace(ids?: Iterable<string> | null): number;
  clear(): number;
}

/**
 * A selection cannot be replaced wholesale — see js/dashboard-selection.js. Select-all ticks the
 * rendered rows, so an operation that drops the rest would silently lose off-page ticks, and no
 * caller wants one.
 */
export type SelectionSet = Omit<IdSet, "replace">;

export interface SelectionApi {
  DfirSelection: { events: SelectionSet; iocs: SelectionSet; findings: SelectionSet };
  /** Starred is a CACHE of server tags, not view state, so it is a separate owner. */
  DfirStarred: Pick<IdSet, "has" | "count" | "ids" | "toggle" | "replace">;
}

/**
 * public/js/dashboard-timeline-view.js — the timeline's view filters, as ACTIONS.
 *
 * The reads are scalars and membership tests; no Set or array the caller can write ever comes out.
 * The actions each declare their own refresh set, which is why there is no generic setter and no
 * subscription — see the module header.
 */
export interface TimelineViewApi {
  DfirTimelineView: {
    wire(handlers: Record<string, () => void>): void;
    hydrate(state?: { excludeTerms?: string[]; corroboration?: Record<string, number> }): void;

    search(): string;
    excludeTerms(): readonly string[];
    from(): string | null;
    to(): string | null;
    starredOnly(): boolean;
    hasEventId(id: unknown): boolean;
    eventIdFilterActive(): boolean;
    eventIdCount(): number;
    eventIdLabel(): string;
    corrobTimeline(): number;
    corrobIocs(): number;
    corrobFindings(): number;

    setSearch(term: unknown): void;
    setExcludeTerms(terms?: Iterable<string> | null): void;
    setTimeWindow(from: string | null, to: string | null): void;
    showOnlyStarred(on: boolean): void;
    setCorroboration(which: string, value: unknown): number;
    filterToEventIds(ids?: Iterable<unknown> | null, label?: string): number;
    clearEventIds(): void;
    clearFilters(): void;
    resetForCase(): void;
  };
}

/**
 * One facet filter (public/js/dashboard-facets.js): the names the analyst UNCHECKED.
 *
 * `has` rather than `isHidden` on purpose — realSourceCount(sources, hidden) needs an object with
 * `.has()`, so the owner itself can be that argument without a Set escaping.
 */
export interface Facet {
  has(name: string): boolean;
  /**
   * The derived `hidden ∩ available` count — the ONLY "how many" read.
   *
   * There is deliberately no `any()`. One existed as a cheap guard and review found it driving the
   * timeline's "N of M events" label, where a facet hidden in a previous import made the dashboard
   * claim it was filtering when it was not.
   */
  countIn(available?: Iterable<string> | null): number;
  /** A frozen `{ has }` view, for helpers that only need membership. The owner is never passed. */
  matcher(): HasOnly;
  toggle(name: string, hidden?: boolean): number;
  hideAll(names?: Iterable<string> | null): number;
  showAll(): number;
}

export interface FacetsApi {
  DfirFacets: { sources: Facet; origins: Facet; hosts: Facet; iocTypes: Facet };
}

/** An investigation window. Mirrors the server's ScopeWindow (src/analysis/scope.ts). */
export interface ScopeWindow {
  start: string | null;
  end: string | null;
}

/**
 * public/js/dashboard-scope.js — tier 2's first owner (#415).
 *
 * Note what is NOT here: there is no `set`, and no `onScopeChange`. The three call sites that write
 * this window want three different refreshes, so the module publishes the two COMMIT shapes they
 * actually differ by — `receive` (the server told us; push into the controls) and `confirm` (the
 * analyst typed it; leave the controls alone) — and leaves the redraw at the call site. A generic
 * setter plus a subscriber would have to be the union of the three, which is the behaviour change
 * this design exists to avoid. If a `set` or an `onScopeChange` ever appears here, that is the
 * design being lost, not extended.
 */
export interface ScopeApi {
  DfirScope: {
    get(): Readonly<ScopeWindow>;
    isEmpty(): boolean;
    contains(ts: unknown): boolean;
    /** The client-side mirror of the server's projectScope(). Same object back when no window is set. */
    project<T>(state: T): T;
    receive(start: unknown, end: unknown): void;
    confirm(start: unknown, end: unknown): void;
  };
}
