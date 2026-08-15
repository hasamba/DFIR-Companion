// Case-load progress — the arithmetic and labelling behind the loading overlay's bar and the
// panel strip that outlives it.
//
// Loaded in the browser as an ES module (<script type="module" src="/js/case-load-progress.js">),
// the same arrangement command-palette.js uses. The pure half below is exported by name so Vitest
// can drive it in node, where there is no DOM — see companion/tests/analysis/caseLoadProgress.test.ts.
//
// THE RULE THIS FILE EXISTS TO ENFORCE: never display a number that nothing actually measured.
// The old overlay spun a CSS animation that knew nothing and then claimed "Still loading" on a
// 15-second timer whether or not anything was stuck. Of the phases in a case load, exactly one —
// the JSON download — yields a true fraction (Content-Length; the server sets no compression
// middleware, so it is present). Server think time, JSON.parse and render() yield nothing. So the
// bar fills to the floor of the last COMPLETED stage, which is a claim the code can defend, and the
// pending segment shimmers instead of creeping. A shimmer says "working, no estimate available";
// a creeping fill would say "I know how far along this is", which would be a lie.
//
// Stages are weighted EQUALLY on purpose. Time-proportional weights were considered and rejected:
// a weight is a guess about duration, and a bar whose position encodes a guess is the thing this
// module exists to remove. Equal weights make the bar mean "3 of 5 stages done", which is true.

/**
 * The phases the overlay is up for, in order.
 *
 * The lock-status fetch is deliberately absent. It happens in connect(), BEFORE proceedConnect()
 * shows the overlay, so a stage for it would always be complete by the time the bar first paints —
 * padding the bar with progress the analyst never waited for.
 *
 * `lifecycle` (the /cases fetch) is listed last but actually runs in parallel from the start. That
 * is why progress counts a contiguous PREFIX rather than a total: an early lifecycle finish must
 * not claim progress through stages that have not happened. See prefixCount().
 */
export const LOAD_STAGES = ["query", "download", "parse", "render", "lifecycle"];

const BYTES_PER_MB = 1024 * 1024;

/** Fresh tracker for one case-load generation. */
export function createLoadState() {
  return { done: new Set(), loaded: 0, total: 0, eventCount: null, high: 0 };
}

/**
 * Mark a stage complete. Unknown, duplicate and out-of-order ids are no-ops rather than throws —
 * a progress bar must never be able to break a case load.
 */
export function advanceStage(state, stageId) {
  if (!state || !LOAD_STAGES.includes(stageId)) return;
  state.done.add(stageId);
}

/**
 * Record download progress. A total that is zero, negative or non-finite means the response carried
 * no usable Content-Length (a proxy chunking it, typically) — the download stage then shimmers like
 * the others rather than inventing a denominator.
 */
export function setDownloadBytes(state, loaded, total) {
  if (!state) return;
  state.total = Number.isFinite(total) && total > 0 ? total : 0;
  state.loaded = Number.isFinite(loaded) && loaded > 0 ? loaded : 0;
}

/** The parsed payload's forensicTimelineTotal — the real figure behind the render stage's label. */
export function setEventCount(state, n) {
  if (!state) return;
  state.eventCount = Number.isFinite(n) && n >= 0 ? Math.floor(n) : null;
}

// How many leading stages are complete. A gap stops the count: `lifecycle` done with `query` still
// running reads as zero, not one.
function prefixCount(state) {
  let n = 0;
  for (const stage of LOAD_STAGES) {
    if (!state.done.has(stage)) break;
    n++;
  }
  return n;
}

function formatBytes(b) {
  if (!Number.isFinite(b) || b < 0) return "";
  if (b >= BYTES_PER_MB) return (b / BYTES_PER_MB).toFixed(1) + " MB";
  if (b >= 1024) return Math.round(b / 1024) + " KB";
  return Math.round(b) + " B";
}

// Grouped by hand rather than via toLocaleString so the label is identical in every locale and in
// the tests that assert it.
function formatCount(n) {
  return String(Math.round(n)).replace(/\B(?=(\d{3})+(?!\d))/g, ",");
}

function labelFor(stage, state) {
  const hasTotal = state.total > 0;
  switch (stage) {
    case "query":
      return "Querying case database…";
    case "download":
      return hasTotal
        ? `Downloading ${formatBytes(state.loaded)} of ${formatBytes(state.total)}`
        : "Downloading…";
    // Bytes, not events: nothing has parsed yet, so an event count here would be a guess. The
    // render stage below can name the true count precisely because parse has finished by then.
    case "parse":
      return hasTotal ? `Parsing ${formatBytes(state.total)}…` : "Parsing…";
    case "render":
      return state.eventCount === null
        ? "Rendering…"
        : `Rendering ${formatCount(state.eventCount)} events…`;
    case "lifecycle":
      return "Loading case status…";
    default:
      return "Case loaded";
  }
}

/**
 * Current progress: `fraction` (0..1), `percent`, the `label` for the stage now RUNNING (not the
 * one just finished), and whether that stage has any signal behind it.
 *
 * `fraction` is monotonic by construction — a high-water mark lives in the state, so a duplicated
 * or retried byte-progress event reporting less than a previous one cannot rewind the bar. That is
 * enforced here rather than left to the caller's discipline.
 */
export function progressOf(state) {
  const done = prefixCount(state);
  const stage = done < LOAD_STAGES.length ? LOAD_STAGES[done] : null;
  let raw = done / LOAD_STAGES.length;
  let shimmer = stage !== null;
  if (stage === "download" && state.total > 0) {
    // Clamped: a body longer than Content-Length claimed must not spill into the next stage's share.
    raw += Math.min(1, state.loaded / state.total) / LOAD_STAGES.length;
    shimmer = false;
  }
  state.high = Math.max(state.high, raw);
  return {
    fraction: state.high,
    percent: Math.round(state.high * 100),
    label: labelFor(stage, state),
    shimmer,
  };
}

// ── Panel tally ─────────────────────────────────────────────────────────────────────────────────
// The ~60 load*/poll* panel loaders that keep running after the overlay hides.

/** Fresh tally over a denominator fixed before any loader runs, so the strip cannot run backwards. */
export function createPanelTally(total) {
  const n = Math.floor(Number(total));
  return { total: Number.isFinite(n) && n > 0 ? n : 0, settled: new Set(), failed: new Set() };
}

/** Record a panel as finished. Idempotent per name. */
export function settlePanel(tally, name) {
  if (tally) tally.settled.add(name);
}

/**
 * Record a panel as finished unsuccessfully. It still counts as SETTLED — several routes 501 by
 * design when their store is not configured, and a fulfilled-only tally would sit short of the
 * total forever waiting for panels that are never coming.
 */
export function failPanel(tally, name) {
  if (!tally) return;
  tally.settled.add(name);
  tally.failed.add(name);
}

/** Tally state: `fraction` (0..1), `settled`, `total`, `failed`. Empty tallies read as complete. */
export function panelProgressOf(tally) {
  const settled = Math.min(tally.settled.size, tally.total);
  return {
    settled,
    total: tally.total,
    failed: tally.failed.size,
    fraction: tally.total === 0 ? 1 : settled / tally.total,
  };
}

// ── Streaming read ──────────────────────────────────────────────────────────────────────────────

/**
 * Read a response body to text while reporting real byte progress into `state`.
 *
 * This is the ONE phase of a case load with a true denominator, which is why it is worth streaming
 * by hand rather than calling response.text(): Content-Length is present (the server sets no
 * compression middleware), so every chunk yields a fraction that actually means something.
 *
 * Falls back to text() when the body cannot be streamed, and to a shimmer when the header is
 * missing — never to a guess.
 */
export async function readBodyWithProgress(state, response, onProgress) {
  const total = Number(response.headers ? response.headers.get("Content-Length") : 0);
  setDownloadBytes(state, 0, total);
  if (!response.body || typeof response.body.getReader !== "function") return response.text();
  const reader = response.body.getReader();
  const chunks = [];
  let loaded = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
    loaded += value.length;
    setDownloadBytes(state, loaded, total);
    if (onProgress) onProgress();
  }
  const joined = new Uint8Array(loaded);
  let offset = 0;
  for (const chunk of chunks) {
    joined.set(chunk, offset);
    offset += chunk.length;
  }
  return new TextDecoder().decode(joined);
}

// ── Panel runner ────────────────────────────────────────────────────────────────────────────────

/**
 * Run every panel loader, tallying each one as its requests settle.
 *
 * None of the dashboard's panel loaders returns a promise — they are all fire-and-forget
 * `fetch(...).then(...)` chains — so completion is observed at the transport instead. `fetch` is
 * swapped for a wrapper that attributes each request to whichever loader is running when it is
 * CALLED, which works because these loaders all call fetch synchronously in their body.
 *
 * THE WRAPPER'S LIFETIME IS THE SAFETY PROPERTY. Attribution happens at call time, so the wrapper
 * is installed for exactly the synchronous body of ONE loader and restored immediately after, in a
 * `finally` and to the CAPTURED ORIGINAL rather than to whatever is installed at that moment. No
 * unrelated caller can observe the patched global, and a nested install cannot strand a wrapper
 * permanently. Scoping it per loader rather than around the whole run keeps that true even though
 * a queued request now reaches the wire long after its loader's body returned: the wrapper is what
 * ATTRIBUTES and gates, and it does both at call time, so it never has to outlive the call.
 *
 * Without a signal the returned promise is the original, untouched, so callers' `.catch` chains
 * behave exactly as before. With one, an abort is hidden from the loader rather than delivered as
 * a failure — see the wrapper for why a rejected panel fetch must not be allowed to reach handlers
 * that read it as "this endpoint is missing".
 *
 * A loader that throws synchronously is recorded as a failed panel rather than taking the rest of
 * the fan-out with it. A loader that starts no request at all settles immediately.
 *
 * `options.signal` makes the fan-out ABANDONABLE, which the case-load overlay's dismiss button and
 * every case switch depend on. It is injected into each panel request that did not bring a signal
 * of its own, so aborting the generation cancels ~60 in-flight requests instead of leaving them to
 * occupy the browser's connection pool on behalf of a case nobody is looking at any more.
 *
 * `options.concurrency` bounds how many REQUESTS may be on the wire at once. THIS IS A
 * CONNECTION-POOL RESERVATION, not a politeness limit. The dashboard is served over HTTP/1.1, where
 * a browser opens at most six connections per origin; firing all ~60 loaders at once fills that
 * pool for the whole fan-out, and every request the analyst then starts — the case list behind
 * "+ New case", the lock-status probe behind connecting to a different case — sits in the queue
 * behind them. Measured on an 82 MB case: 86 requests, peak 7 in flight, ~7.9s of pure queue wait
 * on requests the server answered in 2ms. Leaving lanes free is what keeps the dashboard usable
 * while a big case loads. Absent or non-positive means unbounded — the original behaviour, kept as
 * the default so callers that never opted in are unaffected.
 *
 * The unit is the request rather than the loader, and the lane is held until the response BODY has
 * been read rather than until its headers land. Both are load-bearing; see the lane block for what
 * each of them was letting through.
 */
export function runPanelLoaders(entries, onProgress, options) {
  const list = Array.isArray(entries) ? entries : [];
  const tally = createPanelTally(list.length);
  const originalFetch = globalThis.fetch;
  const outstanding = new Map();
  const broke = new Set();
  let current = null;

  const opts = options || {};
  const signal = opts.signal || null;
  const rawLimit = Number(opts.concurrency);
  const limit = Number.isFinite(rawLimit) && rawLimit > 0 ? Math.floor(rawLimit) : 0; // 0 = unbounded

  const report = () => {
    if (!onProgress) return;
    try {
      onProgress(tally);
    } catch {
      /* a progress callback must never break the fan-out */
    }
  };
  const finish = (name) => {
    if (broke.has(name)) failPanel(tally, name);
    else settlePanel(tally, name);
    report();
  };

  if (typeof originalFetch !== "function") {
    // No fetch to instrument (node without a global fetch). Still run every loader.
    for (const [name, fn] of list) {
      try {
        fn();
        settlePanel(tally, name);
      } catch {
        failPanel(tally, name);
      }
    }
    return tally;
  }

  // ── Lanes ───────────────────────────────────────────────────────────────────────────────────
  // A lane stands for one of the browser's six per-origin HTTP/1.1 connections, and the cap is a
  // reservation of them. So a lane has to be held by the thing that actually occupies a connection
  // — ONE REQUEST, from the moment it goes on the wire until its body is off it.
  //
  // Counting LOADERS instead got both halves of that wrong. A loader that fans out internally took
  // a single lane however many requests it made (loadVeloTriage issues four, loadMcpRun three), so
  // four such loaders could put a dozen requests on a six-connection pool — the exact saturation
  // the cap exists to prevent. And a lane came back when `fetch` fulfilled, which is when the
  // HEADERS arrive: the body is still streaming down the connection at that point, so the next
  // loader was admitted against a lane that was not free yet.
  let lanesUsed = 0;
  const laneQueue = [];
  // null means "granted, go now". A promise means "queued". Under-cap requests are deliberately
  // NOT deferred by even a microtask: that would change when the common case hits the wire, and
  // the point here is to hold back the over-cap ones only.
  const takeLane = () => {
    if (limit === 0) return null;
    if (lanesUsed < limit) {
      lanesUsed++;
      return null;
    }
    return new Promise((resolve) => laneQueue.push(resolve));
  };
  const freeLane = () => {
    if (limit === 0) return;
    lanesUsed--;
    const next = laneQueue.shift();
    if (next) {
      lanesUsed++; // re-taken immediately by whoever was waiting; every grant pairs with a release
      next();
    }
  };

  // Hold the lane until the BODY has been read, not until the headers land.
  //
  // The reader methods are shadowed with OWN properties, so the Response itself is untouched —
  // `instanceof Response`, `r.ok`, `r.status`, headers and everything else behave exactly as
  // before, which matters because 60 loaders poke at these responses in their own ways.
  const BODY_READERS = ["json", "text", "blob", "arrayBuffer", "formData"];
  const holdLaneUntilBodyRead = (res) => {
    let released = false;
    const release = () => {
      if (released) return;
      released = true;
      freeLane();
    };
    if (!res || typeof res !== "object") {
      release();
      return res;
    }
    // A loader that only checks `r.ok` and never reads the body would otherwise hold its lane for
    // good. setTimeout is a MACROTASK, so every microtask — including the loader's own
    // `.then(r => r.json())` — runs first and gets to clear it; the backstop fires only for a
    // loader that really never reads.
    let backstop = null;
    try {
      backstop = setTimeout(release, 0);
    } catch {
      /* no timer available (a bare test double) — the readers below still release the lane */
    }
    for (const name of BODY_READERS) {
      const read = typeof res[name] === "function" ? res[name] : null;
      if (!read) continue;
      try {
        Object.defineProperty(res, name, {
          configurable: true,
          writable: true,
          value: function (...readArgs) {
            if (backstop !== null) clearTimeout(backstop);
            let out;
            try {
              out = read.apply(this, readArgs);
            } catch (err) {
              release();
              throw err;
            }
            if (!out || typeof out.then !== "function") {
              release();
              return out;
            }
            return out.then(
              (value) => {
                release();
                return value;
              },
              (err) => {
                release();
                throw err;
              },
            );
          },
        });
      } catch {
        /* frozen or exotic response — leave it be; the backstop still frees the lane */
      }
    }
    return res;
  };

  const patchedFetch = function (...args) {
    const owner = current;
    // Only supply a signal where the caller chose none — a loader that brought its own abort
    // controller keeps it.
    if (signal && args.length > 0 && (!args[1] || !args[1].signal)) {
      args[1] = Object.assign({}, args[1], { signal });
    }
    // Not one of ours. The wrapper is only ever installed around a loader's synchronous body, so
    // this is belt-and-braces: issue it untouched and take no lane.
    if (owner === null) return originalFetch.apply(this, args);

    const self = this;
    // Counted against its loader NOW, synchronously, so attribution survives a lane wait.
    outstanding.set(owner, (outstanding.get(owner) || 0) + 1);
    const issue = () => {
      // Abandoned while queued — never put it on the wire at all.
      if (signal && signal.aborted) {
        freeLane();
        throw new Error("panel request abandoned");
      }
      let out;
      try {
        out = originalFetch.apply(self, args);
      } catch (err) {
        freeLane();
        throw err;
      }
      if (!out || typeof out.then !== "function") {
        freeLane();
        return out;
      }
      return out.then(holdLaneUntilBodyRead, (err) => {
        freeLane();
        throw err;
      });
    };
    const queued = takeLane();
    let p;
    if (queued === null) {
      // Granted: run issue() RIGHT HERE, inside the loader's own synchronous body, so an under-cap
      // request reaches the wire at exactly the moment it always did.
      try {
        p = Promise.resolve(issue());
      } catch (err) {
        p = Promise.reject(err);
      }
    } else {
      p = queued.then(issue);
    }
    // The TALLY watches this promise, so the strip still settles every panel on abort.
    p.then(
      () => settleOne(owner, false),
      () => settleOne(owner, true),
    );
    if (!signal) return p;
    // What the LOADER sees is different, and deliberately so. These loaders overwhelmingly end in
    // `.catch(() => somethingUnavailable())`, and ~73 of those report a missing endpoint on the
    // shared status line — several telling the analyst in as many words to restart the companion
    // server. An abort is not a broken endpoint: cancelling a case load, or switching cases, would
    // otherwise fill the screen with alarms about a server that is perfectly healthy, and hand out
    // actively wrong advice.
    //
    // So on OUR abort the loader's chain never runs at all: it is handed a promise that stays
    // pending forever, which is the honest shape for "this request was abandoned, draw nothing".
    // The pending promises are bounded by the fan-out (~60) and die with the retired generation.
    // Any other rejection — a real network failure, a real 5xx — is rethrown untouched, so genuine
    // unavailability still reports exactly as before.
    return p.catch((err) => {
      if (signal.aborted) return new Promise(() => {});
      throw err;
    });
  };

  let next = 0;

  // Start one loader with the wrapper installed for exactly its synchronous body.
  const startLoader = (name, fn) => {
    globalThis.fetch = patchedFetch;
    current = name;
    try {
      fn();
    } catch {
      broke.add(name);
    } finally {
      current = null;
      globalThis.fetch = originalFetch;
    }
    // Promise callbacks are microtasks and cannot have run yet, so an absent entry here really
    // does mean "this loader issued no request".
    if (!outstanding.has(name)) finish(name);
  };

  // Every loader that never started is settled-as-failed rather than left pending, so the strip
  // reaches its total instead of sitting short forever on panels that are never coming. Only
  // reachable when the signal was ALREADY aborted on the way in — see the loop below.
  const abandonRemaining = () => {
    while (next < list.length) {
      const [name] = list[next++];
      broke.add(name);
      finish(name);
    }
  };

  function settleOne(owner, failed) {
    if (failed) broke.add(owner);
    const left = (outstanding.get(owner) || 1) - 1;
    outstanding.set(owner, left);
    if (left > 0) return;
    finish(owner);
  }

  // Release everything still waiting for a lane so it can observe the abort and reject, instead of
  // queueing behind lanes that are themselves being torn down. Each resolved waiter runs issue(),
  // sees signal.aborted and never reaches the wire — so the tally completes without a single extra
  // request. Granting a lane per waiter keeps the accounting balanced, since each one's issue()
  // path frees a lane on its way out.
  const releaseLaneQueue = () => {
    while (laneQueue.length) {
      lanesUsed++;
      laneQueue.shift()();
    }
  };

  // Guarded because `signal` only has to be signal-SHAPED for the injection above to work, and a
  // test double need not be an EventTarget.
  if (signal && typeof signal.addEventListener === "function") {
    signal.addEventListener("abort", releaseLaneQueue, { once: true });
  }

  // Every loader starts now. There is no loader-level throttle any more and there should not be:
  // starting a loader costs nothing until it asks for a connection, and the lane semaphore above
  // is what gates those. One gate, on the resource that is actually scarce.
  if (signal && signal.aborted) abandonRemaining();
  else while (next < list.length) startLoader(...list[next++]);
  return tally;
}

// ── Browser glue ────────────────────────────────────────────────────────────────────────────────
// Everything below touches the DOM and is deliberately thin — the logic worth testing lives above.
//
// The inline dashboard script owns the load sequence (it is the only code that can see render(),
// the 60 loaders and the abort generation from #174), so this half publishes a facade it calls into
// rather than driving anything itself. Every call site there guards on the facade being present, so
// if this module has not executed yet the load proceeds exactly as it did before — without a bar,
// never broken.

function paintOverlay(state) {
  const p = progressOf(state);
  const bar = document.getElementById("caseLoadingBar");
  if (bar) {
    bar.style.setProperty("--clp-w", (p.fraction * 100).toFixed(1) + "%");
    // The shimmer sits over the PENDING segment only: it says "working, no estimate available"
    // for the stage in progress without implying anything about how far along it is.
    bar.classList.toggle("clp-shimmer", p.shimmer);
  }
  const text = document.getElementById("caseLoadingText");
  if (text) text.textContent = p.label;
  const pct = document.getElementById("caseLoadingPct");
  // Only shown once it means something. "0%" next to a shimmer is noise, not information.
  if (pct) pct.textContent = p.fraction > 0 ? p.percent + "%" : "";
}

/**
 * Resolves after the browser has actually painted — or after `timeoutMs`, whichever comes first.
 *
 * Awaited immediately before JSON.parse and render(), both of which block the main thread for as
 * long as they take. Without this the label change for those stages is queued behind the very work
 * it describes and never appears until after it finishes — so the bar would freeze showing the
 * PREVIOUS stage and read as hung during the two phases that most need explaining. Two frames: the
 * first schedules the style change, the second guarantees it was painted.
 *
 * THE TIMEOUT IS NOT OPTIONAL, and neither is the hidden-document check. A backgrounded or
 * throttled tab does not run rAF callbacks AT ALL, and this await sits in the middle of the case
 * load. Without a way out it does not degrade the bar — it hangs the LOAD: the dashboard never
 * renders and the overlay never hides. Found live: opening a case and switching browser tabs (which
 * is exactly what an analyst does while waiting) left the dashboard stuck at "Parsing …" forever
 * with an empty timeline. A cosmetic paint hint must never be able to block the work it describes.
 */
export function afterPaint(timeoutMs = 50) {
  if (typeof requestAnimationFrame !== "function") return Promise.resolve();
  // Nothing is being painted in a hidden document, so there is no paint to wait for.
  if (typeof document !== "undefined" && document.visibilityState === "hidden") {
    return Promise.resolve();
  }
  return new Promise((resolve) => {
    let settled = false;
    const finish = () => {
      if (settled) return;
      settled = true;
      resolve();
    };
    setTimeout(finish, timeoutMs);
    requestAnimationFrame(() => requestAnimationFrame(finish));
  });
}

function paintPanelStrip(tally) {
  const el = document.getElementById("panelProgressBar");
  if (!el) return;
  const p = panelProgressOf(tally);
  el.classList.add("ppb-active");
  el.classList.toggle("ppb-failed", p.failed > 0);
  el.style.setProperty("--ppb-w", (p.fraction * 100).toFixed(1) + "%");
  el.title = p.failed > 0
    ? `${p.settled} of ${p.total} panels loaded, ${p.failed} unavailable`
    : `${p.settled} of ${p.total} panels loaded`;
  // Said once, then it goes away. A permanent bar reporting "5 unavailable" would nag about
  // routes that are 501 by design in this deployment.
  if (p.fraction >= 1) setTimeout(() => el.classList.remove("ppb-active"), 900);
}

function hidePanelStrip() {
  const el = document.getElementById("panelProgressBar");
  if (!el) return;
  el.classList.remove("ppb-active", "ppb-failed");
  el.style.setProperty("--ppb-w", "0%");
}

// Guarded so the pure exports above can be imported in node (Vitest) with no DOM present.
if (typeof document !== "undefined" && typeof window !== "undefined") {
  window.DfirCaseLoadProgress = {
    createLoadState,
    advanceStage,
    setEventCount,
    progressOf,
    readBodyWithProgress,
    runPanelLoaders,
    panelProgressOf,
    paintOverlay,
    afterPaint,
    paintPanelStrip,
    hidePanelStrip,
  };
}
