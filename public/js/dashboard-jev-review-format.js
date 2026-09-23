// Missed evidence review (#1540, #1568): the pure formatting half of js/dashboard-jev-review.js.
//
// Split out when #1552's "Stop waiting" control pushed that module past the 800-line budget. The
// size gate is a freeze, not a budget to spend, so the answer is a new module, not a bigger one.
//
// PURE, AND HOLDS NOTHING. Every function here takes what it needs as an argument — the last
// review response, the row counts the panel drew, the full-read plan — and returns a string or a
// number. The review's state, its run and its render stay in js/dashboard-jev-review.js, which
// calls these at paint time only, so this file must be tagged before it but is never read at load.
//
// Published under a `jev` prefix: these are page globals, and bare `num` or `when` would collide.
(function () {
  // The grades the server may send. A class name is built from this value, so it is matched
  // against the list rather than interpolated — model output is never trusted into markup.
  const GRADES = ["Critical", "High", "Medium", "Low", "Info"];

  const gradeRank = (g) => {
    const i = GRADES.indexOf(g);
    return i < 0 ? GRADES.length : i;
  };

  const gradeClass = (g) => (GRADES.indexOf(g) < 0 ? "sev-Info" : `sev-${g}`);

  const pct = (v) => (typeof v === "number" && isFinite(v) ? `${Math.round(v * 100)}%` : "—");

  const when = (ts) => (ts ? String(ts).slice(0, 19).replace("T", " ") : "—");

  function money(v) {
    if (typeof v !== "number" || !isFinite(v) || v < 0) return "";
    // Sub-cent runs are the normal case for a decision model, so a 2-decimal format would print
    // "$0.00" for every run and say nothing.
    return v >= 0.01 ? `$${v.toFixed(2)}` : `$${v.toFixed(6)}`;
  }

  const num = (v) => (typeof v === "number" && isFinite(v) ? v.toLocaleString() : "0");

  /** Rows the last run matched but never reached. Zero when there is no run to compare against. */
  function unreadRows(r) {
    if (!r) return 0;
    return Math.max(0, (r.matched || 0) - (r.read || 0));
  }

  // WHAT A FULL READ WOULD COVER, FROM THE LAST RUN'S OWN NUMBERS — never from a guess.
  //
  // `matched` is how many rows a full read reads. The cost is the last run's real cost scaled by
  // rows read (cost x matched / read), because the spend is per row read, not per row matched.
  // When there is no last run, `known` is false and the panel says it does not know rather than
  // printing a number it invented. Same when the run reported no cost: `cost` stays null.
  function fullReadPlan(result) {
    if (!result) return { known: false, matched: 0, unread: 0, cost: null };
    const matched = result.matched || 0;
    const read = result.read || 0;
    const usage = result.usage || {};
    const spent = typeof usage.costUSD === "number" && isFinite(usage.costUSD) ? usage.costUSD : null;
    return {
      known: true,
      matched,
      unread: unreadRows(result),
      cost: spent !== null && read > 0 ? (spent * matched) / read : null,
    };
  }

  // `counts` is what the panel drew — { shown, kept, drawn } after the tooling filter, the grade
  // and confidence floors, and the draw cap — so this reads no panel state of its own.
  function captionHtml(result, counts) {
    // STATE FACTS, NAME NO CAUSE YOU CANNOT KNOW. This caption once read "the row cap stopped the
    // read" on a case where 1,344 rows matched a 2,000 cap: the shortfall was 366 rows already in
    // the forensic timeline, not the cap. The server now sends the reasons apart — `capped` is true
    // only when the cap really held rows back — and each fact gets its own clause.
    //
    // `readAll` is a third fact, not a fourth guess: the server says the run ignored the cap, and
    // the shortfall is still checked against the numbers before the panel calls it full coverage.
    const matched = result.matched || 0;
    const analyzed = result.alreadyAnalyzed || 0;
    const graded = result.graded || 0;
    const unread = unreadRows(result);
    const total = Array.isArray(result.rows) ? result.rows.length : 0;
    const hidden = total - counts.shown;

    // SAY THE SUM OUT LOUD. The first wording read "848 of 1,308 matching super-timeline row(s)
    // were graded. 460 were already in the forensic timeline" — and an analyst whose forensic
    // timeline PANEL showed 182 rows could not reconcile it, because the panel filters what it
    // draws and the stored timeline is bigger than the view. So the caption no longer invites a
    // comparison with a number on another screen: it accounts for the rows it read, and states
    // the total it is accounting for, so the arithmetic closes here (#1547).
    let line = `Graded ${num(graded)} archive row(s).`;
    if (analyzed > 0) {
      line +=
        ` Another ${num(analyzed)} were skipped because the case has already analysed them` +
        ` — the AI can see those. That accounts for all ${num(matched)} row(s) that matched.`;
    } else {
      line += ` That is every row that matched, out of ${num(matched)}.`;
    }
    if (result.readAll === true && result.capped !== true && unread === 0) {
      line += " Nothing was left unread: no cap was in force.";
    } else if (result.readAll === true && result.capped !== true && unread > 0) {
      // The cap was not in force and rows are still missing. The panel does not know why, so it
      // reports the shortfall and stops there.
      line +=
        ` <span class="jev-truncated">${num(unread)} matching row(s) were not read, ` +
        `so this is not full coverage of the case.</span>`;
    }
    if (result.capped === true && unread > 0) {
      line +=
        ` <span class="jev-truncated">The ${num(result.cap || 0)}-row cap stopped the read — ` +
        `${num(unread)} matching row(s) were never read, so this is not full coverage of the case.</span>`;
    }
    if (graded === 0 && analyzed > 0 && result.capped !== true) {
      line += " Nothing was left for this review to grade.";
    }

    // The display line subtracts in the order the analyst sees: the tooling filter takes rows out
    // first, then the grade and confidence floors, then the draw cap shows the top of what is left.
    // The first version listed shown, hidden and undrawn as three flat numbers that happened to sum
    // to the total, which reads as three unrelated facts rather than one subtraction. EVERY
    // subtraction is named, because each one also narrows what a select-all would promote.
    const passing = total - hidden;
    const kept = counts.kept;
    const byFilters = passing - kept;
    const drawn = counts.drawn;
    let second = "";
    if (hidden > 0) {
      second += `${num(hidden)} of the ${num(total)} graded row(s) look like our own collection tooling and are hidden. `;
      second += `Of the ${num(passing)} left, `;
    } else {
      second += `Of the ${num(total)} graded row(s), `;
    }
    if (byFilters > 0) second += `${num(byFilters)} are below the grade or confidence filter. Of the ${num(kept)} left, `;
    second +=
      drawn >= kept
        ? `all ${num(drawn)} are shown.`
        : `the top ${num(drawn)} are shown — ${num(kept - drawn)} more are not drawn.`;
    return `<p class="jev-caption">${line}</p><p class="jev-caption">${esc(second)}</p>`;
  }

  // THE CONFIRMATION, IN THE PANEL — never confirm(), alert() or any other browser modal: they
  // block the automation harness, and a native dialog cannot show the numbers this one has to.
  function confirmHtml(plan) {
    let body;
    if (!plan.known) {
      body =
        "No review has run on this case yet, so this panel cannot say how many rows a full read " +
        "covers or what it would cost. That is not an estimate of zero — the figures are simply " +
        "not known until a first run reports them.";
    } else {
      const est = money(plan.cost);
      body =
        `This reads all ${num(plan.matched)} matching super-timeline row(s), ` +
        `${num(plan.unread)} of which the last run never reached. ` +
        (est
          ? `Estimated cost ${est}, worked out from the last run's own cost per row — an estimate, not a quote.`
          : "The last run reported no cost, so there is no figure to estimate from.");
    }
    return `<div class="jev-confirm" role="group" aria-label="Confirm reading every row">
      <p class="jev-confirm-head">Read every row, ignoring the cap?</p>
      <p class="jev-caption">${esc(body)}</p>
      <p class="jev-caption">It reads only. Nothing is promoted and no case data changes, however long it runs.</p>
      <p class="jev-confirm-actions">
        <button type="button" id="jevConfirmRun">Yes — read every row</button>
        <button type="button" id="jevConfirmCancel">Cancel</button>
      </p>
    </div>`;
  }

  // Accessor, not the array: published names must be callable, and a shared array is one another
  // module could push to.
  window.jevGrades = () => GRADES.slice();
  window.jevGradeRank = gradeRank;
  window.jevGradeClass = gradeClass;
  window.jevPct = pct;
  window.jevWhen = when;
  window.jevMoney = money;
  window.jevNum = num;
  window.jevUnreadRows = unreadRows;
  window.jevFullReadPlan = fullReadPlan;
  window.jevCaptionHtml = captionHtml;
  window.jevFullReadConfirmHtml = confirmHtml;
})();
