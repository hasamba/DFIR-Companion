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

  // A count from the wire: a finite positive number, or 0. A string or NaN never reaches arithmetic.
  const count = (v) => (typeof v === "number" && isFinite(v) && v > 0 ? v : 0);

  /** Rows the last run matched but never reached. Zero when there is no run to compare against. */
  function unreadRows(r) {
    if (!r) return 0;
    return Math.max(0, count(r.matched) - count(r.read));
  }

  // WHAT A FULL READ WOULD COVER, FROM THE LAST RUN'S OWN NUMBERS — never from a guess.
  //
  // `matched` is how many rows a full read reads. The spend is per row GRADED, not per row read:
  // rows already analysed, inside a build window or from the collector's own footprint are read and
  // set aside before anything goes to the model (#2077). So the last run's cost is divided by the
  // rows it graded and multiplied by the rows a full read would grade. That second number is not
  // knowable without reading the rows, so the plan gives a range rather than inventing one figure:
  //   - costLow:  the unread rows get graded as often as the rows read did;
  //   - costHigh: every unread row needs grading (none is analysed or set aside).
  // On the case behind #2077 the read sample was mostly already analysed, so the low end came out
  // about 3x under the real cost — which is why the high end is shown beside it.
  // When there is no last run, `known` is false and the panel says it does not know rather than
  // printing a number it invented. Same when the run reported no cost or graded nothing: both stay null.
  function fullReadPlan(result) {
    if (!result) return { known: false, matched: 0, unread: 0, costLow: null, costHigh: null };
    const matched = count(result.matched);
    const read = count(result.read);
    const graded = count(result.graded);
    const unread = unreadRows(result);
    const usage = result.usage || {};
    const spent = typeof usage.costUSD === "number" && isFinite(usage.costUSD) ? usage.costUSD : null;
    const perGraded = spent !== null && graded > 0 && read > 0 ? spent / graded : null;
    return {
      known: true,
      matched,
      unread,
      costLow: perGraded !== null ? perGraded * (graded + (unread * graded) / read) : null,
      costHigh: perGraded !== null ? perGraded * (graded + unread) : null,
    };
  }

  // The plan's cost in words: "" when unknown, one figure when both ends print the same.
  function costRangeText(plan) {
    const low = money(plan && plan.costLow);
    const high = money(plan && plan.costHigh);
    if (!low || !high) return "";
    return low === high ? `about ${low}` : `${low} to ${high}`;
  }

  // The share of the archive a run read, as a percentage that never lies at either end: a read of
  // a few rows is "<1%", never "0%", and a read one row short is ">99%", never "100%".
  function coverageShare(read, matched) {
    if (!(matched > 0)) return "";
    const ratio = Math.min(1, Math.max(0, read / matched));
    if (ratio < 0.01) return "<1%";
    if (ratio < 1 && Math.round(ratio * 100) >= 100) return ">99%";
    return `${Math.round(ratio * 100)}%`;
  }

  // THE CAPPED-REVIEW WARNING (#2077). Only when the cap really held rows back — the #1540 rule:
  // a shortfall with no cap in force is the caption's to report, and it must not blame the cap.
  // `foundNothing` (no graded row above Info) makes it a bordered status block the panel puts
  // first, because an empty result is when an analyst stops. It states the unread count only:
  // how many of those rows were never graded is not knowable without reading them.
  function capWarningHtml(result, opts) {
    if (!result || result.capped !== true) return "";
    const unread = unreadRows(result);
    if (unread <= 0) return "";
    const read = count(result.read);
    const matched = count(result.matched);
    const share = coverageShare(read, matched);
    const lead =
      `Reviewed ${num(read)} of ${num(matched)} archive rows${share ? ` (${share})` : ""}. ` +
      `${num(unread)} archive rows were not read.`;
    const cost = costRangeText(fullReadPlan(result));
    const offer =
      "Reading every row covers them" +
      (cost ? ` — estimated ${cost} from this run's cost per graded row, an estimate, not a quote.` : ".");
    const button = `<button type="button" id="jevOfferAll">Read every row</button>`;
    if (opts && opts.foundNothing) {
      return `<div class="jev-cap-warn" role="status">
      <p class="jev-confirm-head">Nothing above Info was found — in the rows that were read.</p>
      <p class="jev-caption">${esc(lead)} ${esc(offer)}</p>
      <p class="jev-offer">${button}</p>
      <p class="jev-caption jev-truncated">An empty result here is not evidence that nothing was missed.</p>
    </div>`;
    }
    return `<p class="jev-offer"><strong>${esc(lead)}</strong> ${esc(offer)} ${button}</p>`;
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
    const buildWindow = result.buildWindow || 0;
    const collector = result.collectorFootprint || 0;
    const read = result.read || 0;
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
    //
    // The sum closes on the rows READ: graded + already analysed + build window = read, and a capped
    // read names what it never reached below. It used to claim "all N that matched" even when the cap
    // had held rows back (Codex review of #1700). The build-window clause is #1700: the review sets
    // the host's own provisioning rows aside before it grades anything.
    // DFIR_JEV_GRADING: say when the experimental style graded the rows, so a grade is never read
    // without knowing which method produced it. An older server sends no shape — nothing is said.
    let line = `Graded ${num(graded)} archive row(s)${result.shape === "decomposed" ? " with narrow questions (experimental)" : ""}.`;
    const skipped = [];
    if (analyzed > 0)
      skipped.push(`${num(analyzed)} were skipped because the case has already analysed them — the AI can see those`);
    if (buildWindow > 0) {
      // WHERE, not just how many (Codex review of #1700): the analyst can open these ranges in the
      // super-timeline and check a set-aside row by hand. Host names come from the case's own data
      // and still go through esc().
      const windows = Array.isArray(result.buildWindows) ? result.buildWindows : [];
      const where = windows
        .slice(0, 3)
        .map((w) => `${esc(w.host)} ${when(w.start).slice(0, 16)}–${when(w.end).slice(11, 16)} UTC`)
        .join("; ");
      const more = windows.length > 3 ? `; ${num(windows.length - 3)} more` : "";
      skipped.push(
        `${num(buildWindow)} were set aside because they sit inside the host's own build window` +
          ` — the machine being built, not the incident` +
          (where ? ` (${where}${more}; open that range in the super-timeline to check them)` : ""),
      );
    }
    // #1949: rows the importer marked as the investigator's own collector at work. Graded blind they
    // read as the intruder, so the review sets them aside like the build window.
    if (collector > 0)
      skipped.push(
        `${num(collector)} were set aside because they are the collector's own footprint` +
          ` — the investigator's tooling at work, not the incident`,
      );
    if (skipped.length) {
      line += ` Another ${skipped.join(". Another ")}.`;
      line +=
        unread > 0
          ? ` That accounts for all ${num(read)} row(s) read.`
          : ` That accounts for all ${num(matched)} row(s) that matched.`;
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
    if (graded === 0 && analyzed + buildWindow + collector > 0 && result.capped !== true) {
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
      const est = costRangeText(plan);
      body =
        `This reads all ${num(plan.matched)} matching super-timeline row(s), ` +
        `${num(plan.unread)} of which the last run never reached. ` +
        (est
          ? `Estimated cost ${est}, worked out from the last run's own cost per graded row — an estimate, not a quote.`
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

  // THE REASON LINE (#1924). A decomposed grade was decided by a rule from a few answers; this says
  // which, in words. Evidence words use the server rule's own cut points (jevDecomposed.ts: 1, 1.5,
  // 2.5), so the word never disagrees with the grade; impact words round to the nearest level, whose
  // top edge is the rule's 2.5. Plain text — the caller escapes it. Anything malformed reads as no reason.
  const STRENGTH_CUTS = [1, 1.5, 2.5];
  const STRENGTH_WORDS = ["speculative", "circumstantial", "strong", "confirmed"];
  const IMPACT_WORDS = [
    "none or limited",
    "host-level",
    "credentials, privilege or persistence",
    "domain-wide or destructive",
  ];
  const fin = (v) => typeof v === "number" && isFinite(v);
  const levelWord = (words, v) => words[Math.min(words.length - 1, Math.max(0, Math.round(v)))];

  function signalsText(row) {
    const s = row && row.signals;
    if (!s || !fin(s.malicious) || !fin(s.strength) || !fin(s.impact)) return "";
    const parts = [
      `attacker activity ${pct(s.malicious)}`,
      `evidence: ${STRENGTH_WORDS[STRENGTH_CUTS.filter((c) => s.strength >= c).length]}`,
      `impact: ${levelWord(IMPACT_WORDS, s.impact)}`,
    ];
    if (s.decision === "conflict") parts.push("conflicts with an analyst record — check it");
    else if (s.decision === "explained" && fin(s.explained))
      parts.push(`an analyst record explains it (${pct(s.explained)})`);
    return parts.join(" · ");
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
  window.jevSignalsText = signalsText;
  window.jevFullReadConfirmHtml = confirmHtml;
  window.jevCapWarningHtml = capWarningHtml;
})();
