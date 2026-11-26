// The AI Agent Forensics findings table: what its filters offer, which hits they keep, and how long
// values are shortened for the table (#2911).
//
// A real run produced dozens of hits of one rule against agent session files, and the table had no
// way to narrow them: one long scroll of full paths and four-line hash cells. The filters (grade, rule,
// and endpoint when the run has more than one) and the shortening live here so they can be tested.
//
// PURE, AND HOLDS NOTHING. The run card owns the DOM; every function takes what it needs.

const AA_GRADE_ORDER = ["Critical", "High", "Medium", "Low", "Info"];

// The choices each filter offers, from the hits themselves: grades most severe first, rules and
// endpoints alphabetically. An unknown grade sorts after the known ones.
function aaHitFilterOptions(hits) {
  const list = Array.isArray(hits) ? hits : [];
  const uniq = (pick) => [...new Set(list.map(pick).filter((v) => typeof v === "string" && v))];
  const rank = (g) => {
    const i = AA_GRADE_ORDER.indexOf(g);
    return i < 0 ? AA_GRADE_ORDER.length : i;
  };
  return {
    grades: uniq((h) => h.severity).sort((a, b) => rank(a) - rank(b) || a.localeCompare(b)),
    rules: uniq((h) => h.rule).sort((a, b) => a.localeCompare(b)),
    hosts: uniq((h) => h.host).sort((a, b) => a.localeCompare(b)),
  };
}

// The hits a filter keeps. An empty choice means "all"; every set choice must match exactly.
function aaFilterHits(hits, filter) {
  const list = Array.isArray(hits) ? hits : [];
  const f = filter || {};
  return list.filter(
    (h) => (!f.grade || h.severity === f.grade) && (!f.rule || h.rule === f.rule) && (!f.host || h.host === f.host),
  );
}

// "Showing 12 of 40 findings" while a filter hides some; "40 finding(s)" when none is set.
function aaHitCountNote(shown, total) {
  const n = (x) => Number(x).toLocaleString("en-US");
  return shown < total ? `Showing ${n(shown)} of ${n(total)} findings` : `${n(total)} finding(s)`;
}

// A long path kept readable in a narrow column: the start (drive, user folder) and the end (the file
// name), with the middle cut. The full path stays on the cell's hover title.
function aaShortPath(path, max = 70) {
  const s = typeof path === "string" ? path : "";
  if (s.length <= max) return s;
  const tail = Math.ceil((max - 1) * 0.6);
  return `${s.slice(0, max - 1 - tail)}…${s.slice(s.length - tail)}`;
}

// A SHA-256 shortened for the table: its first 12 characters. "none" when there is none.
function aaShortHash(hash) {
  return typeof hash === "string" && hash ? `${hash.slice(0, 12)}…` : "none";
}

window.aaHitFilterOptions = aaHitFilterOptions;
window.aaFilterHits = aaFilterHits;
window.aaHitCountNote = aaHitCountNote;
window.aaShortPath = aaShortPath;
window.aaShortHash = aaShortHash;
