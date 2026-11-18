// Watson's CrowdStrike Next-Gen SIEM search card (#2666): a cs_search proposal. It shows the exact
// CQL that will run, the repository and the time range; Run search starts the same search job as the
// Run in Falcon button on a CQL hunt card, and the rows are imported as evidence. After the search,
// the card shows its outcome sentence. Pure HTML builder; dashboard-watson-cards.js calls it.
// Every model and server string goes through esc()/escAttr(). Actions ride on data-act="watsonAct".
(function () {
  const NO_UNDO = "You cannot undo a search that ran. Use Undo import to take its rows back out.";

  const btn = (pid, verb, label) =>
    `<button type="button" class="watson-mini" data-act="watsonAct" data-w-verb="${verb}" data-pid="${escAttr(pid)}">${label}</button> `;

  function timeHtml(iso) {
    const raw = String(iso || "");
    if (!raw || isNaN(Date.parse(raw))) return esc(raw);
    return `<span title="${escAttr(raw)}">${esc(raw.replace("T", " ").replace(/\.\d+Z$/, "Z"))}</span>`;
  }

  function statusHtml(p) {
    if (p.status !== "applied") return "";
    const l = p.launched || {};
    const w = p.watch || {};
    const state =
      w.state === "finished" || w.state === "failed"
        ? esc(w.text || (w.state === "failed" ? "The search did not complete." : "The search finished."))
        : "The search runs now. Follow it in the Jobs panel. Watson hears the result when it finishes.";
    return (
      `<div class="watson-why">${esc(l.by || p.appliedBy || "An analyst")} started this search at ${timeHtml(l.at || p.appliedAt)}</div>` +
      `<div class="watson-why" data-w-status="cs">${state}</div>` +
      `<div class="watson-why">${esc(NO_UNDO)}</div>`
    );
  }

  function verbs(p) {
    return p.status === "pending" ? btn(p.id, "apply", "Run search") + btn(p.id, "reject", "Reject") : "";
  }

  // "Open in Falcon" (#2685): the card's query and range in Next-Gen SIEM Advanced event search, a
  // plain link built by dashboard-siem-search.js (no API call, no credential). Absent when that
  // module does not know the console host.
  function openInFalcon(p) {
    const url = typeof falconSearchUrl === "function" ? falconSearchUrl(p.query, p.start, p.end, p.repository) : "";
    return url
      ? `<a class="watson-mini watson-falcon-open" href="${escAttr(url)}" target="_blank" rel="noopener noreferrer" ` +
          `title="Open this query in Falcon Next-Gen SIEM Advanced event search, in a new tab. Nothing runs here.">Open in Falcon</a> `
      : "";
  }

  function csCardHtml(p) {
    const grey = p.status === "rejected" ? " watson-rejected" : "";
    return (
      `<div class="watson-prop watson-cs watson-prop-${escAttr(p.status)}${grey}" data-pid="${escAttr(p.id)}">` +
      `<div class="watson-lbl">CrowdStrike NG-SIEM search · ${esc(p.status)}</div>` +
      `<div><strong>${esc(p.title)}</strong></div>` +
      `<div class="watson-why">Repository ${esc(p.repository)} · ${timeHtml(p.start)} to ${timeHtml(p.end)}</div>` +
      `<pre class="watson-pre">${esc(p.query)}</pre>` +
      `<button type="button" class="watson-mini" data-act="watsonAct" data-w-verb="copy">Copy</button>` +
      openInFalcon(p) +
      (p.status === "pending"
        ? `<div class="watson-meta">Runs this query on your Next-Gen SIEM and imports the rows into the case as evidence. It changes nothing in Falcon.</div>`
        : "") +
      statusHtml(p) +
      (p.uiError ? `<div class="watson-why watson-err">${esc(p.uiError)}</div>` : "") +
      `<div>${verbs(p)}</div></div>`
    );
  }

  window.watsonCsCardHtml = csCardHtml;
})();
