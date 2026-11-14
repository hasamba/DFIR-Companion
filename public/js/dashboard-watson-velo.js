// Watson's Velociraptor pieces: the launch card (velo_launch proposals), the "Velociraptor connected"
// chip, and the Auto listing turn drawn as a list. Pure HTML builders except watsonVeloResolve, which
// posts the analyst's answer for an uncertain launch. dashboard-watson-cards.js calls the card builder.
//
// Every model and evidence string (title, VQL, host, ids, names, error text) goes through
// esc()/escAttr() (dashboard-escape.js). Actions ride on data-act="watsonAct" + data-w-verb.
(function () {
  const AUTO_HEADS = ["Watson acted on its own (Auto mode", "(Watson's Auto actions, continued)"];
  const UNCERTAIN =
    "Watson cannot tell whether this ran. Check Velociraptor, then mark it launched or try again.";
  const NO_UNDO = "A launched hunt cannot be undone: it already ran on the endpoints.";

  const num = (n) => esc(String(Number(n) || 0));
  const rowsText = (n) => `${num(n)} row${Number(n) === 1 ? "" : "s"}`;

  function statusLine(w) {
    if (!w || w.state === "watching") return "Running. Watson reads the result when it finishes.";
    if (w.state === "timeout") return "Timed out waiting for the result. Check Velociraptor.";
    if (w.state === "failed") return `Could not read the result${w.error ? `: ${esc(w.error)}` : ""}.`;
    if (typeof w.rows !== "number") return "Finished.";
    if (w.rows === 0) return "Found nothing: the collection returned no rows.";
    const cut = w.truncated
      ? ` (cut by the row cap${Number(w.total) > 0 ? `; Velociraptor counted ${num(w.total)}` : ""})`
      : "";
    return `Collected ${rowsText(w.rows)}${cut}.`;
  }

  const where = (p) =>
    p.mode === "hunt" ? "Fleet-wide hunt — all enrolled clients" : `Collection on ${esc(p.hostname || "a host")}`;

  const btn = (pid, verb, label, extra) =>
    `<button type="button" class="watson-mini" data-act="watsonAct" data-w-verb="${verb}" data-pid="${escAttr(pid)}"${extra || ""}>${label}</button> `;

  function bodyFor(p) {
    const lines = [];
    if (p.status === "launching") lines.push(`<div class="watson-why">Launching…</div>`);
    if (p.status === "applied") {
      const l = p.launched || {};
      lines.push(
        `<div class="watson-why">Launched by ${esc(l.by || p.appliedBy || "an analyst")} at ${esc(l.at || p.appliedAt || "")}</div>`,
        `<div class="watson-why" data-w-status="launch">${statusLine(p.watch)}</div>`,
        `<div class="watson-why">${esc(NO_UNDO)}</div>`,
      );
    }
    if (p.status === "uncertain") lines.push(`<div class="watson-why watson-warn">${esc(UNCERTAIN)}</div>`);
    return lines.join("");
  }

  function verbsFor(p) {
    if (p.status === "pending") return btn(p.id, "apply", "Launch") + btn(p.id, "reject", "Reject");
    if (p.status === "uncertain")
      return (
        btn(p.id, "resolveLaunch", "Mark as launched", ' data-outcome="launched"') +
        btn(p.id, "resolveLaunch", "Try again", ' data-outcome="retry"')
      );
    return "";
  }

  function veloCardHtml(p) {
    const grey = p.status === "rejected" ? " watson-rejected" : "";
    return (
      `<div class="watson-prop watson-velo${grey}" data-pid="${escAttr(p.id)}">` +
      `<div class="watson-lbl">Velociraptor launch · ${esc(p.status)}</div>` +
      `<div><strong>${esc(p.title)}</strong></div>` +
      `<div class="watson-why">${where(p)}</div>` +
      `<pre class="watson-pre">${esc(p.vql)}</pre>` +
      `<button type="button" class="watson-mini" data-act="watsonAct" data-w-verb="copy">Copy</button>` +
      bodyFor(p) +
      (p.uiError ? `<div class="watson-why watson-err">${esc(p.uiError)}</div>` : "") +
      `<div>${verbsFor(p)}</div></div>`
    );
  }

  function chipHtml(connected) {
    return connected
      ? `<span class="watson-velo-chip" title="This case has a Velociraptor server Watson can launch on">Velociraptor connected</span>`
      : "";
  }

  // The Auto listing: "- line" items, each maybe followed by "  VQL:" and the query. "" for any other turn.
  function autoListHtml(text) {
    const all = String(text || "").split("\n");
    if (!AUTO_HEADS.some((h) => all[0].startsWith(h))) return "";
    const items = [];
    for (const raw of all.slice(1)) {
      if (raw.startsWith("- ") || !items.length) items.push({ line: raw.replace(/^- /, ""), vql: null });
      else {
        const cur = items[items.length - 1];
        if (cur.vql !== null) cur.vql.push(raw);
        else if (raw.trim() === "VQL:") cur.vql = [];
        else cur.line += "\n" + raw.trim();
      }
    }
    return (
      `<div class="watson-text">${esc(all[0])}</div><ul class="watson-auto-list">` +
      items
        .map((i) => `<li>${esc(i.line)}${i.vql && i.vql.length ? `<pre class="watson-pre">${esc(i.vql.join("\n"))}</pre>` : ""}</li>`)
        .join("") +
      `</ul>`
    );
  }

  const currentCase = () => String((document.getElementById("caseId") || {}).value || "").trim();

  function showError(el, text) {
    const host = el.parentElement;
    if (!host || !document.createElement) return;
    let msg = host.querySelector(".watson-undo-msg");
    if (!msg) {
      msg = document.createElement("span");
      msg.className = "watson-undo-msg";
      msg.setAttribute("role", "alert");
      host.appendChild(msg);
    }
    msg.textContent = text; // textContent: the server message is never markup
  }

  // "Mark as launched" / "Try again" on an uncertain launch.
  async function watsonVeloResolve(el) {
    const caseId = currentCase();
    const outcome = el.dataset.outcome;
    if (!caseId || (outcome !== "launched" && outcome !== "retry")) return;
    try {
      const r = await fetch(
        `/cases/${encodeURIComponent(caseId)}/watson/proposals/${encodeURIComponent(el.dataset.pid)}/resolve`,
        { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ outcome }) },
      );
      const body = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(body.error ? String(body.error) : "HTTP " + r.status);
      if (caseId === currentCase() && body.chat && typeof renderWatson === "function") renderWatson(body.chat);
    } catch (e) {
      showError(el, "Could not update the launch: " + (e && e.message ? e.message : "network error"));
    }
  }

  function watsonVeloChipSync(chat) {
    if (typeof document === "undefined" || !document.querySelectorAll) return;
    const html = chipHtml(!!(chat && chat.veloConnected));
    document.querySelectorAll('[data-w="velo"]').forEach((el) => { el.innerHTML = html; });
  }

  window.watsonVeloCardHtml = veloCardHtml;
  window.watsonVeloAutoListHtml = autoListHtml;
  window.watsonVeloResolve = watsonVeloResolve;
  window.watsonVeloChipSync = watsonVeloChipSync;
})();
