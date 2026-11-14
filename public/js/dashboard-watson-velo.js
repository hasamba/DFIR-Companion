// Watson's Velociraptor pieces: the launch card (velo_launch proposals), the "Velociraptor connected"
// chip, and the Auto listing turn drawn as a list. Pure HTML builders except watsonVeloResolve, which
// posts the analyst's answer for an uncertain launch. dashboard-watson-cards.js calls the card builder.
//
// A risky launch (Task 9) carries a red warning; its Approve is a two-step inline confirmation
// (never confirm(): a browser modal blocks automation) that posts acceptRisk:true.
//
// Every model and evidence string (title, VQL, host, ids, names, error text) goes through
// esc()/escAttr() (dashboard-escape.js). Actions ride on data-act="watsonAct" + data-w-verb.
(function () {
  const AUTO_HEADS = ["Watson acted on its own (Auto mode", "(Watson's Auto actions, continued)"];
  const UNCERTAIN =
    "Watson cannot tell whether this ran. Check Velociraptor, then mark it launched or try again.";
  const NO_UNDO = "A launched hunt cannot be undone: it already ran on the endpoints.";
  const NO_IDS =
    "Marked as launched. Watson does not know this run's id and will not read its result; import it from Velociraptor.";
  const STALLED =
    "This launch was interrupted before Watson saved its outcome. Check Velociraptor, then mark it launched or try again.";

  const RISK_TAIL = ". Watson's safety check would normally block this. Read the query before approving.";
  // Risky cards whose second confirmation is on screen (by proposal id); cleared on a case switch.
  const wRiskArmed = new Set();
  // Risky launches whose "Yes, launch it" request is in flight: the button stays disabled (M-5).
  const wRiskSending = new Set();

  const num = (n) => esc(String(Number(n) || 0));
  const rowsText = (n) => `${num(n)} row${Number(n) === 1 ? "" : "s"}`;

  // A friendly local time with the exact ISO value in the title; an unparseable value is shown as is.
  function timeHtml(iso) {
    const raw = String(iso || "");
    if (!raw || isNaN(Date.parse(raw))) return esc(raw);
    const fmt = typeof window !== "undefined" && window.DfirTime && window.DfirTime.fmtDateTime;
    const shown = fmt ? fmt(raw) : new Date(raw).toLocaleString();
    return `<span title="${escAttr(raw)}">${esc(shown)}</span>`;
  }

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

  // A launch "marked as launched" by an analyst has no ids: Watson never reads its result (G8).
  const hasIds = (l) => !!(l && (l.huntId || l.flowId));

  const where = (p) =>
    p.mode === "hunt" ? "Fleet-wide hunt — all enrolled clients" : `Collection on ${esc(p.hostname || "a host")}`;

  const btn = (pid, verb, label, extra) =>
    `<button type="button" class="watson-mini" data-act="watsonAct" data-w-verb="${verb}" data-pid="${escAttr(pid)}"${extra || ""}>${label}</button> `;

  // Risky is decided by the stored risk field, never by how many reasons it lists (M-4).
  const isRisky = (p) => !!p.risk && typeof p.risk === "object";
  const riskReasons = (p) => (p.risk && Array.isArray(p.risk.reasons) ? p.risk.reasons.map(String) : []);

  function riskHtml(p) {
    if (!isRisky(p) || p.status === "applied" || p.status === "rejected") return "";
    const reasons = riskReasons(p).join("; ") || "Watson did not record why";
    return `<div class="watson-why watson-risk" role="alert">${esc(`Risky query — ${reasons}${RISK_TAIL}`)}</div>`;
  }

  function acceptedHtml(l) {
    const r = l && l.riskAccepted;
    if (!r) return "";
    const why = Array.isArray(r.reasons) ? r.reasons.map(String).join("; ") : "";
    return `<div class="watson-why watson-risk">${esc(`Approved by ${r.by || "an analyst"} despite the warning: ${why}`)}</div>`;
  }

  function bodyFor(p) {
    const lines = [riskHtml(p)];
    if (p.status === "launching" && p.stalled) lines.push(`<div class="watson-why watson-warn">${esc(STALLED)}</div>`);
    else if (p.status === "launching") lines.push(`<div class="watson-why">Launching…</div>`);
    if (p.status === "applied") {
      const l = p.launched || {};
      lines.push(
        `<div class="watson-why">Launched by ${esc(l.by || p.appliedBy || "an analyst")} at ${timeHtml(l.at || p.appliedAt)}</div>`,
        acceptedHtml(l),
        `<div class="watson-why" data-w-status="launch">${hasIds(l) ? statusLine(p.watch) : esc(NO_IDS)}</div>`,
        `<div class="watson-why">${esc(NO_UNDO)}</div>`,
      );
    }
    if (p.status === "uncertain") lines.push(`<div class="watson-why watson-warn">${esc(UNCERTAIN)}</div>`);
    return lines.join("");
  }

  function riskConfirmHtml(p) {
    return (
      `<div class="watson-risk-confirm" role="group" aria-label="Confirm launching a risky query">` +
      `<div class="watson-why">Launch this risky query? You have read it and accept the risk.</div>` +
      btn(p.id, "applyRisk", "Yes, launch it", wRiskSending.has(p.id) ? " disabled" : "") +
      btn(p.id, "riskCancel", "Cancel") + `</div>`
    );
  }

  function verbsFor(p) {
    if (p.status !== "pending") wRiskArmed.delete(p.id); // a relaunch confirms twice again (M-7)
    if (p.status === "pending" && isRisky(p))
      return wRiskArmed.has(p.id) ? riskConfirmHtml(p) : btn(p.id, "riskArm", "Review risk and launch…") + btn(p.id, "reject", "Reject");
    if (p.status === "pending") return btn(p.id, "apply", "Launch") + btn(p.id, "reject", "Reject");
    if (p.status === "uncertain" || (p.status === "launching" && p.stalled))
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

  // The Auto listing. Its text shape is written by listingTurns in
  // companion/src/analysis/ai/watson/autoApply.ts; watsonVeloCards.test.ts feeds this parser the real
  // output, so a wording change there breaks a test. "- line" items, each maybe followed by "  VQL:" and the query. "" for any other turn.
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

  const rerender = () => { if (typeof renderWatson === "function") renderWatson(); };
  function watsonVeloRiskArm(el) { wRiskArmed.add(String(el.dataset.pid)); rerender(); }
  function watsonVeloRiskCancel(el) { wRiskArmed.delete(String(el.dataset.pid)); rerender(); }

  // The second confirmation's "Yes": the only path that sends acceptRisk (Task 9).
  async function watsonVeloApplyRisk(el) {
    const caseId = currentCase();
    const pid = String(el.dataset.pid || "");
    if (!caseId || !pid || wRiskSending.has(pid)) return; // one request at a time (M-5)
    wRiskSending.add(pid);
    el.disabled = true;
    try {
      const r = await fetch(
        `/cases/${encodeURIComponent(caseId)}/watson/proposals/${encodeURIComponent(pid)}/apply`,
        { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ acceptRisk: true }) },
      );
      const body = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(body.error ? String(body.error) : "HTTP " + r.status);
      el.disabled = false;
      if (caseId === currentCase() && body.chat && typeof renderWatson === "function") renderWatson(body.chat);
    } catch (e) {
      showError(el, "Could not launch: " + (e && e.message ? e.message : "network error"));
    } finally {
      // Whatever the outcome, a further launch of this card asks for the second confirmation again (M-7).
      // A refused click's button stays disabled (its message stays beside it) until the next render,
      // which draws "Review risk and launch…" again.
      wRiskSending.delete(pid);
      wRiskArmed.delete(pid);
    }
  }

  // Only a GET carries veloConnected; the replies to a proposal POST do not, so they leave it be.
  let wVeloConnected = false;

  function watsonVeloChipSync(chat) {
    if (chat && typeof chat.veloConnected === "boolean") wVeloConnected = chat.veloConnected;
    if (typeof document === "undefined" || !document.querySelectorAll) return;
    const html = chipHtml(wVeloConnected);
    document.querySelectorAll('[data-w="velo"]').forEach((el) => { el.innerHTML = html; });
  }

  window.watsonVeloCardHtml = veloCardHtml;
  window.watsonVeloAutoListHtml = autoListHtml;
  window.watsonVeloResolve = watsonVeloResolve;
  window.watsonVeloChipSync = watsonVeloChipSync;
  window.watsonVeloRiskArm = watsonVeloRiskArm;
  window.watsonVeloRiskCancel = watsonVeloRiskCancel;
  window.watsonVeloApplyRisk = watsonVeloApplyRisk;
  // A case switch: no chip and Approve shown until the new case's GET says otherwise (G15, G19).
  window.watsonCaseReset = () => {
    wRiskArmed.clear();
    wRiskSending.clear();
    watsonVeloChipSync({ veloConnected: false });
    if (typeof watsonModeSync === "function") watsonModeSync({ runMode: "approve" });
  };
})();
