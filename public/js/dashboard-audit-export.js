// SIEM audit export (#929) — the Settings pane that manages where the per-case activity log is
// forwarded. Mirrors dashboard-notifications.js: no initializer work at load, the list is fetched
// when the Settings tab opens, and no credential is ever rendered because the API never sends one.
(function () {
  "use strict";

  let axDestinations = [];

  const AX_TYPE_LABEL = {
    splunk: "Splunk HEC",
    elastic: "Elasticsearch",
    syslog: "Syslog",
  };

  // Which config rows a type needs. Shown/hidden together so a half-filled form for another
  // product can never be submitted.
  function axTypeChanged() {
    const t = document.getElementById("axType").value;
    document.getElementById("axSplunkRows").style.display = t === "splunk" ? "" : "none";
    document.getElementById("axElasticRows").style.display = t === "elastic" ? "" : "none";
    document.getElementById("axSyslogRows").style.display = t === "syslog" ? "" : "none";
  }

  // What the destination is actually pointed at, with no secret in it.
  function axTargetSummary(d) {
    if (d.type === "splunk" && d.splunk) {
      const extra = [d.splunk.index && `index ${d.splunk.index}`, d.splunk.sourcetype]
        .filter(Boolean)
        .join(" · ");
      return `${esc(d.splunk.url)}${extra ? ` · ${esc(extra)}` : ""}${d.splunk.hasToken ? "" : " · no token"}`;
    }
    if (d.type === "elastic" && d.elastic) {
      const auth = d.elastic.hasApiKey ? "API key" : d.elastic.hasPassword ? "password" : "no credential";
      return `${esc(d.elastic.url)} · index ${esc(d.elastic.index)} · ${esc(auth)}`;
    }
    if (d.type === "syslog" && d.syslog) {
      return `${esc(d.syslog.host)}:${esc(String(d.syslog.port))} ${esc(d.syslog.protocol.toUpperCase())}`;
    }
    return "not configured";
  }

  // The delivery record this process has seen. Deliberately says "nothing sent yet" rather than
  // showing a hopeful blank: a feed an operator believes is running but is not is the worst state.
  function axStatusSummary(s) {
    if (!s) return "nothing sent yet";
    const parts = [];
    if (s.sentTotal) parts.push(`${s.sentTotal} record(s) forwarded`);
    if (s.lastSuccessAt) parts.push(`last ok ${esc(String(s.lastSuccessAt).replace("T", " ").slice(0, 19))}`);
    if (s.lastError) parts.push(`⚠ ${esc(s.lastError)}`);
    if (!parts.length) parts.push(s.lastAttemptAt ? "attempted, nothing to send" : "nothing sent yet");
    return parts.join(" · ");
  }

  function renderAuditExport(payload) {
    axDestinations = (payload && payload.destinations) || [];
    const el = document.getElementById("axList");
    const cnt = document.getElementById("axCount");
    if (cnt) cnt.textContent = axDestinations.length ? `(${axDestinations.length})` : "";
    if (!el) return;
    if (!axDestinations.length) {
      el.innerHTML =
        "<div data-safe-style='color:var(--text-muted);font-size:12px;padding:4px'>No destinations yet — add one above. Nothing is forwarded until you do.</div>";
      return;
    }
    el.innerHTML = axDestinations
      .map((d) => {
        const dim = d.enabled ? "" : "opacity:.55;";
        return (
          `<div data-safe-style="border-bottom:1px solid var(--border-subtle);padding:6px 2px;font-size:12px;${dim}">` +
          `<div data-safe-style="display:flex;align-items:center;gap:8px">` +
          `<span data-safe-style="color:var(--accent);flex:0 0 auto;font-weight:600">${esc(AX_TYPE_LABEL[d.type] || d.type)}</span>` +
          `<span data-safe-style="flex:1;word-break:break-all">${esc(d.name || "(unnamed)")}</span>` +
          `<label data-safe-style="display:flex;align-items:center;gap:4px;color:var(--text-muted)"><input type="checkbox" class="ax-toggle" data-id="${escAttr(d.id)}" ${d.enabled ? "checked" : ""}/> on</label>` +
          `<button class="ax-test" data-id="${escAttr(d.id)}" type="button" data-safe-style="background:var(--border-color);border:1px solid var(--border-strong);color:var(--text-primary);border-radius:5px;padding:1px 8px;cursor:pointer">Test</button>` +
          `<button class="ax-backfill" data-id="${escAttr(d.id)}" type="button" title="Re-send every case's activity history to this destination" data-safe-style="background:var(--border-color);border:1px solid var(--border-strong);color:var(--text-primary);border-radius:5px;padding:1px 8px;cursor:pointer">Send history</button>` +
          `<button class="ax-del" data-id="${escAttr(d.id)}" title="Remove destination" type="button" data-safe-style="background:transparent;border:1px solid var(--danger-border);color:var(--tag-red-text);border-radius:5px;padding:1px 7px;cursor:pointer">✕</button>` +
          `</div>` +
          `<div data-safe-style="color:var(--text-dim);margin-top:2px">${axTargetSummary(d)}</div>` +
          `<div data-safe-style="color:var(--text-dim);margin-top:2px">${axStatusSummary(d.status)}</div>` +
          `</div>`
        );
      })
      .join("");
  }

  function loadAuditExport() {
    fetch("/audit-export")
      .then((r) => r.json())
      .then(renderAuditExport)
      .catch(() => {});
  }

  function axMsg(text, ok) {
    const el = document.getElementById("axMsg");
    if (!el) return;
    el.textContent = text;
    el.style.color = ok ? "var(--success-text)" : "var(--tag-red-text)";
  }

  function axVal(id) {
    const el = document.getElementById(id);
    return el ? el.value.trim() : "";
  }

  // Build exactly the block the chosen type needs. Sending the other blocks too would let a
  // half-typed Elasticsearch form survive inside a Splunk destination.
  function axBody() {
    const type = document.getElementById("axType").value;
    const body = {
      type,
      name: axVal("axName"),
      enabled: document.getElementById("axEnabled").checked,
    };
    if (type === "splunk") {
      body.splunk = {
        url: axVal("axSplunkUrl"),
        token: axVal("axSplunkToken"),
        index: axVal("axSplunkIndex"),
        sourcetype: axVal("axSplunkSourcetype"),
      };
    } else if (type === "elastic") {
      body.elastic = {
        url: axVal("axElasticUrl"),
        index: axVal("axElasticIndex"),
        username: axVal("axElasticUser"),
        password: axVal("axElasticPass"),
        apiKey: axVal("axElasticApiKey"),
      };
    } else {
      body.syslog = {
        host: axVal("axSyslogHost"),
        port: Number(axVal("axSyslogPort")) || 514,
        protocol: document.getElementById("axSyslogProtocol").value,
        appName: axVal("axSyslogAppName"),
      };
    }
    return body;
  }

  function axAddDestination() {
    axMsg("adding…", true);
    fetch("/audit-export", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(axBody()),
    })
      .then((r) => r.json().then((j) => ({ ok: r.ok, j })))
      .then(({ ok, j }) => {
        if (!ok) {
          axMsg(j && j.error ? j.error : "could not add destination", false);
          return;
        }
        axMsg("added — press Test to check it before switching it on", true);
        ["axSplunkToken", "axElasticPass", "axElasticApiKey"].forEach((id) => {
          const el = document.getElementById(id);
          if (el) el.value = "";
        });
        loadAuditExport();
      })
      .catch(() => axMsg("could not add destination", false));
  }

  function axTest(id) {
    axMsg("sending a test record…", true);
    fetch("/audit-export/test", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ destinationId: id }),
    })
      .then((r) => r.json())
      .then((j) => {
        const result = j && j.results && j.results[0];
        if (!result) {
          axMsg(j && j.error ? j.error : "no destination to test", false);
          return;
        }
        axMsg(result.ok ? "test record accepted" : `test failed — ${result.error}`, !!result.ok);
        loadAuditExport();
      })
      .catch(() => axMsg("test failed", false));
  }

  // A backfill re-sends every case's whole history, so it asks first. The count it will send is
  // not known until it runs, which is exactly why the confirmation names the scope instead.
  function axBackfill(id) {
    const d = axDestinations.find((x) => x.id === id);
    const label = (d && d.name) || "this destination";
    if (
      !window.confirm(
        `Re-send the FULL activity history of every case to ${label}?\n\nRecords carry their original ids, so a SIEM that honours them will collapse duplicates — but a plain syslog receiver will show every line again.`,
      )
    )
      return;
    axMsg("sending history…", true);
    fetch(`/audit-export/${encodeURIComponent(id)}/backfill`, { method: "POST" })
      .then((r) => r.json().then((j) => ({ ok: r.ok, j })))
      .then(({ ok, j }) => {
        if (!ok) {
          axMsg(j && j.error ? j.error : "backfill failed", false);
          return;
        }
        const failed = (j.failed || []).length;
        axMsg(
          `${j.sent} record(s) across ${j.cases} case(s)` + (failed ? ` — ${failed} case(s) failed` : ""),
          !failed,
        );
        loadAuditExport();
      })
      .catch(() => axMsg("backfill failed", false));
  }

  // Toggling on or off re-sends the destination's own saved config with the new flag. The
  // credential fields go up blank on purpose — the server keeps the stored one for a blank field,
  // and the browser never had the secret to send back.
  function axToggle(id, enabled) {
    const d = axDestinations.find((x) => x.id === id);
    if (!d) return;
    const body = { type: d.type, name: d.name, enabled };
    if (d.type === "splunk" && d.splunk) {
      body.splunk = {
        url: d.splunk.url,
        token: "",
        index: d.splunk.index || "",
        sourcetype: d.splunk.sourcetype || "",
      };
    } else if (d.type === "elastic" && d.elastic) {
      body.elastic = {
        url: d.elastic.url,
        index: d.elastic.index,
        username: d.elastic.username || "",
        password: "",
        apiKey: "",
      };
    } else if (d.syslog) {
      body.syslog = d.syslog;
    }
    fetch(`/audit-export/${encodeURIComponent(id)}`, {
      method: "PUT",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    })
      .then((r) => (r.ok ? { ok: true } : r.json().then((j) => ({ ok: false, j }))))
      .then((out) => {
        // ALWAYS re-read, pass or fail. The checkbox is optimistic — the browser flipped it before
        // the request went — so on a failure it is showing a state the server does not hold. The
        // dangerous direction is OFF: an operator who thinks they stopped forwarding case activity,
        // and has an unticked box agreeing with them, while the destination is still enabled and
        // still sending. Re-reading the list puts the control back to the truth.
        if (!out.ok) {
          axMsg(
            out.j && out.j.error ? out.j.error : "could not change this destination — it is unchanged",
            false,
          );
        }
        loadAuditExport();
      })
      .catch(() => {
        axMsg("could not reach the server — this destination is unchanged", false);
        loadAuditExport();
      });
  }

  // Binds EVERYTHING this feature needs, including its own pane delegation and its own visibility
  // trigger. Notifications leaves those stanzas in dashboard.html's inline script; this feature
  // keeps them here, so the page's only line is the one call below — the inline block is frozen at
  // its recorded size by the file-size ratchet (#384), and every line a feature can own itself is
  // a line it does not have to take from there.
  //
  // Called BY THE PAGE, never by this module: these are <head> scripts, so anything wired at load
  // would query markup that does not exist yet and attach to nothing, silently.
  function initAuditExport() {
    const type = document.getElementById("axType");
    if (type) type.addEventListener("change", axTypeChanged);
    const add = document.getElementById("axAddBtn");
    if (add) add.addEventListener("click", axAddDestination);

    const pane = document.getElementById("stab-auditexport");
    if (pane) {
      pane.addEventListener("click", (e) => {
        const test = e.target.closest(".ax-test");
        if (test) {
          axTest(test.dataset.id);
          return;
        }
        const backfill = e.target.closest(".ax-backfill");
        if (backfill) {
          axBackfill(backfill.dataset.id);
          return;
        }
        const del = e.target.closest(".ax-del");
        if (del) {
          if (!window.confirm("Remove this destination? Forwarding to it stops immediately."))
            return;
          fetch(`/audit-export/${encodeURIComponent(del.dataset.id)}`, { method: "DELETE" })
            .then((r) => {
              if (!r.ok) axMsg("could not remove this destination — it is still configured", false);
              loadAuditExport();
            })
            .catch(() => {
              axMsg("could not reach the server — this destination is still configured", false);
              loadAuditExport();
            });
        }
      });
      pane.addEventListener("change", (e) => {
        const tog = e.target.closest(".ax-toggle");
        if (tog) axToggle(tog.dataset.id, tog.checked);
      });
    }

    // The list is fetched when the pane BECOMES VISIBLE, not when the page loads: a destination
    // list is worth one request when someone looks at it, and none at all on a dashboard that
    // never opens Settings.
    //
    // Watching the pane rather than clicking the tab button is deliberate. A tab-button listener
    // only fires for a click, so it misses openSettingsTab("auditexport") — the deep-link helper
    // that exists precisely because hand-rolled tab clicks land on a hidden tab in Essential mode
    // (tests/settings/settingsEssentialAll.test.ts). The pane's own `active` class is set by every
    // route in, so this covers all of them.
    if (pane) {
      let wasActive = pane.classList.contains("active");
      new MutationObserver(() => {
        const isActive = pane.classList.contains("active");
        if (isActive && !wasActive) {
          axTypeChanged();
          loadAuditExport();
        }
        wasActive = isActive;
      }).observe(pane, { attributes: true, attributeFilter: ["class"] });
    }
  }


  window.initAuditExport = initAuditExport;
  window.loadAuditExport = loadAuditExport;
  window.axTypeChanged = axTypeChanged;
  window.axAddDestination = axAddDestination;
  window.axTest = axTest;
  window.axBackfill = axBackfill;
  window.axToggle = axToggle;
})();
