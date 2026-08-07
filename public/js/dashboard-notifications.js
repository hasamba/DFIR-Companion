// Notifications (#58) — Slack / Teams / Mattermost / SMTP channels, configured in Settings —
// extracted from dashboard.html (issue #415, tier 3).
//
// This block had ZERO state escapes and sat off my own queue for most of the PR, because I was
// filtering the queue on `sharedMachinery` as if it were a blocker. It is not — it flags a
// function several sections call, which is an argument about what to PUBLISH, not about whether a
// block can move. The one entry here was loadCaseList, and that turned out not to be part of this
// feature at all: it sits below the nine guard stanzas that follow this block, is read by eight
// extracted modules, and is page machinery filed under a Notifications banner. It stays put.
//
// No initializer: nothing here runs at load. loadNotifications() is called when Settings opens.
(function () {
  "use strict";

  let ntfChannels = [];
  const NTF_TYPE_LABEL = {
    slack: "Slack",
    teams: "MS Teams",
    mattermost: "Mattermost",
    discord: "Discord",
    email: "Email",
    telegram: "Telegram",
  };
  const NTF_WEBHOOK_PLACEHOLDER = {
    slack: "https://hooks.slack.com/services/…",
    teams: "https://outlook.office.com/webhook/…  or Power Automate URL",
    mattermost: "https://mattermost.example.com/hooks/…",
    discord: "https://discord.com/api/webhooks/…",
  };
  function ntfTypeChanged() {
    const t = document.getElementById("ntfType").value;
    const email = t === "email";
    const telegram = t === "telegram";
    document.getElementById("ntfWebhookRow").style.display =
      email || telegram ? "none" : "";
    document.getElementById("ntfSmtpRows").style.display = email ? "" : "none";
    document.getElementById("ntfTelegramRows").style.display = telegram
      ? ""
      : "none";
    if (!email && !telegram) {
      document.getElementById("ntfWebhookUrl").placeholder =
        NTF_WEBHOOK_PLACEHOLDER[t] || NTF_WEBHOOK_PLACEHOLDER.slack;
    }
  }
  function renderNotifications(channels) {
    ntfChannels = channels || [];
    const el = document.getElementById("ntfList");
    const cnt = document.getElementById("ntfCount");
    if (cnt)
      cnt.textContent = ntfChannels.length ? `(${ntfChannels.length})` : "";
    if (!el) return;
    if (!ntfChannels.length) {
      el.innerHTML =
        "<div data-safe-style='color:var(--text-muted);font-size:12px;padding:4px'>No channels yet — add one above. Notifications are off until you do.</div>";
      return;
    }
    el.innerHTML = ntfChannels
      .map((ch) => {
        const dim = ch.enabled ? "" : "opacity:.55;";
        return (
          `<div data-safe-style="border-bottom:1px solid var(--border-subtle);padding:6px 2px;font-size:12px;${dim}">` +
          `<div data-safe-style="display:flex;align-items:center;gap:8px">` +
          `<span data-safe-style="color:var(--accent);flex:0 0 auto;font-weight:600">${esc(NTF_TYPE_LABEL[ch.type] || ch.type)}</span>` +
          `<span data-safe-style="flex:1;word-break:break-all">${esc(ch.name || "(unnamed)")}</span>` +
          `<label data-safe-style="display:flex;align-items:center;gap:4px;color:var(--text-muted)"><input type="checkbox" class="ntf-toggle" data-id="${escAttr(ch.id)}" ${ch.enabled ? "checked" : ""}/> on</label>` +
          `<button class="ntf-test" data-id="${escAttr(ch.id)}" type="button" data-safe-style="background:var(--border-color);border:1px solid var(--border-strong);color:var(--text-primary);border-radius:5px;padding:1px 8px;cursor:pointer">Test</button>` +
          `<button class="ntf-del" data-id="${escAttr(ch.id)}" title="Delete channel" data-safe-style="background:transparent;border:1px solid var(--danger-border);color:var(--tag-red-text);border-radius:5px;padding:1px 7px;cursor:pointer">✕</button>` +
          `</div>` +
          `<div data-safe-style="color:var(--text-dim);margin-top:2px">≥ ${esc(ch.minSeverity)} · on: ${esc(ntfEventsSummary(ch.events))} · ${ntfTargetSummary(ch)}</div>` +
          `</div>`
        );
      })
      .join("");
  }
  function loadNotifications() {
    fetch("/notifications")
      .then((r) => r.json())
      .then(renderNotifications)
      .catch(() => {});
  }
  function ntfAddChannel() {
    const type = document.getElementById("ntfType").value;
    const msg = document.getElementById("ntfMsg");
    const body = {
      type,
      name: document.getElementById("ntfName").value.trim(),
      enabled: document.getElementById("ntfEnabled").checked,
      minSeverity: document.getElementById("ntfMinSeverity").value,
      events: {
        critical_finding: document.getElementById("ntfEvtFinding").checked,
        playbook_update: document.getElementById("ntfEvtPlaybook").checked,
        milestone: document.getElementById("ntfEvtMilestone").checked,
        mention: document.getElementById("ntfEvtMention").checked,
      },
    };
    if (type === "email") {
      body.smtp = {
        host: document.getElementById("ntfSmtpHost").value.trim(),
        port: Number(document.getElementById("ntfSmtpPort").value) || 587,
        secure: document.getElementById("ntfSmtpSecure").checked,
        username: document.getElementById("ntfSmtpUser").value.trim(),
        password: document.getElementById("ntfSmtpPass").value,
        from: document.getElementById("ntfSmtpFrom").value.trim(),
        to: document.getElementById("ntfSmtpTo").value.trim(),
      };
    } else if (type === "telegram") {
      body.telegram = {
        botToken: document.getElementById("ntfTgToken").value,
        chatId: document.getElementById("ntfTgChatId").value.trim(),
      };
    } else {
      body.webhookUrl = document.getElementById("ntfWebhookUrl").value.trim();
    }
    msg.textContent = "adding…";
    fetch("/notifications", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    })
      .then(async (r) => {
        if (!r.ok)
          throw new Error(
            (await r.json().catch(() => ({}))).error || "HTTP " + r.status,
          );
        return r.json();
      })
      .then(() => {
        msg.textContent = "";
        document.getElementById("ntfName").value = "";
        document.getElementById("ntfWebhookUrl").value = "";
        [
          "ntfSmtpHost",
          "ntfSmtpUser",
          "ntfSmtpPass",
          "ntfSmtpFrom",
          "ntfSmtpTo",
        ].forEach((id) => {
          document.getElementById(id).value = "";
        });
        ["ntfTgToken", "ntfTgChatId"].forEach((id) => {
          document.getElementById(id).value = "";
        });
        loadNotifications();
      })
      .catch((e) => {
        msg.textContent = e.message;
      });
  }
  function ntfTest(id) {
    const msg = document.getElementById("ntfMsg");
    msg.textContent = "sending test…";
    fetch("/notifications/test", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ channelId: id }),
    })
      .then(async (r) => {
        if (!r.ok)
          throw new Error(
            (await r.json().catch(() => ({}))).error || "HTTP " + r.status,
          );
        return r.json();
      })
      .then((j) => {
        const r = (j.results || [])[0];
        msg.textContent =
          r && r.ok ? "✓ test sent" : "✗ " + ((r && r.error) || "failed");
      })
      .catch((e) => {
        msg.textContent = e.message;
      });
  }
  function ntfToggle(id, enabled) {
    const ch = ntfChannels.find((c) => c.id === id);
    if (!ch) return;
    const body = ntfChannelToBody(ch);
    body.enabled = enabled;
    fetch(`/notifications/${id}`, {
      method: "PUT",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    })
      .then((r) => {
        if (r.ok) loadNotifications();
      })
      .catch(() => {});
  }

  // Its own two controls, which had been left in the page's wiring block. They are read at LOAD
  // there, so with this module extracted a 404 would have thrown before anything could report it.
  function initNotifications() {
    document
      .getElementById("ntfType")
      .addEventListener("change", ntfTypeChanged);
    document
      .getElementById("ntfAddBtn")
      .addEventListener("click", ntfAddChannel);
  }

  window.initNotifications = initNotifications;
  window.loadNotifications = loadNotifications;
  window.ntfAddChannel = ntfAddChannel;
  window.ntfTest = ntfTest;
  window.ntfToggle = ntfToggle;
  window.ntfTypeChanged = ntfTypeChanged;
})();
