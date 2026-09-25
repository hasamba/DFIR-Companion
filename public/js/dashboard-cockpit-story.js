// "Story so far" in the Now cockpit (#1487, #1493) — the rendering half of dashboard-cockpit.js.
//
// The stage cards, the shape strip, the missing-stage placeholders, the prose and the plain-text
// brief. Split out when #1493 pushed the cockpit past 650 lines; the click handlers stay in
// dashboard-cockpit.js with the panel table they route through, and call nothing here. This
// module publishes two names: cockpitStoryHtml (called by renderCockpit at paint time) and
// cockpitStoryCopy (the "Copy as brief" button, dispatched through data-act). It reads
// `lastCockpit` — the page's snapshot cell — at call time only.
(function () {
  "use strict";

  // The attack chain as one card per stage, above the workspaces row. The server derives it from
  // the forensic timeline only (never the super-timeline) and trims the synthesis prose to two
  // sentences; the client formats and escapes, nothing more.
  const STORY_EMPTY_CHAIN =
    "No staged activity yet — import evidence to build the chain.";
  const STORY_EMPTY_TEXT =
    "No synthesis yet — the conclusion appears after the first analysis run.";
  // Kill-chain order, mirrored from the server's STORY_STAGE_ORDER so a missing-stage card can sit
  // in its slot among the real ones (#1493). cockpitStory.test.ts pins the two lists together.
  const STORY_STAGE_ORDER = [
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
  ];

  function storyMs(iso) {
    const t = Date.parse(iso);
    return Number.isFinite(t) ? t : null;
  }

  function storyStageMs(stage) {
    return storyMs(stage && stage.firstSeenAt);
  }

  // `HH:MM` while every stage sits on one UTC day, `MM-DD HH:MM` once the chain spans days. Always
  // UTC — the timeline is UTC, and a card that disagrees with the row it filters to is a trap.
  function storyStageTime(ms, withDay) {
    if (ms === null) return "—";
    const iso = new Date(ms).toISOString();
    const clock = iso.slice(11, 16);
    return withDay ? `${iso.slice(5, 10)} ${clock}` : clock;
  }

  // Every stamp the story shows — the cards' first-seen and the shape's span — decides the day
  // rule together, so the strip and the cards never disagree on whether to name the day.
  function storyWithDay(story) {
    const shape = story.shape || {};
    const days = new Set(
      [
        ...(story.stages || []).map(storyStageMs),
        storyMs(shape.firstAt),
        storyMs(shape.lastAt),
      ]
        .filter((ms) => ms !== null)
        .map((ms) => new Date(ms).toISOString().slice(0, 10)),
    );
    return days.size > 1;
  }

  const MINUTE_MS = 60 * 1000;
  const HOUR_MS = 60 * MINUTE_MS;
  const DAY_MS = 24 * HOUR_MS;

  // `4d 14h` past a day, `3h 5m` past an hour, else `12m`. Coarse on purpose: dwell is a shape
  // fact, and the cards carry the exact stamps.
  function storyDwell(ms) {
    if (!Number.isFinite(ms) || ms < 0) return null;
    const days = Math.floor(ms / DAY_MS);
    const hours = Math.floor((ms % DAY_MS) / HOUR_MS);
    const mins = Math.floor((ms % HOUR_MS) / MINUTE_MS);
    if (days >= 1) return `${days}d ${hours}h`;
    if (hours >= 1) return `${hours}h ${mins}m`;
    return `${mins}m`;
  }

  // "(+N)" is the overflow past the server's cap, so the strip stays one line.
  function storyShapeList(items, total, joiner) {
    const more = total > items.length ? ` (+${total - items.length})` : "";
    return items.map((item) => `<b>${esc(item)}</b>`).join(joiner) + more;
  }

  // Span → dwell, then the hosts in first-touch order and the accounts. Each item is omitted
  // when it has nothing to say; the whole strip goes when the shape has no first stamp.
  function storyShapeHtml(story, withDay) {
    const shape = story.shape;
    if (!shape || !shape.firstAt) return "";
    const first = storyStageTime(storyMs(shape.firstAt), withDay);
    const last = storyStageTime(storyMs(shape.lastAt), withDay);
    const dwell = storyDwell(shape.dwellMs);
    const hosts = shape.hosts || [];
    const accounts = shape.accounts || [];
    const items = [
      `<b>${esc(first)}</b> → <b>${esc(last)}</b>` +
        (dwell ? ` · dwell <b>${esc(dwell)}</b>` : ""),
    ];
    if (hosts.length)
      items.push(
        `hosts ${storyShapeList(hosts, shape.hostsTotal || 0, " → ")}`,
      );
    if (accounts.length)
      items.push(
        `accounts ${storyShapeList(accounts, shape.accountsTotal || 0, ", ")}`,
      );
    return `<div class="now-story-shape">${items
      .map((item) => `<span class="now-shape-item">${item}</span>`)
      .join("")}</div>`;
  }

  function storyFreshness(story) {
    if (!story.synthesizedAt) return { text: "no synthesis yet", stale: false };
    const n = story.staleEventCount || 0;
    if (n > 0)
      return {
        text: `stale — ${n} event${n === 1 ? "" : "s"} since synthesis`,
        stale: true,
      };
    // #1599: a dismissed finding or a new scope window adds no rows, so the count above cannot
    // see it — the server's out-of-date marker can.
    if (story.conclusionsOutOfDate)
      return { text: "stale — conclusions out of date", stale: true };
    return {
      text: `synthesis ${cockpitAge(story.synthesizedAt)}`,
      stale: false,
    };
  }

  function storyStageWhen(stage, withDay) {
    const when = storyStageTime(storyStageMs(stage), withDay);
    return stage.host ? `${when} · ${stage.host}` : when;
  }

  // The stage's top finding, or the "no finding yet" row so every card keeps the same height.
  // `.now-sev` leans on the page-wide `.sev-<Severity>` colour rule the Findings panel uses.
  function storyFindingHtml(finding) {
    if (!finding)
      return `<div class="now-stage-finding now-stage-nofinding">no finding yet</div>`;
    return (
      `<div class="now-stage-finding">` +
      `<span class="now-sev sev-${escAttr(finding.severity)}">${esc(finding.severity)}</span>` +
      `<button data-act="cockpitStoryFinding" data-id="${escAttr(finding.id)}">${esc(finding.title)}</button></div>`
    );
  }

  // One card per stage: name and count both open the stage's events, the top border carries the
  // worst severity, the headline is the stage's most severe event (CSS clamps it to two lines).
  function storyStageHtml(stage, withDay) {
    const open = `data-act="cockpitStoryStage" data-tactic="${escAttr(stage.tactic)}"`;
    const sev = stage.worstSeverity
      ? ` sev-${escAttr(stage.worstSeverity)}`
      : "";
    const headline = stage.headline
      ? `<div class="now-stage-headline">${esc(stage.headline.description)}</div>`
      : "";
    return (
      `<div class="now-stage-card${sev}"><div class="now-stage-card-head">` +
      `<button ${open} class="now-stage-name">${esc(stage.tactic)}</button>` +
      `<button ${open} class="now-stage-count">${esc(String(stage.eventCount || 0))} ev ›</button></div>` +
      `<div class="now-stage-when">${esc(storyStageWhen(stage, withDay))}</div>` +
      `${headline}${storyFindingHtml(stage.finding)}</div>`
    );
  }

  // A stage with no evidence: a dashed placeholder in its kill-chain slot that points at the
  // Evidence Gaps panel, which says where to collect for it.
  function storyMissingHtml(tactic) {
    return (
      `<div class="now-stage-card now-stage-missing"><div class="now-stage-card-head">` +
      `<span class="now-stage-name">${esc(tactic)}</span></div>` +
      `<div class="now-stage-nofinding">no evidence yet · ` +
      `<button data-act="cockpitStoryOpen" data-panel="evidence-gaps">Evidence gaps ↗</button></div></div>`
    );
  }

  // Real and missing stages interleaved in kill-chain order, so a gap shows where it sits in the
  // chain. A tactic the client does not know sorts last, in the server's order (the sort is stable).
  function storyOrderedCards(stages, missing) {
    const rank = (tactic) => {
      const i = STORY_STAGE_ORDER.indexOf(tactic);
      return i === -1 ? STORY_STAGE_ORDER.length : i;
    };
    return [
      ...stages.map((stage) => ({ tactic: stage.tactic, stage })),
      ...missing.map((tactic) => ({ tactic, stage: null })),
    ].sort((a, b) => rank(a.tactic) - rank(b.tactic));
  }

  // The grid wraps, so no arrows join the cards. With no real stage at all the empty hint stands
  // alone — twelve dashed placeholders would say nothing the hint does not.
  function storyCardsHtml(story, withDay) {
    const stages = story.stages || [];
    if (!stages.length)
      return `<div class="now-empty">${esc(STORY_EMPTY_CHAIN)}</div>`;
    const cards = storyOrderedCards(stages, story.missingStages || []);
    return `<div class="now-story-cards">${cards
      .map((card) =>
        card.stage
          ? storyStageHtml(card.stage, withDay)
          : storyMissingHtml(card.tactic),
      )
      .join("")}</div>`;
  }

  function storyTextHtml(story) {
    if (!story.synthesizedAt)
      return `<div class="now-empty">${esc(STORY_EMPTY_TEXT)}</div>`;
    const conclusion = story.conclusion
      ? `<p>${esc(story.conclusion)}</p>`
      : "";
    const path = story.attackerPath ? `${esc(story.attackerPath)} ` : "";
    return (
      `<div class="now-story-text">${conclusion}<p>${path}` +
      `<button data-act="cockpitStoryOpen" data-panel="attack-path">Full path ↗</button> ` +
      `<button data-act="cockpitStoryOpen" data-panel="summary">Executive summary ↗</button></p></div>`
    );
  }

  // Empty string on an old server whose snapshot has no `story`, so the rest of the cockpit still
  // paints. A story without `shape`/`missingStages` (a server older than #1493) paints without
  // the strip and without placeholders.
  function cockpitStoryHtml(story) {
    if (!story) return "";
    const fresh = storyFreshness(story);
    const freshClass = fresh.stale
      ? "now-story-fresh now-story-stale"
      : "now-story-fresh";
    const withDay = storyWithDay(story);
    return (
      `<div class="now-story"><div class="now-story-head">Story so far ` +
      `<span class="${freshClass}">${esc(fresh.text)}</span>` +
      `<button data-act="cockpitStoryCopy" class="now-story-copy">⧉ Copy as brief</button>` +
      `<span class="now-story-copy-msg"></span></div>` +
      `${storyShapeHtml(story, withDay)}${storyCardsHtml(story, withDay)}${storyTextHtml(story)}</div>`
    );
  }

  // ---- Copy as brief (#1493) ----
  // Plain text for a chat, a ticket or a hand-over: header, span line, one numbered entry per
  // stage, the stages with no evidence, then the two prose lines. Raw strings — it is not HTML.
  function briefTime(iso) {
    const ms = storyMs(iso);
    if (ms === null) return "?";
    return new Date(ms).toISOString().slice(0, 16).replace("T", " ");
  }

  function briefHeader(caseId, story) {
    const parts = [
      `synthesis ${story.synthesizedAt ? `${briefTime(story.synthesizedAt)} UTC` : "none"}`,
    ];
    const fresh = storyFreshness(story);
    if (fresh.stale) parts.push(fresh.text);
    return `Story so far — ${caseId} (${parts.join("; ")})`;
  }

  function briefList(items, total, joiner) {
    const more = total > items.length ? ` (+${total - items.length})` : "";
    return items.join(joiner) + more;
  }

  function briefSpan(shape) {
    if (!shape || !shape.firstAt) return "";
    const dwell = storyDwell(shape.dwellMs);
    const hosts = shape.hosts || [];
    const accounts = shape.accounts || [];
    const parts = [
      `Span: ${briefTime(shape.firstAt)} → ${briefTime(shape.lastAt)} UTC` +
        (dwell ? ` (dwell ${dwell})` : ""),
    ];
    if (hosts.length)
      parts.push(`hosts: ${briefList(hosts, shape.hostsTotal || 0, " → ")}`);
    if (accounts.length)
      parts.push(
        `accounts: ${briefList(accounts, shape.accountsTotal || 0, ", ")}`,
      );
    return parts.join(" · ");
  }

  function briefStage(stage, n) {
    const count = stage.eventCount || 0;
    const head = [`${briefTime(stage.firstSeenAt)} UTC`];
    if (stage.host) head.push(stage.host);
    head.push(`${count} event${count === 1 ? "" : "s"}`);
    const lines = [`${n}. ${stage.tactic} — ${head.join(" · ")}`];
    if (stage.headline) lines.push(`   Event: ${stage.headline.description}`);
    if (stage.finding)
      lines.push(
        `   Finding: [${stage.finding.severity}] ${stage.finding.title}`,
      );
    return lines.join("\n");
  }

  function briefStages(story) {
    const stages = story.stages || [];
    if (!stages.length) return STORY_EMPTY_CHAIN;
    const lines = stages.map((stage, i) => briefStage(stage, i + 1));
    const missing = story.missingStages || [];
    if (missing.length) lines.push(`No evidence yet: ${missing.join(", ")}`);
    return lines.join("\n");
  }

  function storyBriefText(caseId, story) {
    const top = [briefHeader(caseId, story), briefSpan(story.shape)];
    const prose = [];
    if (story.conclusion) prose.push(`Conclusion: ${story.conclusion}`);
    if (story.attackerPath) prose.push(`Attacker path: ${story.attackerPath}`);
    return [
      top.filter(Boolean).join("\n"),
      briefStages(story),
      prose.join("\n"),
    ]
      .filter(Boolean)
      .join("\n\n");
  }

  // Clipboard API first; the textarea/execCommand path is for a page served without a secure
  // context, where navigator.clipboard is undefined (same pattern as diagCopyToClipboard).
  function copyPlainText(text) {
    if (navigator.clipboard && navigator.clipboard.writeText)
      return navigator.clipboard.writeText(text);
    return new Promise((resolve, reject) => {
      try {
        const ta = document.createElement("textarea");
        ta.value = text;
        document.body.appendChild(ta);
        ta.select();
        const ok = document.execCommand("copy");
        ta.remove();
        if (!ok) throw new Error("execCommand copy refused");
        resolve();
      } catch (err) {
        reject(err);
      }
    });
  }

  const STORY_COPY_MSG_MS = 2000;

  async function cockpitStoryCopy(el) {
    const story = lastCockpit && lastCockpit.story;
    if (!story) return;
    const msg = el && el.nextElementSibling;
    const say = (text) => {
      if (msg) msg.textContent = text;
    };
    try {
      await copyPlainText(storyBriefText(lastCockpit.caseId, story));
      say("copied");
    } catch {
      say("copy failed — select & copy manually");
    }
    setTimeout(() => say(""), STORY_COPY_MSG_MS);
  }

  window.cockpitStoryCopy = cockpitStoryCopy;
  window.cockpitStoryHtml = cockpitStoryHtml;
})();
