// Push ingest token (#84) — the per-case token an external collector posts evidence with
// (#415 tier 3).
//
// THE BANNER IS NOT THE BOUNDARY HERE. The "Push ingest token" comment sits in the middle of the
// Velociraptor bundle builder: eleven velo* functions follow it under the same heading and belong
// to the feature above. Only the five push-token functions moved. Extracting to the banner would
// have cut Velociraptor's bundle builder in half.
//
// IIFE-WRAPPED BECAUSE IT OWNS STATE: _pushTokenInfo, the last-loaded token record the renderer
// reads back. This is a CLASSIC script, so unwrapped that `let` would join the shared global
// lexical environment and be reachable from every other script on the page.
//
// ITS WIRING IS AN INITIALIZER. The two buttons were bound by a self-calling wirePushToken() at
// module scope. In a <head> script that runs before #pushTokenGenBtn exists and binds nothing,
// silently — so it becomes a named function the page calls behind a guard, at the point the IIFE
// used to run.
(function () {
  // ── Push ingest token (#84) ───────────────────────────────────────────────────────────────
  let _pushTokenInfo = null; // last-loaded { configured, createdAt, globalConfigured, pushUrl, … }
  // The SERVER never sends the token back on a GET (it is a standing credential for the case; see
  // routes/pushNotify.ts). It is returned exactly once, in the 201 from /generate, so the curl
  // example can only show the real key for the rest of that page's life — a reload falls back to
  // the "<your-token>" placeholder. Held in a closure variable rather than on _pushTokenInfo so a
  // later loadPushToken() refresh does not silently drop it.
  //
  // IT CARRIES ITS OWN IDENTITY, and both halves are load-bearing. As a bare string it survived a
  // switch to another case, so opening case B's settings rendered B's push URL beside A's token —
  // a working credential for A, shown under another case's name and ready to be copied. `createdAt`
  // catches the other way it goes stale: if a second session rotates the token, the GET comes back
  // with a different timestamp and the key we are holding is dead.
  let _justGenerated = null; // { caseId, token, createdAt }
  function loadPushToken(caseId) {
    if (!caseId) {
      renderPushToken(null);
      return;
    }
    fetch(`/cases/${encodeURIComponent(caseId)}/push-token`)
      .then((r) => (r.ok ? r.json() : null))
      .then((info) => renderPushToken(info, caseId))
      .catch(() => renderPushToken(null));
  }
  function renderPushToken(info, caseId) {
    _pushTokenInfo = info;
    const elInfo = document.getElementById("pushTokenInfo");
    const curl = document.getElementById("pushCurl");
    if (!elInfo || !curl) return;
    if (!info) {
      elInfo.textContent = "Connect to a case to manage its push token.";
      curl.textContent = "connect to a case to see the curl example";
      return;
    }
    const parts = [];
    if (info.globalConfigured)
      parts.push(
        "a <strong>global</strong> token (DFIR_PUSH_TOKEN) is set — it covers every case",
      );
    parts.push(
      info.configured
        ? `a <strong>per-case</strong> token is set (created ${info.createdAt ? esc(info.createdAt) : "—"})`
        : "no per-case token",
    );
    if (!info.globalConfigured && !info.configured)
      parts.push("⚠ push is <strong>disabled</strong> until you set one");
    elInfo.innerHTML = parts.join(" · ");
    // Prefer the key we just generated — but only if it belongs to THIS case and is still the one
    // the server holds. Otherwise show a placeholder: `configured` with no secret in hand means a
    // token exists but was generated earlier or elsewhere, and the operator has to re-generate to
    // see one, which is the intended trade (see routes/pushNotify.ts).
    const mine =
      _justGenerated &&
      _justGenerated.caseId === caseId &&
      _justGenerated.createdAt === info.createdAt
        ? _justGenerated.token
        : "";
    const token =
      mine || (info.globalConfigured ? "$DFIR_PUSH_TOKEN" : "<your-token>");
    const url = info.pushUrl || "";
    curl.textContent = `curl -X POST ${url} \\\n  -H "X-DFIR-Key: ${token}" \\\n  -H "Content-Type: application/json" \\\n  -d '{"source":"my-tool","events":[ { /* a SIEM alert, Velociraptor rows, etc. */ } ]}'`;
  }
  function pushTokenGenerate() {
    const caseId = veloCaseId();
    const msg = document.getElementById("pushTokenMsg");
    if (!caseId) {
      if (msg) msg.textContent = "connect to a case first";
      return;
    }
    const btn = document.getElementById("pushTokenGenBtn");
    if (btn) btn.disabled = true;
    fetch(`/cases/${encodeURIComponent(caseId)}/push-token/generate`, {
      method: "POST",
    })
      .then((r) => r.json().then((j) => ({ ok: r.ok, j })))
      .then(({ ok, j }) => {
        if (!ok || j.error) {
          if (msg) msg.textContent = "error: " + (j.error || "failed");
          return;
        }
        if (msg)
          msg.textContent =
            "token generated — copy it now, it is not shown again";
        _justGenerated =
          typeof j.token === "string"
            ? { caseId, token: j.token, createdAt: j.createdAt }
            : null;
        loadPushToken(caseId);
      })
      .catch((e) => {
        if (msg) msg.textContent = "error: " + e.message;
      })
      .finally(() => {
        if (btn) btn.disabled = false;
      });
  }
  function pushTokenClear() {
    const caseId = veloCaseId();
    const msg = document.getElementById("pushTokenMsg");
    if (!caseId) return;
    const btn = document.getElementById("pushTokenClearBtn");
    if (btn) btn.disabled = true;
    fetch(`/cases/${encodeURIComponent(caseId)}/push-token`, {
      method: "DELETE",
    })
      .then(() => {
        if (msg) msg.textContent = "cleared";
        _justGenerated = null; // the key is revoked; stop offering it in the curl example
        loadPushToken(caseId);
      })
      .catch((e) => {
        if (msg) msg.textContent = "error: " + e.message;
      })
      .finally(() => {
        if (btn) btn.disabled = false;
      });
  }

  // Was a self-calling (function wirePushToken(){…})() at the bottom of the block.
  function initPushToken() {
    const gen = document.getElementById("pushTokenGenBtn");
    if (gen) gen.onclick = pushTokenGenerate;
    const clr = document.getElementById("pushTokenClearBtn");
    if (clr) clr.onclick = pushTokenClear;
  }

  window.loadPushToken = loadPushToken;
  window.initPushToken = initPushToken;
})();
