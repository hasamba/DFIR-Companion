// Per-target comment threads (#415 tier 3) (#415 tier 3).
//
// targetKey() deliberately stays in the page: tags, the super-timeline and this feature all key
// off it, so it belongs to none of them. The thread index and the open-modal target ARE this
// feature's, and they stay in the closure — see eachCommentList() for the one read another
// module needs.
//
// NOT AN ES MODULE: the inline script calls the published names below by bare name.
(function () {
  let commentsByTarget = new Map(); // "type:id" -> [comment]
  let commentTarget = null; // currently-open { type, id } in the modal

  // An annotation's keys (#1715): its own `type:id`, plus the event it lives on today when correlation
  // folded the one it was made on into another (the server adds resolvedTargetId for that case only).
  function annotationKeys(a) {
    const keys = [targetKey(a.targetType, a.targetId)];
    if (a.resolvedTargetId) keys.push(targetKey(a.targetType, a.resolvedTargetId));
    return keys;
  }

  function commentChip(type, id) {
    const list = commentsByTarget.get(targetKey(type, id)) || [];
    return (
      `<button class="comment-chip${list.length ? " has" : ""}" data-ct="${escAttr(type)}" data-ci="${escAttr(String(id))}" ` +
      `title="Comments — collaborate with other investigators">${ICON_COMMENT}${list.length ? " " + list.length : ""}</button>`
    );
  }
  // #2904: is `caseId` still the case on screen? Fails open when there is no #caseId to read.
  function commentsOnScreen(caseId) {
    const el = typeof document === "undefined" ? null : document.getElementById("caseId");
    return !el || typeof el.value !== "string" || el.value.trim() === caseId;
  }
  // #2904: target ids recur across cases, so the previous case's threads must not stay to be
  // matched against this case's rows. A load for another case drops them — and closes an open
  // thread, whose post would land on this case — at once (no render: this case's render reads the
  // empty index). Only the newest answer for the case on screen is applied.
  let commentsCase = null;
  let commentsSeq = 0;
  // #2933: a post's answer applies only in the generation it was sent in (owner change / cancel).
  let commentsGen = 0;
  function clearComments(caseId) {
    commentsGen++;
    commentsCase = caseId;
    commentsByTarget = new Map();
    if (commentTarget) closeCommentModal();
  }
  // #2915: a cancelled or failed case load drops the index and closes an open thread (no render: the
  // view the cancel left is not redrawn; the next render reads the empty index). The next open — the
  // same case included — reads the comments again.
  function onCommentsReset(caseId) {
    if (caseId !== null) return;
    commentsSeq++;
    clearComments(null);
  }
  function loadComments(caseId) {
    if (!commentsOnScreen(caseId)) return; // a late caller for a case the analyst has left
    typeof DfirPanelDefer !== "undefined" && typeof DfirPanelDefer.onReset === "function" && DfirPanelDefer.onReset(onCommentsReset);
    if (commentsCase !== caseId) clearComments(caseId);
    const seq = ++commentsSeq;
    fetch(`/cases/${caseId}/comments`)
      .then((r) => r.json())
      .then((list) => {
        if (seq !== commentsSeq || !commentsOnScreen(caseId)) return;
        commentsByTarget = new Map();
        (list || []).forEach((c) => {
          // Indexed under the event it now lives on as well (#1715) — see annotationKeys().
          annotationKeys(c).forEach((k) => {
            let arr = commentsByTarget.get(k);
            if (!arr) {
              arr = [];
              commentsByTarget.set(k, arr);
            }
            arr.push(c);
          });
        });
        if (DfirState.lastState())
          typeof render === "function" && render(DfirState.lastState()); // refresh chip counts
        refreshSuperRows(); // super-timeline rows share the comment chips
        if (commentTarget) renderCommentModal(); // refresh an open thread (live collaboration)
      })
      .catch(() => {});
  }

  function openCommentModal(type, id) {
    commentTarget = { type, id };
    document.getElementById("commentOverlay").classList.add("open");
    renderCommentModal();
    document.getElementById("commentText").focus();
  }
  function closeCommentModal() {
    commentTarget = null;
    document.getElementById("commentOverlay").classList.remove("open");
    document.getElementById("commentText").value = "";
    document.getElementById("commentMsg").textContent = "";
  }
  function renderCommentModal() {
    if (!commentTarget) return;
    const list =
      commentsByTarget.get(targetKey(commentTarget.type, commentTarget.id)) ||
      [];
    document.getElementById("commentTitle").textContent =
      `Comments on ${commentTarget.type} ${commentTarget.id}`;
    document.getElementById("commentList").innerHTML = list.length
      ? list
          .map(
            (c) =>
              `<div class="comment-item"><div class="meta"><strong data-safe-style="color:var(--text-primary)">${esc(c.author)}</strong> · ` +
              `${esc(new Date(c.createdAt).toLocaleString())} <button class="comment-del" data-id="${escAttr(c.id)}" title="Delete">✕</button></div>` +
              `<div class="body">${mentionHtml(c.text)}</div></div>`,
          )
          .join("")
      : "<div data-safe-style='color:var(--text-muted);font-size:12px'>No comments yet.</div>";
    document
      .getElementById("commentList")
      .querySelectorAll(".comment-del")
      .forEach(
        (b) => (b.onclick = () => deleteComment(b.getAttribute("data-id"))),
      );
  }
  function postComment() {
    const caseId = document.getElementById("caseId").value.trim();
    const text = document.getElementById("commentText").value.trim();
    if (!caseId || !commentTarget || !text) return;
    const msg = document.getElementById("commentMsg"), gen = commentsGen;
    const live = () => gen === commentsGen && commentsOnScreen(caseId);
    msg.textContent = "posting…";
    fetch(`/cases/${caseId}/comments`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        targetType: commentTarget.type,
        targetId: commentTarget.id,
        author: investigatorName(),
        text,
      }),
    })
      .then(async (r) => {
        // The server's own sentence: a closed case answers 423 "reopen it before changing it" (#2437).
        if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error || "HTTP " + r.status);
        return r.json();
      })
      .then(() => {
        if (!live()) return; // #2933: the analyst switched case, or cancelled and reopened it
        document.getElementById("commentText").value = "";
        msg.textContent = "";
        loadComments(caseId);
      })
      .catch((e) => live() && (msg.textContent = "failed: " + e.message));
  }
  function deleteComment(id) {
    const caseId = document.getElementById("caseId").value.trim();
    if (!caseId) return;
    fetch(`/cases/${caseId}/comments/${id}`, { method: "DELETE" })
      .then(() => loadComments(caseId))
      .catch(() => {});
  }

  // MIRRORS dashboard-tags.js. That module keeps tagsByTarget private and hands out
  // tagsForTarget()/eachTagList() rather than the Map, so a reader cannot reshape another
  // feature's index. dashboard-render.js walks every thread looking for audit-marked comments;
  // this is the same read, without the map escaping.
  // Each comment ONCE: one on an event correlation folded into another sits in two buckets (#1715),
  // and the Investigation Log must not show the analyst's one action twice.
  function eachCommentList(fn) {
    const seen = new Set();
    commentsByTarget.forEach((list) => fn((list || []).filter((c) => !seen.has(c.id) && seen.add(c.id))));
  }

  // The names the inline script calls by bare name. Everything else — this feature's state
  // included — stays inside the closure, which is the point of moving it.
  window.commentChip = commentChip;
  window.loadComments = loadComments;
  window.openCommentModal = openCommentModal;
  window.closeCommentModal = closeCommentModal;
  window.renderCommentModal = renderCommentModal;
  window.postComment = postComment;
  window.deleteComment = deleteComment;
  window.eachCommentList = eachCommentList;
})();
