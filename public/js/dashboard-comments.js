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

  function commentChip(type, id) {
    const list = commentsByTarget.get(targetKey(type, id)) || [];
    return (
      `<button class="comment-chip${list.length ? " has" : ""}" data-ct="${escAttr(type)}" data-ci="${escAttr(String(id))}" ` +
      `title="Comments — collaborate with other investigators">${ICON_COMMENT}${list.length ? " " + list.length : ""}</button>`
    );
  }
  function loadComments(caseId) {
    fetch(`/cases/${caseId}/comments`)
      .then((r) => r.json())
      .then((list) => {
        commentsByTarget = new Map();
        (list || []).forEach((c) => {
          const k = targetKey(c.targetType, c.targetId);
          let arr = commentsByTarget.get(k);
          if (!arr) {
            arr = [];
            commentsByTarget.set(k, arr);
          }
          arr.push(c);
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
    const msg = document.getElementById("commentMsg");
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
      .then((r) => {
        if (!r.ok) throw new Error("HTTP " + r.status);
        return r.json();
      })
      .then(() => {
        document.getElementById("commentText").value = "";
        msg.textContent = "";
        loadComments(caseId);
      })
      .catch((e) => (msg.textContent = "failed: " + e.message));
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
  function eachCommentList(fn) {
    commentsByTarget.forEach((list) => fn(list || []));
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
