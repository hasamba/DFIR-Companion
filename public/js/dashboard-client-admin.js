// Client management for the Client Baseline panel (#2941): Edit client…, Archive / Unarchive client,
// Delete client… and "Show archived clients" — for the instance administrator only (the server
// answers 403 to anyone else; members never see these controls).
//
// Every action works on the client picked in the panel's Client box, read at click time — linked to
// this case or not — and never changes the case's link. Archive keeps everything; delete is refused
// by the server while any case is linked, and the refusal names those cases.
//
// Every server-derived string is written with textContent, never innerHTML.
(function () {
  "use strict";

  const SERVER_SETS_URL = "/server-sets";
  const profileUrl = (pid, tail) => `/client-profiles/${encodeURIComponent(pid)}${tail ? `/${tail}` : ""}`;

  function el(tag, text, cls) {
    const node = document.createElement(tag);
    if (text !== undefined && text !== null) node.textContent = String(text);
    if (cls) node.className = cls;
    return node;
  }

  function button(text) {
    const b = el("button", text, "ev-bulk-btn");
    b.type = "button";
    return b;
  }

  async function call(url, opts) {
    try {
      const res = await fetch(url, opts);
      let body = {};
      try {
        body = await res.json();
      } catch {
        body = {};
      }
      return { ok: res.ok, status: res.status, body };
    } catch (e) {
      return { ok: false, status: 0, body: { error: String((e && e.message) || e) } };
    }
  }

  const send = (method, url, body) =>
    call(url, { method, headers: { "Content-Type": "application/json" }, body: JSON.stringify(body || {}) });

  const failText = (r) =>
    r.status === 403 ? "only the instance administrator can manage clients" : (r.body && r.body.error) || r.status;

  // Single-user mode has one operator, who is the administrator (the same rule as New Case, #2735).
  function isInstanceAdmin() {
    const auth = window.dfirAuthState;
    if (!auth || !auth.enabled) return true;
    return !!(auth.identity && auth.identity.globalRole === "administrator");
  }

  /** "Name (id), Name (id, link file unreadable)" for a 409's linked cases. */
  function linkedText(cases) {
    return cases
      .map((c) => `${c.name || c.caseId} (${c.caseId}${c.unreadable ? ", link file unreadable" : ""})`)
      .join(", ");
  }

  async function serverSetOptions(select, current) {
    select.appendChild(el("option", "No default server set")).value = "";
    const r = await call(SERVER_SETS_URL);
    const sets = r.ok && r.body && Array.isArray(r.body.sets) ? r.body.sets : [];
    for (const s of sets) select.appendChild(el("option", s.name || s.id)).value = s.id;
    // A stored set that no longer exists stays picked, so saving the name alone does not drop it.
    if (current && !sets.some((s) => s.id === current))
      select.appendChild(el("option", `${current} (not found)`)).value = current;
    select.value = current || "";
  }

  function editForm(client, ctx, close) {
    const form = el("div", null, "cb-client-edit");
    const name = el("input");
    name.type = "text";
    name.id = "cbEditClientName";
    name.value = client.name;
    const set = el("select", null, "toolbar-select");
    set.id = "cbEditClientServerSet";
    const nameLabel = el("label", "Client name");
    nameLabel.htmlFor = name.id;
    const setLabel = el("label", "Default server set for new hunt cases");
    setLabel.htmlFor = set.id;
    const save = button("Save client");
    const cancel = button("Cancel");
    cancel.addEventListener("click", close);
    save.addEventListener("click", async () => {
      const newName = String(name.value || "").trim();
      if (!newName) return void (ctx.status.textContent = "A client needs a name.");
      const body = { name: newName, ...(set.value ? { defaultServerSetId: set.value } : {}) };
      const r = await send("PUT", profileUrl(client.id), body);
      if (!r.ok) return void (ctx.status.textContent = `Edit failed: ${failText(r)}`);
      close();
      ctx.onChanged(`Client “${r.body.name || newName}” saved.`);
    });
    form.append(nameLabel, name, setLabel, set, save, cancel);
    return { form, ready: serverSetOptions(set, client.defaultServerSetId) };
  }

  async function archive(client, ctx) {
    const verb = client.archived ? "unarchive" : "archive";
    const r = await send("POST", profileUrl(client.id, verb), {});
    if (!r.ok) return void (ctx.status.textContent = `${client.archived ? "Unarchive" : "Archive"} failed: ${failText(r)}`);
    ctx.onChanged(
      client.archived
        ? `Client “${client.name}” unarchived. It is back in the client lists.`
        : `Client “${client.name}” archived. It no longer appears in the client lists; linked cases keep working.`,
    );
  }

  async function remove(client, ctx) {
    const ask = `Delete client “${client.name}”? This removes the client with its baseline answers, versions and audit trail. It cannot be undone.`;
    if (!window.confirm(ask)) return;
    const r = await call(profileUrl(client.id), { method: "DELETE" });
    if (r.ok) return void ctx.onChanged(`Client “${client.name}” deleted.`);
    const cases = r.status === 409 && Array.isArray(r.body.linkedCases) ? r.body.linkedCases : null;
    ctx.status.textContent = cases
      ? `Cannot delete “${client.name}”: it is linked to ${cases.length} case(s): ${linkedText(cases)}. Archive the client instead.`
      : `Delete failed: ${failText(r)}`;
  }

  /**
   * The administrator's bar under the Client box. `ctx`: { select, clients, status, showArchived,
   * onToggleArchived(bool), onChanged(note) }. Returns null for anyone else.
   */
  function adminBar(ctx) {
    if (!isInstanceAdmin()) return null;
    const bar = el("div", null, "cb-client-admin");
    const editBox = el("div");
    const picked = () => ctx.clients.find((c) => c.id === ctx.select.value) || null;
    const needPick = () => void (ctx.status.textContent = "Pick a client in the Client box first.");
    const edit = button("Edit client…");
    const arch = button("Archive client");
    const del = button("Delete client…");
    const syncArchiveLabel = () => {
      const c = picked();
      arch.textContent = c && c.archived ? "Unarchive client" : "Archive client";
    };
    ctx.select.addEventListener("change", syncArchiveLabel);
    syncArchiveLabel();
    edit.addEventListener("click", async () => {
      const c = picked();
      if (!c) return needPick();
      const { form, ready } = editForm(c, ctx, () => editBox.replaceChildren());
      editBox.replaceChildren(form);
      await ready;
    });
    arch.addEventListener("click", () => {
      const c = picked();
      return c ? archive(c, ctx) : needPick();
    });
    del.addEventListener("click", () => {
      const c = picked();
      return c ? remove(c, ctx) : needPick();
    });
    const toggle = el("input");
    toggle.type = "checkbox";
    toggle.id = "cbShowArchived";
    toggle.checked = !!ctx.showArchived;
    toggle.addEventListener("change", () => ctx.onToggleArchived(!!toggle.checked));
    const toggleLabel = el("label");
    toggleLabel.append(toggle, " Show archived clients");
    bar.append(edit, arch, del, toggleLabel, editBox);
    return bar;
  }

  window.isClientAdmin = isInstanceAdmin;
  window.clientAdminBar = adminBar;
})();
