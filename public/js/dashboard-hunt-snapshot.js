// The live-snapshot choice on an AI-suggested hunt (#809).
//
// A compiled Sigma rule knows it reads live state — the compiler stamps `snapshot` per template
// (#803) — so its empty result is never a miss. An AI-suggested `pslist()` / `netstat()` / `glob()`
// query has the same character, but the Companion cannot tell from arbitrary VQL what it observes
// and does not guess. Instead the suggestion card carries a checkbox beside Deploy, ticked by
// default only when every FROM in the VQL is visibly a live-state plugin, and the deploy sends
// what the analyst chose. dashboard-hunts-jumps.js and dashboard-playbook.js render and read it;
// launchHuntInto (dashboard-sigma-hunt.js) turns ctx.coverage into the deploy body.
//
// A classic script, IIFE-wrapped like the other #415 tier-3 modules; nothing here holds state.
(function () {
  // The plugins whose rows are the endpoint AS IT IS NOW — the four Sigma template sources and the
  // file/registry readers that work on what those find. A hunt built only from these is a live
  // snapshot (#803): an empty result says nothing about the past and must not read as a miss.
  var LIVE_STATE_PLUGINS = [
    "pslist",
    "netstat",
    "glob",
    "stat",
    "hash",
    "read_file",
    "yara",
    "reg_keys",
    "read_reg_key",
  ];
  // True when every `FROM <plugin>(` in the VQL is a live-state plugin (and there is at least one).
  // Anything else — parse_evtx(), an Artifact.<Name>(), foreach()/chain() wrappers — leaves the
  // answer to the analyst: this only reads what is visibly on the page, it never guesses (#809).
  function vqlReadsLiveState(vql) {
    var re = /\bFROM\s+([A-Za-z_][\w.]*)\s*\(/gi;
    var seen = 0;
    var m;
    while ((m = re.exec(String(vql || "")))) {
      seen++;
      if (LIVE_STATE_PLUGINS.indexOf(m[1].toLowerCase()) < 0) return false;
    }
    return seen > 0;
  }
  // The "live snapshot" choice beside a suggestion's Deploy button (#809). `cls` is the card's
  // input class, `idx` its index. It is on by default only when vqlReadsLiveState says so; the
  // analyst flips it either way, and launchHuntInto sends coverage: "snapshot" when it is on.
  function huntSnapshotToggleHtml(cls, idx, vql) {
    var on = vqlReadsLiveState(vql);
    return (
      `<label class="hunt-snapshot-opt" title="A live snapshot reads the endpoint as it is now (pslist, netstat, glob…): a process that exited or a file that was deleted will not be there, so an empty result is not a miss and is never counted against a hypothesis. Untick for an event-backed query, where an empty result IS negative evidence.">` +
      `<input type="checkbox" class="${escAttr(cls)}" data-idx="${escAttr(String(idx))}"${on ? " checked" : ""} /> live snapshot (empty ≠ miss)</label>`
    );
  }
  // Read the toggle for card `idx` into the deploy ctx: { coverage: "snapshot" } when ticked, {} when not.
  function huntSnapshotCtx(container, cls, idx) {
    var box = container && container.querySelector(`.${cls}[data-idx="${idx}"]`);
    return box && box.checked ? { coverage: "snapshot" } : {};
  }

  window.vqlReadsLiveState = vqlReadsLiveState;
  window.huntSnapshotToggleHtml = huntSnapshotToggleHtml;
  window.huntSnapshotCtx = huntSnapshotCtx;
})();
