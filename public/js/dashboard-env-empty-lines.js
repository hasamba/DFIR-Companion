// Settings → remove empty `KEY=` lines that an older save or a hand edit left in .env (#2496).
//
// The server returns such a line as `KEY: ""` and leaves a key that is not in the file out
// altogether. The form shows both as a blank field, so without this record a save could never tell
// "an empty line is there" from "nothing is there", and the line stayed for good. Since #2465 an
// emptied setting is removed, never written as `KEY=`; this closes the gap for lines saved before.
//
// js/dashboard-env-settings.js records the RAW server values here on every load (a select with an
// unknown value also shows blank, and that value must not be erased — #1785), sends a still-blank
// recorded key in `unset`, and settles the removed keys after a successful save so a second save
// does not send them again.
//
// It also holds the switch load mapping (#2509). A switch offers only its canonical values, but its
// parser may accept more. A stored value the switch has no option for loads as NO selection, and its
// blank "default" option then cannot remove it (the save sees blank-at-load, blank-now). The mapping
// turns every value the parser accepts into the option it means. The form's baseline records the
// mapped value, so an unchanged save still leaves the .env line exactly as it was.
(function () {
  let emptyLines = new Set();

  const SWITCH_LOAD_VALUE = {
    // analysis/sigmaSettings.ts: on unless off / 0 / false / no, trimmed, any case.
    DFIR_SIGMA_SUZAKU_RULES: (v) => (!v ? "" : ["off", "0", "false", "no"].includes(v) ? "off" : "on"),
  };

  /** The option a stored switch value means; any other key's value passes through unchanged. */
  function switchLoadValue(key, val) {
    const map = SWITCH_LOAD_VALUE[key];
    return map ? map(String(val ?? "").trim().toLowerCase()) : val;
  }

  /** Called with the server's raw env map each time Settings load; replaces the previous record. */
  function recordEmptyEnvLines(env) {
    emptyLines = new Set(Object.keys(env || {}).filter((key) => env[key] === ""));
  }

  /** True when .env holds `KEY=` for this key and no save has removed it since the last load. */
  function isEmptyEnvLine(key) {
    return emptyLines.has(key);
  }

  /** After a successful save: the removed keys are gone from .env. */
  function settleEmptyEnvLines(keys) {
    const removed = new Set(keys);
    emptyLines = new Set([...emptyLines].filter((key) => !removed.has(key)));
  }

  window.recordEmptyEnvLines = recordEmptyEnvLines;
  window.isEmptyEnvLine = isEmptyEnvLine;
  window.settleEmptyEnvLines = settleEmptyEnvLines;
  window.switchLoadValue = switchLoadValue;
})();
