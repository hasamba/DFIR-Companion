# DFIR Capture Extension

MV3 extension that captures the active tab (timer + events) and sends to the companion.

## Build & load
    cd extension && npm install && npm run build
Load `extension/dist` as an unpacked extension in Comet/Chrome.

## Test
    npm test

Verified end-to-end against the companion: live capture, offline queue/sync, dashboard live updates, and report generation.

## Keyboard shortcut

`Ctrl+Shift+S` (macOS `Cmd+Shift+S`) toggles capture on/off without opening the popup — turning it on takes one capture immediately and the toolbar badge flashes `REC`/`off`. Rebind it at `chrome://extensions/shortcuts` (or via the **rebind** link in the popup). If the default key conflicts with another extension at install time, Chrome leaves it unset until you assign one there.

## Capture interval note

The periodic capture timer is implemented with `chrome.alarms`, which clamps `periodInMinutes` to a minimum of roughly 1 minute for packed/published extensions — so sub-minute intervals (e.g. 5 s) will only fire at that cadence in unpacked/dev loads. Event-based triggers (tab switch, navigation, and manual capture) are not subject to this floor and fire immediately regardless of the alarm schedule.
