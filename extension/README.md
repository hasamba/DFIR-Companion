# DFIR Capture Extension

MV3 extension that captures the active tab (timer + events) and sends to the companion.

## Build & load
    cd extension && npm install && npm run build
Load `extension/dist` as an unpacked extension in Comet/Chrome.

## Test
    npm test

Verified end-to-end against the companion: live capture, offline queue/sync, dashboard live updates, and report generation.
