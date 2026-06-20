#!/bin/bash
# Runs in the visible terminal — streams setup progress while background.sh pulls + starts Docker.
echo "Setting up DFIR Companion — pulling pre-built Docker image (~1 min)..."
echo ""

# Wait for the log file (background.sh creates it on startup)
until [ -f /tmp/dfir-setup.log ]; do sleep 0.5; done

# Stream setup log to this terminal
tail -f /tmp/dfir-setup.log &
TAIL_PID=$!

# Wait for server to come up
until curl -sf http://localhost:4773/health > /dev/null 2>&1; do
  sleep 3
done

kill "$TAIL_PID" 2>/dev/null
wait "$TAIL_PID" 2>/dev/null

echo ""
echo "========================================="
echo " DFIR Companion is ready!"
echo " Open the dashboard:"
echo "   click the top-right traffic icon (=>)"
echo "   and enter port 4773"
echo "========================================="
echo ""
