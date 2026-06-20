#!/bin/bash
# Runs in the visible terminal while background.sh clones + installs + starts the server.
echo "Setting up DFIR Companion — this takes about 2 minutes..."
echo ""

SECONDS=0
while ! curl -sf http://localhost:4773/health > /dev/null 2>&1; do
  printf "\r  elapsed: %ds — waiting for server to start..." "$SECONDS"
  sleep 3
done

echo ""
echo ""
echo "========================================="
echo " DFIR Companion is ready!"
echo " Open the dashboard:"
echo "   click the top-right traffic icon (=>)"
echo "   and enter port 4773"
echo "========================================="
echo ""
