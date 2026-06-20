#!/bin/bash
{ set +xv; } 2>/dev/null
clear
echo "Setting up DFIR Companion — pulling Docker image (~1 min)..."
echo ""

until [ -f /tmp/dfir-setup.log ]; do sleep 0.5; done

tail -f /tmp/dfir-setup.log &
TAIL_PID=$!

until curl -sf http://localhost:4773/health > /dev/null 2>&1; do
  sleep 3
done

kill "$TAIL_PID" 2>/dev/null
wait "$TAIL_PID" 2>/dev/null

echo ""
echo "========================================="
echo " DFIR Companion is ready!"
echo ""
echo " To open the dashboard:"
echo "   1. Click the hamburger menu (=) top-right"
echo "   2. Select Traffic / Ports"
echo "   3. Enter port 4773 and press Access"
echo "========================================="
echo ""
