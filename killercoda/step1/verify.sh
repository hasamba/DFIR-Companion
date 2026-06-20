#!/bin/bash
# Verify the server is up and the demo case exists
curl -sf http://localhost:4773/health > /dev/null 2>&1 && \
curl -sf http://localhost:4773/cases/demo > /dev/null 2>&1
