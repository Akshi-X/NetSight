#!/bin/bash
# ──────────────────────────────────────────────
#  NetSight — AI Packet Analyzer  |  Start Script
# ──────────────────────────────────────────────

set -e
cd "$(dirname "$0")"

echo ""
echo "  ⬡  NetSight — AI Packet Analyzer"
echo "  ─────────────────────────────────"
echo ""

# Check Python
if ! command -v python3 &>/dev/null; then
  echo "  ✗  Python 3 not found. Please install Python 3.9+"
  exit 1
fi

# Install deps if needed
if ! python3 -c "import fastapi" 2>/dev/null; then
  echo "  ↓  Installing dependencies..."
  pip3 install -r backend/requirements.txt -q
fi

echo "  ✓  Starting server on http://localhost:8000"
echo ""
echo "  NOTE: For live packet capture, run with sudo:"
echo "        sudo python3 -m uvicorn backend.main:app --reload"
echo "        (Without sudo, app runs in DEMO mode)"
echo ""

# Run — try with sudo for live capture, fall back otherwise
python3 -m uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
