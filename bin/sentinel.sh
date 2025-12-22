#!/bin/sh
# ------------------------------------------------------------------------------
# Run sentinel CLI
# ------------------------------------------------------------------------------

# --- 0. Change working directory to project root ---
cd "$(dirname "$0")/.." || exit 1

# --- 1. Set scan directory ---
SCAN_DIR="/Users/Mike/Development/git/repository/autumo-toolbox"

# --- 2. Run sentinel CLI with options ---
python3 app/sentinel.py "$SCAN_DIR" \
  -l \
  -g \
  -k \
  --heuristics-level low \
  # --forensic \
  # --no-bail-out \
  # --all-matches \
  # --exclude-dirs node_modules
