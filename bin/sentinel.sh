#!/bin/sh
# ------------------------------------------------------------------------------
# Run Sentinel CLI
# ------------------------------------------------------------------------------

# --- Usage helper ---
usage() {
  echo "Usage: $0 <scan-directory>"
  echo
  echo "Example:"
  echo "  $0 /path/to/project"
  exit 1
}

# --- Check parameter ---
[ -z "$1" ] && usage

SCAN_DIR="$1"

# --- Check directory exists ---
if [ ! -d "$SCAN_DIR" ]; then
  echo "Error: Scan directory does not exist: $SCAN_DIR"
  exit 1
fi

# --- Change working directory to project root ---
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
cd "$SCRIPT_DIR/.." || exit 1

# --- Run Sentinel CLI ---
python3 app/sentinel.py "$SCAN_DIR" \
  -l \
  -g \
  -k \
  --heuristics-level low
  # --forensic
  # --no-bail-out
  # --all-matches
  # --exclude-dirs node_modules
