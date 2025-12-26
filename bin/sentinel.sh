#!/bin/sh
# ------------------------------------------------------------------------------
# Run Sentinel CLI
# ------------------------------------------------------------------------------

# --- Usage helper ---
usage() {
  echo "Usage: $0 <severity> <scan-directory>"
  echo
  echo "Severity levels: low, medium, high"
  echo
  echo "Example:"
  echo "  $0 medium /path/to/project"
  exit 1
}

# --- Check parameters ---
[ -z "$1" ] && usage
[ -z "$2" ] && usage

SEVERITY="$1"
SCAN_DIR="$2"

# --- Validate severity ---
case "$SEVERITY" in
  low|medium|high) ;;
  *) 
    echo "Error: Invalid severity level: $SEVERITY"
    usage
    ;;
esac

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
  --heuristics-level "$SEVERITY"
  # --forensic
  # --no-bail-out
  # --all-matches
  # --exclude-dirs node_modules
