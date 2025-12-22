#!/bin/bash
# ------------------------------------------------------------------------------
# make.sh - Build sentinel CLI using PyInstaller (no venv)
# ------------------------------------------------------------------------------

set -euo pipefail

# --- 0. Variables and Options
VERSION="3.0.0"
BIN_NAME="sentinel"
DIST_DIR="dist"
PACK_DIR="pack"
DIST_ZIP="autumo-Sentinel-v${VERSION}"
DIST_ZIP_POSTFIX=
CLEAN_ONLY=false

export COMMERCIAL_BUILD=false

# --- 1. Parse optional flags
for arg in "$@"; do
    case "$arg" in
        --commercial)
            COMMERCIAL_BUILD=true
            VERSION="${VERSION}c"
            shift
            ;;
        --clean)
            CLEAN_ONLY=true
            shift
            ;;
    esac
done

# --- 2. Determine project root
PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT_ROOT"
echo "📂 Project root: $PROJECT_ROOT"

# --- 3. Clean only mode
if [ "$CLEAN_ONLY" = true ]; then
    echo "🧹 Cleaning build artifacts only..."
    rm -rf "$DIST_DIR" build sentinel.spec
    echo "✅ Clean finished."
    exit 0
fi

# --- 4. Detect OS and architecture, show targets
OS=$(uname -s)
ARCH=$(uname -m)

echo "🧭 Detected OS: $OS, architecture: $ARCH"

if [ "$OS" = "Linux" ] && grep -qi microsoft /proc/version 2>/dev/null; then
    echo "❌ WSL detected."
    echo "➡️ Release builds must be created on native Linux or macOS."
    exit 1
elif [ "$OS" = "Darwin" ]; then
    # macOS
    if [ "$ARCH" = "arm64" ]; then
        DIST_ZIP_POSTFIX="macos-arm64"
    else
        DIST_ZIP_POSTFIX="macos-x64"
    fi
elif [ "$OS" = "Linux" ]; then
    # Linux
    if [ "$ARCH" = "x86_64" ]; then
        DIST_ZIP_POSTFIX="linux-x64"
    elif [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then
        DIST_ZIP_POSTFIX="linux-arm64"
    else
        echo "❌ ERROR: Unsupported Linux architecture: $ARCH"
        exit 1
    fi
else
    echo "❌ ERROR: Unsupported OS: $OS"
    exit 1
fi

# --- 5. Clean old builds
echo "🧹 Cleaning old builds..."
rm -rf "$DIST_DIR" build sentinel.spec

# --- 6. Generate build_info.py ---
echo "📝 Generating build_info.py..."
if [ "$COMMERCIAL_BUILD" = true ]; then
    PY_COMMERCIAL_BUILD=True
else
    PY_COMMERCIAL_BUILD=False
fi
cat > app/build_info.py <<EOF
COMMERCIAL_BUILD = ${PY_COMMERCIAL_BUILD}
VERSION = "${VERSION}"
EOF

# --- 7. PyInstaller build
echo "🪄 Building sentinel CLI with PyInstaller..."

# Check pyinstaller command
command -v pyinstaller >/dev/null 2>&1 || {
    echo "❌ ERROR: PyInstaller not found. Please install it first."
    exit 1
}

# Build
pyinstaller \
    --name "${BIN_NAME}" \
    --onefile \
    app/sentinel.py

echo "✅ Build finished. Check ${DIST_DIR}/${BIN_NAME}"

# --- 8. Create name, path and show targets
DIST_ZIP_NAME="autumo-Sentinel-v${VERSION}-${DIST_ZIP_POSTFIX}"
DIST_ZIP_PATH="${DIST_DIR}/${DIST_ZIP_NAME}.zip"
echo "🔧 Building autumo Sentinel v${VERSION}"
echo "📦 Target: ${DIST_ZIP_NAME}"

# --- 9. Package ---
echo "📦 Creating ${DIST_ZIP}.zip..."

# Check zip command
command -v zip >/dev/null 2>&1 || {
    echo "❌ ERROR: 'zip' not found. Please install zip."
    exit 1
}

# Prepare package
mkdir -p "$DIST_DIR/$PACK_DIR/rules"

# Copy app files
cp "$DIST_DIR/$BIN_NAME" "$DIST_DIR/$PACK_DIR"
cp -r config "$DIST_DIR/$PACK_DIR"
cp -r patterns "$DIST_DIR/$PACK_DIR"
cp rules/rules.low* "$DIST_DIR/$PACK_DIR/rules"
cp rules/rule-set-policy.md "$DIST_DIR/$PACK_DIR/rules"
cp README.md "$DIST_DIR/$PACK_DIR"
cp LICENSE "$DIST_DIR/$PACK_DIR"
# Copy commercial files if requested
if [ "$COMMERCIAL_BUILD" = true ]; then
    echo "📦 Including commercial files for enterprise build..."
    cp rules/rules.high* "$DIST_DIR/$PACK_DIR/rules"
    cp rules/rules.medium* "$DIST_DIR/$PACK_DIR/rules"
    cp rules/rules-overview* "$DIST_DIR/$PACK_DIR/rules"
    cp LICENSE_COMMERCIAL.html "$DIST_DIR/$PACK_DIR/"
fi

# ZIP
cd $DIST_DIR/$PACK_DIR
zip -r "${DIST_ZIP_NAME}.zip" . -x "*/.DS_Store" -x "*/__MACOSX"
mv "${DIST_ZIP_NAME}.zip" ..
echo "🧹 Removing ${PACK_DIR} after packaging..."
cd ..
rm -rf $PACK_DIR

echo "✅ Distribution package created as '${DIST_ZIP_PATH}'"
