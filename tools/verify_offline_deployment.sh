#!/usr/bin/env bash
# ==============================================================================
# VibeHacking v2.0.0 Offline Deployment Verification & Smoke Test
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "=================================================================="
echo " VibeHacking v2.0.0 Offline Deployment Verification & Smoke Test"
echo "=================================================================="
echo "[+] Target Root: ${ROOT_DIR}"

# 1. Check SHA256SUMS if release archive exists
if [ -f "${ROOT_DIR}/release/SHA256SUMS" ]; then
    echo "[1/7] Verifying release package SHA256 checksums..."
    (cd "${ROOT_DIR}/release" && sha256sum -c SHA256SUMS)
    echo "  ✓ Checksum verified."
else
    echo "[1/7] No release/SHA256SUMS found, skipping archive checksum (run bundle_offline.py --tar first)."
fi

# 2. Check offline vendor assets
echo "[2/7] Verifying offline vendor assets & web static files..."
VENDOR_DIR="${ROOT_DIR}/docs/vendor"
REQUIRED_ASSETS=(
    "docsify.min.js"
    "theme-simple-dark.css"
    "search.min.js"
    "docsify-copy-code.min.js"
    "docsify-pagination.min.js"
    "zoom-image.min.js"
)
for asset in "${REQUIRED_ASSETS[@]}"; do
    if [ ! -f "${VENDOR_DIR}/${asset}" ]; then
        echo "[-] ERROR: Missing offline vendor asset: ${VENDOR_DIR}/${asset}" >&2
        exit 1
    fi
done
if [ ! -f "${ROOT_DIR}/portal/static/index.html" ]; then
    echo "[-] ERROR: Missing portal static UI: ${ROOT_DIR}/portal/static/index.html" >&2
    exit 1
fi
echo "  ✓ Offline documentation and portal static assets present."

# 3. Verify Python core compilation
echo "[3/7] Verifying Python core scripts compilation..."
python3 -m py_compile \
    "${ROOT_DIR}/vhack.py" \
    "${ROOT_DIR}/portal/server.py" \
    "${ROOT_DIR}/ctf/server.py" \
    "${ROOT_DIR}/labs/solvers.py" \
    "${ROOT_DIR}/tools/bundle_offline.py"
echo "  ✓ All core Python scripts compiled cleanly."

# 4. Verify JavaScript syntax
echo "[4/7] Verifying Wargame JavaScript syntax..."
node -c "${ROOT_DIR}/wargame/assets/challenges.js"
node -c "${ROOT_DIR}/wargame/assets/app.js"
node -c "${ROOT_DIR}/wargame/scripts/verify.js"
echo "  ✓ All Wargame JavaScript files validated."

# 5. Run bundle integrity check
echo "[5/7] Running subsystem integrity audit (tools/bundle_offline.py --check-only)..."
python3 "${ROOT_DIR}/tools/bundle_offline.py" --check-only
echo "  ✓ Offline bundle audit passed."

# 6. Run Wargame verification
echo "[6/7] Running Wargame verification (verify.js)..."
node "${ROOT_DIR}/wargame/scripts/verify.js"
echo "  ✓ Wargame verification passed."

# 7. Smoke test CLI functionality
echo "[7/7] Smoke testing CLI commands (vhack doctor, vhack list)..."
python3 "${ROOT_DIR}/vhack.py" doctor > /dev/null
python3 "${ROOT_DIR}/vhack.py" list > /dev/null
echo "  ✓ CLI smoke test passed."

echo ""
echo "=================================================================="
echo " 🎉 ALL CHECKS PASSED: VibeHacking v2.0.0 is 100% Offline Ready!"
echo "=================================================================="
