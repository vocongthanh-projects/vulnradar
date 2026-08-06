#!/usr/bin/env bash
# ==============================================================================
# VulnRadar — Daily Automated Maintenance Pipeline
# Performs daily ingest from all sources, LLM auto-tagging for new entries,
# and outputs daily security digest.
# ==============================================================================

set -e

# Resolve script directory and project paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Ensure logs directory exists
LOGS_DIR="${PROJECT_DIR}/logs"
mkdir -p "${LOGS_DIR}"

DATE_STR="$(date +'%Y-%m-%d')"
DIGEST_LOG="${LOGS_DIR}/digest_${DATE_STR}.log"

echo "======================================================================"
echo "[*] VulnRadar Daily Maintenance Started: $(date)"
echo "======================================================================"

cd "${PROJECT_DIR}"

# Step 1: Ingest fresh data from all sources (last 1 day)
echo ""
echo "[Step 1/3] Ingesting new vulnerabilities and writeups (last 1 day)..."
vulnradar ingest all --days 1

# Step 2: LLM Auto-tagging for untagged entries
echo ""
echo "[Step 2/3] Running LLM Auto-tagging for missing entries..."
vulnradar tag --missing-only --limit 0

# Step 3: Generate daily vulnerability digest
echo ""
echo "[Step 3/3] Generating daily security digest..."
vulnradar digest --since 1d --limit 0 --show-url | tee "${DIGEST_LOG}"

echo ""
echo "======================================================================"
echo "[✓] Daily Maintenance Completed Successfully!"
echo "[*] Digest saved to: ${DIGEST_LOG}"
echo "======================================================================"
