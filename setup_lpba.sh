#!/usr/bin/env bash
set -euo pipefail

# LPBA bootstrap and demo runner.
# This script configures dependencies, compiles the sample binary,
# runs LPBA telemetry collection, and produces analysis reports.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_DIR="${ROOT_DIR}/source"
ARTIFACTS_DIR="${ROOT_DIR}/artifacts"
VENV_DIR="${ROOT_DIR}/.venv"

mkdir -p "${ARTIFACTS_DIR}"

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required" >&2
  exit 1
fi

if ! command -v strace >/dev/null 2>&1; then
  echo "strace is required. Install with: sudo apt-get install -y strace" >&2
  exit 1
fi

if ! command -v gcc >/dev/null 2>&1; then
  echo "gcc is required. Install with: sudo apt-get install -y build-essential" >&2
  exit 1
fi

if [[ ! -x "${VENV_DIR}/bin/python" ]]; then
  python3 -m venv "${VENV_DIR}"
fi

# shellcheck source=/dev/null
source "${VENV_DIR}/bin/activate"
python -m pip --version >/dev/null
pip install -r "${ROOT_DIR}/requirements.txt"

gcc -O2 -Wall -Wextra "${SOURCE_DIR}/dummy_malware.c" -o "${ROOT_DIR}/dummy_malware"

python "${SOURCE_DIR}/lpba_monitor.py" --out "${ARTIFACTS_DIR}" --cmd "${ROOT_DIR}/dummy_malware"
python "${SOURCE_DIR}/analyze_lpba.py" --events "${ARTIFACTS_DIR}/events.jsonl" --out "${ARTIFACTS_DIR}"

echo "LPBA completed. Artifacts in ${ARTIFACTS_DIR}"
