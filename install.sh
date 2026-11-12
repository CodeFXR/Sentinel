#!/usr/bin/env bash
# Sentinel - wrapper delegating to install
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "${SCRIPT_DIR}/install" "$@"
