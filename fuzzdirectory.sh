#!/usr/bin/env bash
# Project enumIA - Entry Point Wrapper (bash-pro)
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec bash "${SCRIPT_DIR}/core/enum.sh" "${@}"