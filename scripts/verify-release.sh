#!/usr/bin/env bash

set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
# shellcheck source=lib.sh
source "${SCRIPT_DIR}/lib.sh"
# shellcheck source=release-lib.sh
source "${SCRIPT_DIR}/release-lib.sh"

main() {
    select_python
    local version archive
    version="$(project_version "${PROJECT_ROOT}/backend/pyproject.toml")"
    archive="${1:-${PROJECT_ROOT}/dist/vpngate-manager-${version}.tar.gz}"
    "$PYTHON_BIN" "${PROJECT_ROOT}/tools/release_archive.py" verify "$archive"
}

main "$@"
