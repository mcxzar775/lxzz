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
    local output_directory="${RELEASE_OUTPUT_DIR:-${PROJECT_ROOT}/dist}"
    "$PYTHON_BIN" "${PROJECT_ROOT}/tools/release_archive.py" build \
        --root "$PROJECT_ROOT" \
        --output-dir "$output_directory" \
        --source-date-epoch "${SOURCE_DATE_EPOCH:-0}"
}

main "$@"
