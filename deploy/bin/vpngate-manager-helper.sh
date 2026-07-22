#!/usr/bin/env bash

set -Eeuo pipefail

readonly VPNGATE_PYTHON="/opt/vpngate-manager/venv/bin/python"

[[ -x "$VPNGATE_PYTHON" ]] || {
    printf 'root_helper_runtime_missing\n' >&2
    exit 126
}

exec "$VPNGATE_PYTHON" -I -m app.root_helper "$@"
