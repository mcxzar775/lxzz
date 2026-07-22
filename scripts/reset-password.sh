#!/usr/bin/env bash

set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "${SCRIPT_DIR}/lib.sh"

RESET_PASSWORD_FILE=""

cleanup_password_file() {
    [[ -n "$RESET_PASSWORD_FILE" ]] || return 0
    [[ "$RESET_PASSWORD_FILE" == "${DATA_DIR}/.reset-password-"* ]] \
        || fail "unsafe transient password path"
    rm -f -- "$RESET_PASSWORD_FILE"
}

prepare_password_file() {
    [[ -n "${VPNGATE_RESET_PASSWORD:-}" ]] || return 0
    RESET_PASSWORD_FILE="${DATA_DIR}/.reset-password-$$"
    [[ ! -e "$RESET_PASSWORD_FILE" ]] || fail "transient password file already exists"
    (umask 077 && printf '%s' "$VPNGATE_RESET_PASSWORD" >"$RESET_PASSWORD_FILE")
    chown "$SERVICE_USER:$SERVICE_GROUP" "$RESET_PASSWORD_FILE"
    chmod 0600 "$RESET_PASSWORD_FILE"
    unset VPNGATE_RESET_PASSWORD
}

main() {
    require_root
    require_linux_systemd
    validate_managed_paths
    acquire_maintenance_lock
    [[ -x "${APP_DIR}/venv/bin/python" && -d "${APP_DIR}/backend" ]] \
        || fail "installed application is missing"
    validate_environment_file
    trap cleanup_password_file EXIT
    prepare_password_file

    local -a reset_arguments=(reset-password)
    if [[ -n "${VPNGATE_RESET_USERNAME:-}" ]]; then
        reset_arguments+=(--username "$VPNGATE_RESET_USERNAME")
    fi
    if [[ -n "$RESET_PASSWORD_FILE" ]]; then
        reset_arguments+=(--password-file "$RESET_PASSWORD_FILE")
    fi
    (cd "$APP_DIR/backend" \
        && run_as_service_user_with_env \
            "$APP_DIR/venv/bin/python" -m app.cli "${reset_arguments[@]}")
    RESET_PASSWORD_FILE=""
}

main "$@"
