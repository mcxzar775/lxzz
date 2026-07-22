#!/usr/bin/env bash

set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
# shellcheck source=lib.sh
source "${SCRIPT_DIR}/lib.sh"
# shellcheck source=release-lib.sh
source "${SCRIPT_DIR}/release-lib.sh"

REPAIR_STAGING=""

cleanup_repair_staging() {
    [[ -n "$REPAIR_STAGING" && -d "$REPAIR_STAGING" ]] || return
    [[ "$REPAIR_STAGING" == "${APP_DIR}/venv.repair."* ]] \
        || fail "unsafe repair staging path"
    rm -rf "$REPAIR_STAGING"
}

repair_virtual_environment() {
    if [[ -x "${APP_DIR}/venv/bin/python" ]] \
        && "${APP_DIR}/venv/bin/python" -c 'import app' >/dev/null 2>&1 \
        && [[ -x "${APP_DIR}/venv/bin/vpngate-root-helper" ]]; then
        return
    fi
    select_python
    local replacement backup_name
    replacement="${APP_DIR}/venv.repair.$$"
    REPAIR_STAGING="$replacement"
    backup_name="${BACKUP_DIR}/repair-venv-$(date -u +%Y%m%dT%H%M%SZ)-$$"
    [[ ! -e "$replacement" ]] || fail "repair virtualenv staging path already exists"
    "$PYTHON_BIN" -m venv "$replacement"
    "$replacement/bin/python" -m pip install --disable-pip-version-check --upgrade pip
    "$replacement/bin/python" -m pip install --disable-pip-version-check "${APP_DIR}/backend"
    if [[ -d "${APP_DIR}/venv" ]]; then
        mv "${APP_DIR}/venv" "$backup_name"
    fi
    if ! mv "$replacement" "${APP_DIR}/venv"; then
        if [[ -d "$backup_name" ]]; then
            mv "$backup_name" "${APP_DIR}/venv"
        fi
        fail "failed to activate repaired virtual environment"
    fi
    REPAIR_STAGING=""
    chown -R root:root "${APP_DIR}/venv"
    log "virtual environment repaired; previous copy retained at ${backup_name}"
}

repair_permissions() {
    install -d -m 0750 -o "$SERVICE_USER" -g "$SERVICE_GROUP" "$DATA_DIR" "$LOG_DIR"
    install -d -m 0700 -o root -g root "$BACKUP_DIR"
    install -d -m 0700 -o "$SERVICE_USER" -g "$SERVICE_GROUP" \
        "$DATA_DIR/openvpn-configs" "$DATA_DIR/socks-configs"
    install -d -m 0750 -o root -g "$SERVICE_GROUP" "$CONFIG_DIR" "$CONFIG_DIR/tls"
    install -d -m 0755 -o root -g root /etc/netns
    chown -R root:root "$APP_DIR/backend" "$APP_DIR/frontend" "$APP_DIR/venv"
    chown root:"$SERVICE_GROUP" "$ENV_FILE"
    chmod 0640 "$ENV_FILE"
}

main() {
    require_root
    require_linux_systemd
    validate_managed_paths
    acquire_maintenance_lock
    trap cleanup_repair_staging EXIT
    [[ -d "$APP_DIR" && ! -L "$APP_DIR" \
        && -f "${APP_DIR}/backend/app/__init__.py" ]] \
        || fail "installed application is missing; run scripts/install.sh"
    id "$SERVICE_USER" >/dev/null 2>&1 || fail "service account is missing"
    getent group "$SERVICE_GROUP" >/dev/null 2>&1 || fail "service group is missing"
    validate_environment_file
    command -v nginx >/dev/null 2>&1 || fail "nginx is required"
    command -v curl >/dev/null 2>&1 || fail "curl is required"

    local version
    version="$(installed_version)"
    printf '%s\n' "$version" >"${APP_DIR}/VERSION"
    chmod 0644 "${APP_DIR}/VERSION"
    chown root:root "${APP_DIR}/VERSION"
    install -d -m 0700 -o root -g root "$BACKUP_DIR"
    repair_virtual_environment
    repair_permissions
    install_release_helper "$APP_DIR"
    install_service_assets
    (cd "$APP_DIR/backend" \
        && run_as_service_user_with_env "$APP_DIR/venv/bin/python" -m app.cli init-secrets)
    (cd "$APP_DIR/backend" \
        && run_as_service_user_with_env "$APP_DIR/venv/bin/alembic" current --check-heads)
    "$ROOT_HELPER_PATH" self-test >/dev/null
    systemctl enable --now vpngate-manager.service
    systemctl enable nginx.service
    systemctl reload-or-restart nginx.service
    wait_for_health 30
    verify_installed_version "$version"
    log "installation repair completed without changing application data"
}

main "$@"
