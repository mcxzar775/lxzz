#!/usr/bin/env bash

set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
# shellcheck source=lib.sh
source "${SCRIPT_DIR}/lib.sh"
# shellcheck source=release-lib.sh
source "${SCRIPT_DIR}/release-lib.sh"

STAGING_DIRECTORY=""
UPGRADE_BACKUP=""
DATABASE_PATH=""
ROLLBACK_ACTIVE=false

backup_optional_asset() {
    local source_path="$1"
    local backup_name="$2"
    [[ -e "$source_path" || -L "$source_path" ]] || return
    cp -a -- "$source_path" "${UPGRADE_BACKUP}/assets/${backup_name}"
}

restore_optional_asset() {
    local backup_name="$1"
    local target_path="$2"
    if [[ -e "${UPGRADE_BACKUP}/assets/${backup_name}" \
        || -L "${UPGRADE_BACKUP}/assets/${backup_name}" ]]; then
        cp -a -- "${UPGRADE_BACKUP}/assets/${backup_name}" "$target_path"
    else
        rm -f -- "$target_path"
    fi
}

managed_database_path() {
    local database_url path normalized
    database_url="$(environment_value VPNGATE_DATABASE_URL)"
    if [[ "$database_url" != sqlite:////* ]]; then
        [[ "${VPNGATE_UPGRADE_ALLOW_EXTERNAL_DATABASE:-false}" == "true" ]] \
            || fail "external database requires a verified external backup and VPNGATE_UPGRADE_ALLOW_EXTERNAL_DATABASE=true"
        log "external database backup acknowledged by operator"
        return
    fi
    [[ "$database_url" != *\?* && "$database_url" != *\#* ]] \
        || fail "SQLite database URL options are not supported by upgrade backup"
    path="${database_url#sqlite:///}"
    normalized="$(realpath -m -- "$path")"
    [[ "$normalized" == "${DATA_DIR}/"* && "$normalized" != "${BACKUP_DIR}/"* ]] \
        || fail "SQLite database must be a managed data file"
    [[ -f "$normalized" && ! -L "$normalized" ]] \
        || fail "managed SQLite database is missing or unsafe"
    DATABASE_PATH="$normalized"
}

create_upgrade_backup() {
    local timestamp
    timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
    UPGRADE_BACKUP="${BACKUP_DIR}/upgrade-${timestamp}-$$"
    install -d -m 0700 -o root -g root "$BACKUP_DIR" "$UPGRADE_BACKUP" \
        "${UPGRADE_BACKUP}/assets"
    cp -a -- "$CONFIG_DIR" "${UPGRADE_BACKUP}/configuration"
    backup_optional_asset "$ROOT_HELPER_PATH" root-helper
    backup_optional_asset "$SUDOERS_FILE" sudoers
    backup_optional_asset "$SERVICE_FILE" systemd-service
    backup_optional_asset /etc/nginx/sites-available/vpngate-manager.conf nginx-available
    backup_optional_asset /etc/nginx/sites-enabled/vpngate-manager.conf nginx-enabled
    backup_optional_asset /etc/nginx/conf.d/vpngate-manager.conf nginx-conf-d
    printf '%s\n' "$(installed_version)" >"${UPGRADE_BACKUP}/previous-version"
    chmod 0600 "${UPGRADE_BACKUP}/previous-version"
}

rollback_upgrade() {
    local original_status="$?"
    trap - EXIT INT TERM
    set +e
    if [[ "$ROLLBACK_ACTIVE" == "true" ]]; then
        log "upgrade failed; restoring the previous release and database"
        systemctl stop vpngate-manager.service >/dev/null 2>&1
        if [[ -d "${UPGRADE_BACKUP}/application" ]]; then
            if [[ -d "$APP_DIR" ]]; then
                mv "$APP_DIR" "${UPGRADE_BACKUP}/failed-application"
            fi
            mv "${UPGRADE_BACKUP}/application" "$APP_DIR"
        fi
        if [[ -n "$DATABASE_PATH" && -f "${UPGRADE_BACKUP}/database.sqlite3" ]]; then
            rm -f -- "${DATABASE_PATH}-wal" "${DATABASE_PATH}-shm"
            cp -a -- "${UPGRADE_BACKUP}/database.sqlite3" "$DATABASE_PATH"
            if [[ -f "${UPGRADE_BACKUP}/database.sqlite3-wal" ]]; then
                cp -a -- "${UPGRADE_BACKUP}/database.sqlite3-wal" "${DATABASE_PATH}-wal"
            fi
            if [[ -f "${UPGRADE_BACKUP}/database.sqlite3-shm" ]]; then
                cp -a -- "${UPGRADE_BACKUP}/database.sqlite3-shm" "${DATABASE_PATH}-shm"
            fi
            chown "$SERVICE_USER:$SERVICE_GROUP" "$DATABASE_PATH"
            chown "$SERVICE_USER:$SERVICE_GROUP" \
                "${DATABASE_PATH}-wal" "${DATABASE_PATH}-shm" 2>/dev/null || true
        fi
        restore_optional_asset root-helper "$ROOT_HELPER_PATH"
        restore_optional_asset sudoers "$SUDOERS_FILE"
        restore_optional_asset systemd-service "$SERVICE_FILE"
        restore_optional_asset nginx-available /etc/nginx/sites-available/vpngate-manager.conf
        restore_optional_asset nginx-enabled /etc/nginx/sites-enabled/vpngate-manager.conf
        restore_optional_asset nginx-conf-d /etc/nginx/conf.d/vpngate-manager.conf
        systemctl daemon-reload
        nginx -t >/dev/null 2>&1
        systemctl start vpngate-manager.service >/dev/null 2>&1
        log "rollback completed; failed release retained under ${UPGRADE_BACKUP}"
    fi
    if [[ -n "$STAGING_DIRECTORY" && -d "$STAGING_DIRECTORY" ]]; then
        validate_release_staging_path "$STAGING_DIRECTORY"
        rm -rf "$STAGING_DIRECTORY"
    fi
    exit "$original_status"
}

main() {
    require_root
    require_linux_systemd
    validate_managed_paths
    acquire_maintenance_lock
    [[ -d "$APP_DIR" && ! -L "$APP_DIR" \
        && -f "${APP_DIR}/backend/app/__init__.py" ]] \
        || fail "installed application is missing; run scripts/install.sh"
    validate_environment_file
    command -v nginx >/dev/null 2>&1 || fail "nginx is required"
    command -v curl >/dev/null 2>&1 || fail "curl is required"
    select_python

    local current_version new_version
    current_version="$(installed_version)"
    new_version="$(project_version "${PROJECT_ROOT}/backend/pyproject.toml")"
    [[ "$current_version" != "$new_version" \
        || "${VPNGATE_ALLOW_SAME_VERSION_UPGRADE:-false}" == "true" ]] \
        || fail "version ${new_version} is already installed; use repair.sh or explicitly allow a same-version upgrade"

    build_frontend_release
    STAGING_DIRECTORY="$(mktemp -d /opt/vpngate-manager.upgrade.XXXXXX)"
    trap rollback_upgrade EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    prepare_release_tree "$STAGING_DIRECTORY" "$new_version"
    managed_database_path
    create_upgrade_backup

    ROLLBACK_ACTIVE=true
    systemctl stop vpngate-manager.service
    if [[ -n "$DATABASE_PATH" ]]; then
        cp -a -- "$DATABASE_PATH" "${UPGRADE_BACKUP}/database.sqlite3"
        if [[ -f "${DATABASE_PATH}-wal" && ! -L "${DATABASE_PATH}-wal" ]]; then
            cp -a -- "${DATABASE_PATH}-wal" "${UPGRADE_BACKUP}/database.sqlite3-wal"
        fi
        if [[ -f "${DATABASE_PATH}-shm" && ! -L "${DATABASE_PATH}-shm" ]]; then
            cp -a -- "${DATABASE_PATH}-shm" "${UPGRADE_BACKUP}/database.sqlite3-shm"
        fi
    fi
    mv "$APP_DIR" "${UPGRADE_BACKUP}/application"
    mv "$STAGING_DIRECTORY" "$APP_DIR"
    STAGING_DIRECTORY=""

    install_release_helper "$APP_DIR"
    install_service_assets
    run_database_migrations
    "$ROOT_HELPER_PATH" self-test >/dev/null
    systemctl enable --now vpngate-manager.service
    systemctl enable nginx.service
    systemctl reload-or-restart nginx.service
    wait_for_health 30
    verify_installed_version "$new_version"

    ROLLBACK_ACTIVE=false
    trap - EXIT INT TERM
    log "upgrade ${current_version} -> ${new_version} completed"
    log "rollback backup retained at ${UPGRADE_BACKUP}"
}

main "$@"
