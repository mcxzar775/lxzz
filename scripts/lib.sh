#!/usr/bin/env bash

set -Eeuo pipefail

readonly APP_NAME="vpngate-manager"
readonly SERVICE_USER="vpngate-manager"
readonly SERVICE_GROUP="vpngate-manager"
readonly APP_DIR="/opt/vpngate-manager"
readonly CONFIG_DIR="/etc/vpngate-manager"
readonly DATA_DIR="/var/lib/vpngate-manager"
readonly LOG_DIR="/var/log/vpngate-manager"
readonly BACKUP_DIR="${DATA_DIR}/backups"
readonly RUNTIME_DIR="/run/vpngate-manager"
readonly ENV_FILE="${CONFIG_DIR}/vpngate.env"
readonly SERVICE_FILE="/etc/systemd/system/vpngate-manager.service"
readonly ROOT_HELPER_PATH="/usr/local/libexec/vpngate-manager-helper"
readonly SUDOERS_FILE="/etc/sudoers.d/vpngate-manager"
readonly MAINTENANCE_LOCK_FILE="/run/lock/vpngate-manager-maintenance.lock"

log() {
    printf '[%s] %s\n' "$APP_NAME" "$*"
}

fail() {
    printf '[%s] ERROR: %s\n' "$APP_NAME" "$*" >&2
    exit 1
}

require_root() {
    if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
        fail "this command must run as root"
    fi
}

require_linux_systemd() {
    [[ -r /etc/os-release ]] || fail "/etc/os-release is missing"
    command -v systemctl >/dev/null 2>&1 || fail "systemd is required"
}

validate_managed_paths() {
    [[ "$APP_DIR" == "/opt/vpngate-manager" ]] || fail "unexpected application path"
    [[ "$CONFIG_DIR" == "/etc/vpngate-manager" ]] || fail "unexpected configuration path"
    [[ "$DATA_DIR" == "/var/lib/vpngate-manager" ]] || fail "unexpected data path"
    [[ "$LOG_DIR" == "/var/log/vpngate-manager" ]] || fail "unexpected log path"
    [[ "$BACKUP_DIR" == "/var/lib/vpngate-manager/backups" ]] \
        || fail "unexpected backup path"
    [[ "$RUNTIME_DIR" == "/run/vpngate-manager" ]] || fail "unexpected runtime path"
}

acquire_maintenance_lock() {
    command -v flock >/dev/null 2>&1 || fail "flock from util-linux is required"
    install -d -m 0755 -o root -g root /run/lock
    exec 9>"$MAINTENANCE_LOCK_FILE"
    flock -n 9 || fail "another VPNGate maintenance operation is running"
}

validate_environment_file() {
    [[ -f "$ENV_FILE" && ! -L "$ENV_FILE" ]] \
        || fail "trusted configuration file is missing or unsafe"
    local owner group mode size
    owner="$(stat -c '%U' "$ENV_FILE")"
    group="$(stat -c '%G' "$ENV_FILE")"
    mode="$(stat -c '%a' "$ENV_FILE")"
    size="$(stat -c '%s' "$ENV_FILE")"
    [[ "$owner" == "root" ]] || fail "configuration must be owned by root"
    [[ "$mode" == "600" || "$mode" == "640" ]] \
        || fail "configuration mode must be 0600 or 0640"
    if [[ "$mode" == "640" ]]; then
        [[ "$group" == "$SERVICE_GROUP" ]] \
            || fail "0640 configuration must use the service group"
    fi
    [[ "$size" =~ ^[0-9]+$ && "$size" -le 65536 ]] \
        || fail "configuration file is too large"
    local line key seen_keys=" "
    while IFS= read -r line || [[ -n "$line" ]]; do
        [[ -z "$line" || "$line" == \#* ]] && continue
        [[ "$line" =~ ^[A-Z][A-Z0-9_]*=[^[:cntrl:]]*$ ]] \
            || fail "configuration contains an invalid assignment"
        key="${line%%=*}"
        [[ "$key" == VPNGATE_* ]] \
            || fail "configuration contains an unexpected variable"
        [[ "$seen_keys" != *" ${key} "* ]] \
            || fail "configuration contains a duplicate key"
        seen_keys+="${key} "
    done <"$ENV_FILE"
}

run_as_service_user_with_env() {
    validate_environment_file
    local -a environment=(
        "PATH=/usr/local/bin:/usr/bin:/bin"
        "LANG=C.UTF-8"
        "LC_ALL=C.UTF-8"
    )
    local line key
    while IFS= read -r line || [[ -n "$line" ]]; do
        [[ -z "$line" || "$line" == \#* ]] && continue
        [[ "$line" =~ ^[A-Z][A-Z0-9_]*=[^[:cntrl:]]*$ ]] \
            || fail "configuration contains an invalid assignment"
        key="${line%%=*}"
        [[ "$key" == VPNGATE_* ]] \
            || fail "configuration contains an unexpected variable"
        environment+=("$line")
    done <"$ENV_FILE"
    run_as_service_user env -i "${environment[@]}" "$@"
}

environment_value() {
    local requested_key="$1"
    [[ "$requested_key" =~ ^VPNGATE_[A-Z0-9_]+$ ]] \
        || fail "invalid environment key requested"
    validate_environment_file
    local line key found=""
    while IFS= read -r line || [[ -n "$line" ]]; do
        [[ -z "$line" || "$line" == \#* ]] && continue
        [[ "$line" =~ ^[A-Z][A-Z0-9_]*=[^[:cntrl:]]*$ ]] \
            || fail "configuration contains an invalid assignment"
        key="${line%%=*}"
        if [[ "$key" == "$requested_key" ]]; then
            [[ -z "$found" ]] || fail "configuration contains a duplicate key"
            found="${line#*=}"
        fi
    done <"$ENV_FILE"
    [[ -n "$found" ]] || fail "required configuration key is missing"
    printf '%s\n' "$found"
}

wait_for_health() {
    local attempts="${1:-30}"
    local count
    for ((count = 1; count <= attempts; count += 1)); do
        if curl --fail --silent --show-error --max-time 3 \
            http://127.0.0.1:8765/healthz >/dev/null 2>&1; then
            return
        fi
        sleep 1
    done
    fail "backend health check did not become ready"
}

project_version() {
    local pyproject="$1"
    local version
    version="$(sed -n 's/^version = "\([0-9][0-9A-Za-z.+-]*\)"$/\1/p' "$pyproject")"
    [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.+-][0-9A-Za-z.-]+)?$ ]] \
        || fail "project version is missing or invalid"
    printf '%s\n' "$version"
}

installed_version() {
    local version
    if [[ -f "${APP_DIR}/VERSION" && ! -L "${APP_DIR}/VERSION" ]]; then
        version="$(<"${APP_DIR}/VERSION")"
    elif [[ -f "${APP_DIR}/backend/app/__init__.py" \
        && ! -L "${APP_DIR}/backend/app/__init__.py" ]]; then
        version="$(sed -n 's/^__version__ = "\([0-9][0-9A-Za-z.+-]*\)"$/\1/p' \
            "${APP_DIR}/backend/app/__init__.py")"
    else
        fail "installed version is missing"
    fi
    [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.+-][0-9A-Za-z.-]+)?$ ]] \
        || fail "installed version is invalid"
    printf '%s\n' "$version"
}

detect_package_manager() {
    # shellcheck disable=SC1091
    source /etc/os-release
    case "${ID:-}" in
        ubuntu|debian)
            printf 'apt-get\n'
            ;;
        rocky|almalinux|centos|rhel)
            if command -v dnf >/dev/null 2>&1; then
                printf 'dnf\n'
            elif command -v yum >/dev/null 2>&1; then
                printf 'yum\n'
            else
                fail "dnf or yum is required"
            fi
            ;;
        *)
            case "${ID_LIKE:-}" in
                *debian*) printf 'apt-get\n' ;;
                *rhel*|*fedora*)
                    command -v dnf >/dev/null 2>&1 && printf 'dnf\n' || printf 'yum\n'
                    ;;
                *) fail "unsupported Linux distribution: ${ID:-unknown}" ;;
            esac
            ;;
    esac
}

run_as_service_user() {
    command -v runuser >/dev/null 2>&1 || fail "runuser from util-linux is required"
    runuser -u "$SERVICE_USER" -- "$@"
}
