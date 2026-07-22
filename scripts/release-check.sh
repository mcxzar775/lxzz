#!/usr/bin/env bash

set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
# shellcheck source=lib.sh
source "${SCRIPT_DIR}/lib.sh"

CHECK_DIRECTORY=""

cleanup() {
    if [[ -n "$CHECK_DIRECTORY" ]]; then
        [[ "$CHECK_DIRECTORY" == "${PROJECT_ROOT}/work/release-check."* ]] \
            || fail "unsafe release-check temporary path"
        rm -rf -- "$CHECK_DIRECTORY"
    fi
}

assert_real_features_disabled() {
    local variable
    local -a gates=(
        VPNGATE_ENABLE_REAL_NETWORK
        VPNGATE_ENABLE_REAL_FIREWALL
        VPNGATE_ENABLE_REAL_OPENVPN
        VPNGATE_ENABLE_REAL_SOCKS5
        VPNGATE_ENABLE_REAL_SCANS
        VPNGATE_ENABLE_REAL_FULL_SCANS
        VPNGATE_ENABLE_REAL_IP_INTELLIGENCE
        VPNGATE_ENABLE_REAL_UNLOCK_CHECKS
        VPNGATE_ENABLE_REAL_CONNECTIONS
        VPNGATE_ENABLE_REAL_AUTO_SWITCH
    )
    for variable in "${gates[@]}"; do
        [[ "${!variable:-false}" != "true" ]] \
            || fail "release checks refuse enabled real integration gates"
    done
}

check_static_security_rules() {
    if rg -n 'shell[[:space:]]*=[[:space:]]*True' \
        "${PROJECT_ROOT}/backend/app" "${PROJECT_ROOT}/tools"; then
        fail "shell=True is forbidden"
    fi
    if rg -n 'NOPASSWD:[[:space:]]*ALL' "${PROJECT_ROOT}/deploy"; then
        fail "NOPASSWD: ALL is forbidden"
    fi
    local script
    for script in "${PROJECT_ROOT}"/scripts/*.sh; do
        bash -n "$script"
    done
    if command -v shellcheck >/dev/null 2>&1; then
        shellcheck "${PROJECT_ROOT}"/scripts/*.sh
    else
        log "shellcheck not installed; skipped"
    fi
}

check_migrations() {
    CHECK_DIRECTORY="$(mktemp -d "${PROJECT_ROOT}/work/release-check.XXXXXX")"
    local database_url="sqlite:///${CHECK_DIRECTORY}/migration.db"
    (
        cd "${PROJECT_ROOT}/backend"
        VPNGATE_DATABASE_URL="$database_url" \
            UV_CACHE_DIR="${UV_CACHE_DIR:-${PROJECT_ROOT}/work/uv-cache}" \
            uv run alembic upgrade head
        VPNGATE_DATABASE_URL="$database_url" \
            UV_CACHE_DIR="${UV_CACHE_DIR:-${PROJECT_ROOT}/work/uv-cache}" \
            uv run alembic downgrade base
        VPNGATE_DATABASE_URL="$database_url" \
            UV_CACHE_DIR="${UV_CACHE_DIR:-${PROJECT_ROOT}/work/uv-cache}" \
            uv run alembic upgrade head
        VPNGATE_DATABASE_URL="$database_url" \
            UV_CACHE_DIR="${UV_CACHE_DIR:-${PROJECT_ROOT}/work/uv-cache}" \
            uv run alembic current --check-heads
    )
}

main() {
    trap cleanup EXIT
    command -v rg >/dev/null 2>&1 || fail "ripgrep is required for release checks"
    command -v uv >/dev/null 2>&1 || fail "uv is required for release checks"
    assert_real_features_disabled
    check_static_security_rules
    local version runtime_version archive
    version="$(project_version "${PROJECT_ROOT}/backend/pyproject.toml")"
    runtime_version="$(sed -n 's/^__version__ = "\([0-9][0-9A-Za-z.+-]*\)"$/\1/p' \
        "${PROJECT_ROOT}/backend/app/__init__.py")"
    [[ "$runtime_version" == "$version" ]] \
        || fail "pyproject and runtime versions do not match"
    check_migrations
    archive="${PROJECT_ROOT}/dist/vpngate-manager-${version}.tar.gz"
    bash "${SCRIPT_DIR}/verify-release.sh" "$archive"
    log "release checks passed for ${version}"
}

main "$@"
