#!/usr/bin/env bash

set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
# shellcheck source=lib.sh
source "${SCRIPT_DIR}/lib.sh"
# shellcheck source=release-lib.sh
source "${SCRIPT_DIR}/release-lib.sh"

PYTHON_BIN=""
STAGING_DIRECTORY=""
ADMIN_PASSWORD_FILE=""
readonly THREEPROXY_VERSION="0.9.6"
readonly THREEPROXY_SHA256="5645111fb146faaaf260c27f0e07e510e8530a7e8a18369474cc8abbedbc9c9a"

cleanup_install_staging() {
    if [[ -n "$STAGING_DIRECTORY" && -d "$STAGING_DIRECTORY" ]]; then
        validate_release_staging_path "$STAGING_DIRECTORY"
        rm -rf "$STAGING_DIRECTORY"
    fi
    if [[ -n "$ADMIN_PASSWORD_FILE" ]]; then
        [[ "$ADMIN_PASSWORD_FILE" == "${DATA_DIR}/.admin-password-"* ]] \
            || fail "unsafe transient password path"
        rm -f -- "$ADMIN_PASSWORD_FILE"
    fi
}

prepare_admin_password_file() {
    [[ -n "${VPNGATE_ADMIN_PASSWORD:-}" ]] || return 0
    ADMIN_PASSWORD_FILE="${DATA_DIR}/.admin-password-$$"
    [[ ! -e "$ADMIN_PASSWORD_FILE" ]] || fail "transient password file already exists"
    (umask 077 && printf '%s' "$VPNGATE_ADMIN_PASSWORD" >"$ADMIN_PASSWORD_FILE")
    chown "$SERVICE_USER:$SERVICE_GROUP" "$ADMIN_PASSWORD_FILE"
    chmod 0600 "$ADMIN_PASSWORD_FILE"
    unset VPNGATE_ADMIN_PASSWORD
}

install_packages() {
    local package_manager="$1"
    if [[ "${VPNGATE_SKIP_PACKAGES:-false}" == "true" ]]; then
        log "package installation skipped by VPNGATE_SKIP_PACKAGES=true"
        return
    fi
    case "$package_manager" in
        apt-get)
            export DEBIAN_FRONTEND=noninteractive
            apt-get update
            apt-get install -y python3 python3-venv python3-pip nginx openssl curl nodejs npm \
                openvpn iproute2 nftables iptables sudo util-linux
            ;;
        dnf|yum)
            "$package_manager" install -y python3.11 python3.11-pip nginx openssl curl nodejs npm \
                openvpn iproute nftables iptables sudo util-linux
            ;;
        *) fail "unsupported package manager: $package_manager" ;;
    esac
}

install_3proxy() {
    local package_manager="$1"
    if command -v 3proxy >/dev/null 2>&1; then
        return
    fi
    if [[ "${VPNGATE_SKIP_PACKAGES:-false}" == "true" ]]; then
        log "3proxy installation skipped by VPNGATE_SKIP_PACKAGES=true"
        return
    fi
    case "$package_manager" in
        apt-get) apt-get install -y build-essential ca-certificates ;;
        dnf|yum) "$package_manager" install -y gcc make ca-certificates tar gzip ;;
        *) fail "unsupported package manager: $package_manager" ;;
    esac

    local build_directory archive source_directory
    build_directory="$(mktemp -d /tmp/vpngate-3proxy.XXXXXX)"
    archive="${build_directory}/3proxy.tar.gz"
    source_directory="${build_directory}/3proxy-${THREEPROXY_VERSION}"
    trap 'rm -rf "$build_directory"' RETURN
    curl --fail --location --silent --show-error --max-time 120 \
        "https://github.com/3proxy/3proxy/archive/refs/tags/${THREEPROXY_VERSION}.tar.gz" \
        --output "$archive"
    printf '%s  %s\n' "$THREEPROXY_SHA256" "$archive" | sha256sum --check --status \
        || fail "3proxy source checksum verification failed"
    tar -xzf "$archive" -C "$build_directory"
    make -C "$source_directory" -f Makefile.Linux
    install -m 0755 -o root -g root "$source_directory/bin/3proxy" /usr/local/bin/3proxy
    command -v 3proxy >/dev/null 2>&1 || fail "3proxy installation failed"
    rm -rf "$build_directory"
    trap - RETURN
}

create_service_account() {
    if ! getent group "$SERVICE_GROUP" >/dev/null 2>&1; then
        groupadd --system "$SERVICE_GROUP"
    fi
    if ! id "$SERVICE_USER" >/dev/null 2>&1; then
        useradd --system --gid "$SERVICE_GROUP" --home-dir "$DATA_DIR" --shell /usr/sbin/nologin "$SERVICE_USER"
    fi
}

create_state_directories() {
    install -d -m 0750 -o "$SERVICE_USER" -g "$SERVICE_GROUP" "$DATA_DIR" "$LOG_DIR"
    install -d -m 0700 -o root -g root "$BACKUP_DIR"
    install -d -m 0700 -o "$SERVICE_USER" -g "$SERVICE_GROUP" "$DATA_DIR/openvpn-configs"
    install -d -m 0700 -o "$SERVICE_USER" -g "$SERVICE_GROUP" "$DATA_DIR/socks-configs"
    install -d -m 0750 -o root -g "$SERVICE_GROUP" "$CONFIG_DIR" "$CONFIG_DIR/tls"
    install -d -m 0755 -o root -g root /etc/netns
}

write_environment() {
    if [[ -f "$ENV_FILE" ]]; then
        log "preserving existing ${ENV_FILE}"
        return
    fi
    umask 077
    printf '%s\n' \
        'VPNGATE_ENVIRONMENT=production' \
        'VPNGATE_DATABASE_URL=sqlite:////var/lib/vpngate-manager/app.db' \
        'VPNGATE_COOKIE_SECURE=true' \
        'VPNGATE_SESSION_MINUTES=720' \
        'VPNGATE_REMEMBER_SESSION_DAYS=30' \
        'VPNGATE_LOGIN_MAX_ATTEMPTS=5' \
        'VPNGATE_LOGIN_LOCK_MINUTES=15' \
        'VPNGATE_VPNGATE_API_URL=https://www.vpngate.net/api/iphone/' \
        'VPNGATE_VPNGATE_REQUEST_TIMEOUT_SECONDS=30' \
        'VPNGATE_VPNGATE_MAX_RESPONSE_BYTES=10485760' \
        'VPNGATE_VPNGATE_MAX_ROWS=20000' \
        'VPNGATE_OPENVPN_CONFIG_DIRECTORY=/var/lib/vpngate-manager/openvpn-configs' \
        'VPNGATE_SOCKS_CONFIG_DIRECTORY=/var/lib/vpngate-manager/socks-configs' \
        'VPNGATE_CREDENTIAL_ENCRYPTION_KEY_FILE=/var/lib/vpngate-manager/credential.key' \
        'VPNGATE_SUDO_PATH=/usr/bin/sudo' \
        'VPNGATE_ROOT_HELPER_PATH=/usr/local/libexec/vpngate-manager-helper' \
        'VPNGATE_NAMESPACE_DNS_SERVERS=["1.1.1.1","8.8.8.8"]' \
        'VPNGATE_OPENVPN_TUN_TIMEOUT_SECONDS=30' \
        'VPNGATE_SOCKS_PORT_START=21000' \
        'VPNGATE_SOCKS_PORT_END=21999' \
        'VPNGATE_SOCKS_READY_TIMEOUT_SECONDS=15' \
        'VPNGATE_FIREWALL_BACKEND=auto' \
        'VPNGATE_SCAN_CONCURRENCY=3' \
        'VPNGATE_SCAN_CONNECT_TIMEOUT_SECONDS=15' \
        'VPNGATE_SCAN_TOTAL_TIMEOUT_SECONDS=30' \
        'VPNGATE_FULL_SCAN_TIMEOUT_SECONDS=90' \
        'VPNGATE_IP_INTELLIGENCE_TIMEOUT_SECONDS=10' \
        'VPNGATE_IP_INTELLIGENCE_MAX_RESPONSE_BYTES=65536' \
        'VPNGATE_UNLOCK_CHECK_TIMEOUT_SECONDS=30' \
        'VPNGATE_HEALTH_CHECK_INTERVAL_SECONDS=60' \
        'VPNGATE_HEALTH_FAILURE_THRESHOLD=3' \
        'VPNGATE_AUTO_SWITCH_MAX_PER_HOUR=5' \
        'VPNGATE_AUTO_SWITCH_ALLOWED_NETWORK_TYPES=' \
        'VPNGATE_AUTO_SWITCH_REQUIRED_SERVICES=' \
        'VPNGATE_ENABLE_AUTO_SWITCH=false' \
        'VPNGATE_ENABLE_REAL_NETWORK=false' \
        'VPNGATE_ENABLE_REAL_FIREWALL=false' \
        'VPNGATE_ENABLE_REAL_OPENVPN=false' \
        'VPNGATE_ENABLE_REAL_SOCKS5=false' \
        'VPNGATE_ENABLE_REAL_SCANS=false' \
        'VPNGATE_ENABLE_REAL_FULL_SCANS=false' \
        'VPNGATE_ENABLE_REAL_IP_INTELLIGENCE=false' \
        'VPNGATE_ENABLE_REAL_UNLOCK_CHECKS=false' \
        'VPNGATE_ENABLE_REAL_CONNECTIONS=false' \
        'VPNGATE_ENABLE_REAL_AUTO_SWITCH=false' >"$ENV_FILE"
    chown root:"$SERVICE_GROUP" "$ENV_FILE"
    chmod 0640 "$ENV_FILE"
}

create_tls_certificate() {
    local key_file="${CONFIG_DIR}/tls/server.key"
    local cert_file="${CONFIG_DIR}/tls/server.crt"
    if [[ -s "$key_file" && -s "$cert_file" ]]; then
        return
    fi
    umask 077
    openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 825 \
        -subj '/CN=VPNGate Multi-Exit Manager' \
        -keyout "$key_file" -out "$cert_file" >/dev/null 2>&1
    chmod 0600 "$key_file"
    chmod 0644 "$cert_file"
}

initialize_database_and_admin() {
    (cd "$APP_DIR/backend" \
        && run_as_service_user_with_env "${APP_DIR}/venv/bin/python" -m app.cli init-secrets)
    run_database_migrations
    if (cd "$APP_DIR/backend" \
        && run_as_service_user_with_env "${APP_DIR}/venv/bin/python" -m app.cli has-users); then
        log "existing administrator database preserved"
    else
        local -a create_arguments=(create-admin)
        if [[ -n "${VPNGATE_ADMIN_USERNAME:-}" ]]; then
            create_arguments+=(--username "$VPNGATE_ADMIN_USERNAME")
        fi
        if [[ -n "$ADMIN_PASSWORD_FILE" ]]; then
            create_arguments+=(--password-file "$ADMIN_PASSWORD_FILE")
        fi
        (cd "$APP_DIR/backend" \
            && run_as_service_user_with_env \
                "${APP_DIR}/venv/bin/python" -m app.cli "${create_arguments[@]}")
        ADMIN_PASSWORD_FILE=""
    fi
}

main() {
    require_root
    require_linux_systemd
    validate_managed_paths
    acquire_maintenance_lock
    trap cleanup_install_staging EXIT
    [[ ! -e "$APP_DIR" ]] || fail "application already exists; use scripts/upgrade.sh or scripts/repair.sh"
    local package_manager
    package_manager="$(detect_package_manager)"
    install_packages "$package_manager"
    install_3proxy "$package_manager"
    select_python
    command -v nginx >/dev/null 2>&1 || fail "nginx is required"
    command -v openssl >/dev/null 2>&1 || fail "openssl is required"

    build_frontend_release
    create_service_account
    create_state_directories
    prepare_admin_password_file
    write_environment
    create_tls_certificate
    local version
    version="$(project_version "${PROJECT_ROOT}/backend/pyproject.toml")"
    STAGING_DIRECTORY="$(mktemp -d /opt/vpngate-manager.install.XXXXXX)"
    prepare_release_tree "$STAGING_DIRECTORY" "$version"
    mv "$STAGING_DIRECTORY" "$APP_DIR"
    STAGING_DIRECTORY=""
    install_release_helper "$APP_DIR"
    install_service_assets
    initialize_database_and_admin

    "$ROOT_HELPER_PATH" self-test >/dev/null
    systemctl enable --now vpngate-manager.service
    systemctl enable nginx.service
    systemctl reload-or-restart nginx.service
    wait_for_health 30
    verify_installed_version "$version"
    log "installation complete; open https://<server-address>/"
    log "real network execution remains disabled"
}

main "$@"
