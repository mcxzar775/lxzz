#!/usr/bin/env bash

set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "${SCRIPT_DIR}/lib.sh"

failures=0

firewall_backend_available() {
    command -v nft >/dev/null 2>&1 || command -v iptables >/dev/null 2>&1
}

trusted_environment_available() {
    (validate_environment_file)
}

application_owned_by_root() {
    [[ "$(stat -c '%U:%G' "${APP_DIR}/backend" 2>/dev/null)" == "root:root" \
        && "$(stat -c '%U:%G' "${APP_DIR}/frontend" 2>/dev/null)" == "root:root" ]]
}

running_version_matches() {
    local installed_version health_payload
    installed_version="$(installed_version)"
    health_payload="$(curl --fail --silent --show-error --max-time 5 \
        http://127.0.0.1:8765/healthz)" || return 1
    [[ "$health_payload" == *"\"version\":\"${installed_version}\""* ]]
}

check() {
    local description="$1"
    shift
    if "$@" >/dev/null 2>&1; then
        printf '[PASS] %s\n' "$description"
    else
        printf '[FAIL] %s\n' "$description"
        failures=$((failures + 1))
    fi
}

main() {
    require_root
    require_linux_systemd
    validate_managed_paths
    log "running read-only diagnostics"

    check "service account exists" id "$SERVICE_USER"
    check "iproute2 command available" command -v ip
    check "OpenVPN command available" command -v openvpn
    check "3proxy SOCKS5 command available" command -v 3proxy
    check "socket inspection command available" command -v ss
    check "nftables or iptables available" firewall_backend_available
    check "network namespace listing available" ip netns list
    check "namespace DNS directory available" test -d /etc/netns
    check "TUN device available" test -c /dev/net/tun
    check "application files installed" test -f "${APP_DIR}/backend/app/main.py"
    check "installed release version exists" test -s "${APP_DIR}/VERSION"
    check "application code is root owned" application_owned_by_root
    check "restricted root helper installed" test -x "$ROOT_HELPER_PATH"
    check "restricted sudoers policy valid" visudo -cf "$SUDOERS_FILE"
    check "root helper self-test" "$ROOT_HELPER_PATH" self-test
    check "service account helper permission" \
        run_as_service_user /usr/bin/sudo -n -- "$ROOT_HELPER_PATH" self-test
    check "configuration exists" test -r "$ENV_FILE"
    check "configuration ownership and mode are trusted" trusted_environment_available
    check "database exists" test -s "${DATA_DIR}/app.db"
    check "private backup directory exists" test -d "$BACKUP_DIR"
    check "systemd unit enabled" systemctl is-enabled vpngate-manager.service
    check "API service active" systemctl is-active vpngate-manager.service
    check "Nginx active" systemctl is-active nginx.service
    check "Nginx configuration valid" nginx -t
    check "TLS certificate remains valid for seven days" \
        openssl x509 -checkend 604800 -noout -in "${CONFIG_DIR}/tls/server.crt"
    check "backend health endpoint" curl --fail --silent --show-error --max-time 5 http://127.0.0.1:8765/healthz
    check "running backend version matches installed release" running_version_matches

    if trusted_environment_available; then
        if grep -q '^VPNGATE_ENABLE_REAL_NETWORK=true$' "$ENV_FILE"; then
            printf '[WARN] real network execution is explicitly enabled\n'
        else
            printf '[PASS] real network execution is disabled\n'
        fi
        if grep -q '^VPNGATE_ENABLE_REAL_OPENVPN=true$' "$ENV_FILE"; then
            printf '[WARN] real OpenVPN execution is explicitly enabled\n'
        else
            printf '[PASS] real OpenVPN execution is disabled\n'
        fi
        if grep -q '^VPNGATE_ENABLE_REAL_SOCKS5=true$' "$ENV_FILE"; then
            printf '[WARN] real SOCKS5 execution is explicitly enabled\n'
        else
            printf '[PASS] real SOCKS5 execution is disabled\n'
        fi
        if grep -q '^VPNGATE_ENABLE_REAL_FIREWALL=true$' "$ENV_FILE"; then
            printf '[WARN] real firewall execution is explicitly enabled\n'
            check "IPv4 forwarding enabled for SOCKS5 mapping" \
                grep -q '^1$' /proc/sys/net/ipv4/ip_forward
        else
            printf '[PASS] real firewall execution is disabled\n'
        fi
        if grep -q '^VPNGATE_ENABLE_REAL_SCANS=true$' "$ENV_FILE"; then
            printf '[WARN] real host-side node scans are explicitly enabled\n'
        else
            printf '[PASS] real host-side node scans are disabled\n'
        fi
        if grep -q '^VPNGATE_ENABLE_REAL_FULL_SCANS=true$' "$ENV_FILE"; then
            printf '[WARN] real Namespace/OpenVPN full scans are explicitly enabled\n'
        else
            printf '[PASS] real Namespace/OpenVPN full scans are disabled\n'
        fi
        if grep -q '^VPNGATE_ENABLE_REAL_IP_INTELLIGENCE=true$' "$ENV_FILE"; then
            printf '[WARN] external IP intelligence is explicitly enabled\n'
            if grep -Eq '^VPNGATE_IPINFO_API_TOKEN=.{8,}$' "$ENV_FILE"; then
                printf '[PASS] external IP intelligence token is configured\n'
            else
                printf '[FAIL] external IP intelligence token is missing\n'
                failures=$((failures + 1))
            fi
        else
            printf '[PASS] external IP intelligence is disabled\n'
        fi
        if grep -q '^VPNGATE_ENABLE_REAL_UNLOCK_CHECKS=true$' "$ENV_FILE"; then
            printf '[WARN] real Namespace unlock checks are explicitly enabled\n'
        else
            printf '[PASS] real Namespace unlock checks are disabled\n'
        fi
        if grep -q '^VPNGATE_ENABLE_REAL_CONNECTIONS=true$' "$ENV_FILE"; then
            printf '[WARN] real connection lifecycle is explicitly enabled\n'
            local connection_gate
            for connection_gate in \
                VPNGATE_ENABLE_REAL_NETWORK \
                VPNGATE_ENABLE_REAL_FIREWALL \
                VPNGATE_ENABLE_REAL_OPENVPN \
                VPNGATE_ENABLE_REAL_SOCKS5 \
                VPNGATE_ENABLE_REAL_FULL_SCANS; do
                if ! grep -q "^${connection_gate}=true$" "$ENV_FILE"; then
                    printf '[FAIL] %s must be true for real connection lifecycle\n' "$connection_gate"
                    failures=$((failures + 1))
                fi
            done
        else
            printf '[PASS] real connection lifecycle is disabled\n'
        fi
        if grep -q '^VPNGATE_ENABLE_AUTO_SWITCH=true$' "$ENV_FILE"; then
            printf '[WARN] background connection health monitoring is enabled\n'
        else
            printf '[PASS] background connection health monitoring is disabled\n'
        fi
        if grep -q '^VPNGATE_ENABLE_REAL_AUTO_SWITCH=true$' "$ENV_FILE"; then
            printf '[WARN] real automatic connection switching is explicitly enabled\n'
            local required_gate
            for required_gate in \
                VPNGATE_ENABLE_REAL_NETWORK \
                VPNGATE_ENABLE_REAL_FIREWALL \
                VPNGATE_ENABLE_REAL_OPENVPN \
                VPNGATE_ENABLE_REAL_SOCKS5 \
                VPNGATE_ENABLE_REAL_FULL_SCANS \
                VPNGATE_ENABLE_REAL_UNLOCK_CHECKS; do
                if ! grep -q "^${required_gate}=true$" "$ENV_FILE"; then
                    printf '[FAIL] %s must be true for real automatic switching\n' "$required_gate"
                    failures=$((failures + 1))
                fi
            done
        else
            printf '[PASS] real automatic connection switching is disabled\n'
        fi
        local credential_key_file
        credential_key_file="$(environment_value VPNGATE_CREDENTIAL_ENCRYPTION_KEY_FILE)"
        if [[ -n "$credential_key_file" ]]; then
            check "credential encryption key is private" \
                run_as_service_user test -r "$credential_key_file"
            check "credential encryption key mode is 0600" \
                test "$(stat -c '%a' "$credential_key_file" 2>/dev/null)" = 600
        fi
        if [[ -x "${APP_DIR}/venv/bin/python" && -d "${APP_DIR}/backend" ]]; then
            if (cd "${APP_DIR}/backend" \
                && run_as_service_user_with_env \
                    "${APP_DIR}/venv/bin/python" -I \
                    -m alembic current --check-heads) >/dev/null 2>&1; then
                printf '[PASS] database migration is at head\n'
            else
                printf '[FAIL] database migration is not at head\n'
                failures=$((failures + 1))
            fi
        fi
    else
        printf '[FAIL] trusted configuration checks skipped because configuration is unsafe\n'
        failures=$((failures + 1))
    fi

    if (( failures > 0 )); then
        fail "${failures} diagnostic check(s) failed"
    fi
    log "all diagnostics passed"
}

main "$@"
