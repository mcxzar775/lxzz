#!/usr/bin/env bash

set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "${SCRIPT_DIR}/lib.sh"

confirm_uninstall() {
    if [[ "${VPNGATE_UNINSTALL_CONFIRM:-}" == "YES" ]]; then
        return
    fi
    if [[ ! -t 0 ]]; then
        fail "set VPNGATE_UNINSTALL_CONFIRM=YES for non-interactive uninstall"
    fi
    local answer
    read -r -p "Remove VPNGate Manager application and services? [y/N] " answer
    [[ "$answer" =~ ^[Yy]$ ]] || fail "uninstall cancelled"
}

runtime_connection_ids() {
    local path filename namespace first second third
    {
        shopt -s nullglob
        for path in \
            "${RUNTIME_DIR}/openvpn/"openvpn-*.pid \
            "${RUNTIME_DIR}/socks/"socks-*.pid \
            "${RUNTIME_DIR}/firewall/"killswitch-*.backend; do
            filename="${path##*/}"
            if [[ "$filename" =~ ^openvpn-([1-9][0-9]*)\.pid$ \
                || "$filename" =~ ^socks-([1-9][0-9]*)\.pid$ \
                || "$filename" =~ ^killswitch-([1-9][0-9]*)\.backend$ ]]; then
                printf '%s\n' "${BASH_REMATCH[1]}"
            fi
        done
        shopt -u nullglob
        if command -v ip >/dev/null 2>&1; then
            while read -r namespace _; do
                if [[ "$namespace" =~ ^lxvpn-([1-9][0-9]*)$ ]]; then
                    printf '%s\n' "${BASH_REMATCH[1]}"
                fi
            done < <(ip netns list 2>/dev/null || true)
            while read -r first second _; do
                if [[ "$second" =~ ^lvh([1-9][0-9]*)[:@] ]]; then
                    printf '%s\n' "${BASH_REMATCH[1]}"
                fi
            done < <(ip -o link show 2>/dev/null || true)
        fi
        if command -v nft >/dev/null 2>&1; then
            while read -r first second third _; do
                if [[ "$first" == "table" && "$second" == "inet" \
                    && "$third" =~ ^vpngate_[hn]([1-9][0-9]*)$ ]]; then
                    printf '%s\n' "${BASH_REMATCH[1]}"
                fi
            done < <(nft list tables 2>/dev/null || true)
        fi
        if command -v iptables >/dev/null 2>&1; then
            while read -r first second _; do
                if [[ "$first" == "-N" && "$second" =~ ^VG[DPFSOI]([1-9][0-9]*)$ ]]; then
                    printf '%s\n' "${BASH_REMATCH[1]}"
                fi
            done < <({ iptables -S 2>/dev/null; iptables -t nat -S 2>/dev/null; } || true)
        fi
    } | sort -nu
}

database_connection_ids() {
    [[ -x "${APP_DIR}/venv/bin/python" && -d "${APP_DIR}/backend" ]] || return 0
    trusted_environment_available_for_uninstall || return 0
    (cd "$APP_DIR/backend" \
        && run_as_service_user_with_env \
            "$APP_DIR/venv/bin/python" -m app.cli list-connection-ids) 2>/dev/null || true
}

trusted_environment_available_for_uninstall() {
    (validate_environment_file) >/dev/null 2>&1
}

purge_managed_runtime() {
    local -a connection_ids=()
    local identifier
    mapfile -t connection_ids < <(
        { database_connection_ids; runtime_connection_ids; } | sort -nu
    )
    if (( ${#connection_ids[@]} > 0 )); then
        [[ -x "$ROOT_HELPER_PATH" ]] \
            || fail "managed network resources exist but the root helper is missing"
    fi
    for identifier in "${connection_ids[@]}"; do
        [[ "$identifier" =~ ^[1-9][0-9]*$ ]] || fail "unsafe managed connection ID"
        "$ROOT_HELPER_PATH" connection-purge "$identifier" \
            || fail "failed to clean managed network resources for connection ${identifier}"
    done
    mapfile -t connection_ids < <(runtime_connection_ids)
    (( ${#connection_ids[@]} == 0 )) \
        || fail "managed network resources remain; application files were not removed"
}

main() {
    require_root
    require_linux_systemd
    validate_managed_paths
    acquire_maintenance_lock
    confirm_uninstall

    systemctl stop vpngate-manager.service >/dev/null 2>&1 || true
    purge_managed_runtime
    systemctl disable vpngate-manager.service >/dev/null 2>&1 || true
    rm -f "$SUDOERS_FILE"
    rm -f "$ROOT_HELPER_PATH"
    rm -f "$SERVICE_FILE"
    rm -f /etc/nginx/sites-enabled/vpngate-manager.conf
    rm -f /etc/nginx/sites-available/vpngate-manager.conf
    rm -f /etc/nginx/conf.d/vpngate-manager.conf
    systemctl daemon-reload
    if command -v nginx >/dev/null 2>&1 && nginx -t >/dev/null 2>&1; then
        systemctl reload nginx.service >/dev/null 2>&1 || true
    fi

    rm -rf "$APP_DIR"
    rm -rf "$RUNTIME_DIR"

    if [[ "${VPNGATE_PURGE_DATA:-false}" == "true" ]]; then
        rm -rf "$CONFIG_DIR"
        rm -rf "$DATA_DIR"
        rm -rf "$LOG_DIR"
        if id "$SERVICE_USER" >/dev/null 2>&1; then
            userdel "$SERVICE_USER" >/dev/null 2>&1 || true
        fi
        if getent group "$SERVICE_GROUP" >/dev/null 2>&1; then
            groupdel "$SERVICE_GROUP" >/dev/null 2>&1 || true
        fi
        log "application, configuration, database, backups and logs removed"
        log "purged state cannot be recovered by the uninstall script"
    else
        log "application removed; configuration and data preserved for recovery"
        log "service account preserved so retained encrypted data remains accessible"
        log "set VPNGATE_PURGE_DATA=true to remove preserved state on a later run"
    fi
}

main "$@"
