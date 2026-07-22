#!/usr/bin/env bash

set -Eeuo pipefail

readonly DEFAULT_VERSION="0.1.0"
GITHUB_REPOSITORY="${VPNGATE_GITHUB_REPOSITORY:-}"
INSTALL_VERSION="${VPNGATE_INSTALL_VERSION:-$DEFAULT_VERSION}"
BOOTSTRAP_DIRECTORY=""

log() {
    printf '[vpngate-manager-bootstrap] %s\n' "$*"
}

fail() {
    printf '[vpngate-manager-bootstrap] ERROR: %s\n' "$*" >&2
    exit 1
}

usage() {
    printf 'Usage: sudo bash install-from-github.sh --repo OWNER/REPOSITORY [--version VERSION]\n'
}

cleanup() {
    if [[ -n "$BOOTSTRAP_DIRECTORY" ]]; then
        [[ "$BOOTSTRAP_DIRECTORY" == /tmp/vpngate-bootstrap.* ]] \
            || fail "unsafe bootstrap temporary path"
        rm -rf -- "$BOOTSTRAP_DIRECTORY"
    fi
}

parse_arguments() {
    while (($# > 0)); do
        case "$1" in
            --repo)
                (($# >= 2)) || fail "--repo requires a value"
                GITHUB_REPOSITORY="$2"
                shift 2
                ;;
            --version)
                (($# >= 2)) || fail "--version requires a value"
                INSTALL_VERSION="$2"
                shift 2
                ;;
            --help|-h)
                usage
                exit 0
                ;;
            *)
                fail "unknown argument: $1"
                ;;
        esac
    done
}

validate_inputs() {
    [[ ${EUID:-$(id -u)} -eq 0 ]] || fail "run this installer through sudo"
    [[ "$GITHUB_REPOSITORY" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}/[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$ ]] \
        || fail "--repo must be OWNER/REPOSITORY"
    [[ "$INSTALL_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.+-][0-9A-Za-z.-]+)?$ ]] \
        || fail "invalid release version"
    command -v curl >/dev/null 2>&1 || fail "curl is required"
    command -v python3 >/dev/null 2>&1 || fail "Python 3.10 or newer is required"
    command -v tar >/dev/null 2>&1 || fail "tar is required"
    python3 -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)' \
        || fail "Python 3.10 or newer is required"
}

download() {
    local url="$1"
    local destination="$2"
    curl --proto '=https' --tlsv1.2 \
        --fail --location --silent --show-error \
        --retry 3 --connect-timeout 15 --max-time 300 \
        --output "$destination" "$url"
}

main() {
    parse_arguments "$@"
    validate_inputs
    trap cleanup EXIT

    local archive_name="vpngate-manager-${INSTALL_VERSION}.tar.gz"
    local release_base="https://github.com/${GITHUB_REPOSITORY}/releases/download/v${INSTALL_VERSION}"
    local raw_base="https://raw.githubusercontent.com/${GITHUB_REPOSITORY}/v${INSTALL_VERSION}"
    BOOTSTRAP_DIRECTORY="$(mktemp -d /tmp/vpngate-bootstrap.XXXXXX)"
    local archive="${BOOTSTRAP_DIRECTORY}/${archive_name}"
    local verifier="${BOOTSTRAP_DIRECTORY}/release_archive.py"
    local extract_directory="${BOOTSTRAP_DIRECTORY}/extract"

    log "downloading release v${INSTALL_VERSION}"
    download "${release_base}/${archive_name}" "$archive"
    download "${release_base}/${archive_name}.sha256" "${archive}.sha256"
    download "${raw_base}/tools/release_archive.py" "$verifier"

    log "verifying checksum and archive manifest"
    python3 "$verifier" verify "$archive"
    install -d -m 0755 "$extract_directory"
    tar -xzf "$archive" -C "$extract_directory"

    local project_directory="${extract_directory}/vpngate-manager-${INSTALL_VERSION}"
    [[ -f "${project_directory}/scripts/install.sh" \
        && ! -L "${project_directory}/scripts/install.sh" ]] \
        || fail "verified release does not contain the installer"
    log "starting verified installer"
    bash "${project_directory}/scripts/install.sh"
}

main "$@"
