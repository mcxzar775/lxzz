#!/usr/bin/env bash

set -Eeuo pipefail

PYTHON_BIN="${PYTHON_BIN:-}"

select_python() {
    local candidate
    for candidate in python3.13 python3.12 python3.11 python3.10 python3; do
        if command -v "$candidate" >/dev/null 2>&1 \
            && "$candidate" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)'; then
            PYTHON_BIN="$(command -v "$candidate")"
            return
        fi
    done
    fail "Python 3.10 or newer is required"
}

build_frontend_release() {
    if [[ "${VPNGATE_USE_PREBUILT_FRONTEND:-false}" == "true" ]]; then
        [[ -f "${PROJECT_ROOT}/frontend/dist/index.html" ]] \
            || fail "prebuilt frontend is missing"
        log "using explicitly requested prebuilt frontend"
        return
    fi
    log "building Vue frontend"
    if command -v pnpm >/dev/null 2>&1; then
        (cd "${PROJECT_ROOT}/frontend" && pnpm install --frozen-lockfile && pnpm run build)
    elif command -v corepack >/dev/null 2>&1; then
        (cd "${PROJECT_ROOT}/frontend" && corepack pnpm install --frozen-lockfile && corepack pnpm run build)
    elif command -v npx >/dev/null 2>&1; then
        (cd "${PROJECT_ROOT}/frontend" \
            && npx --yes pnpm@11.9.0 install --frozen-lockfile \
            && npx --yes pnpm@11.9.0 run build)
    else
        fail "pnpm, corepack or npx is required to build the frontend"
    fi
    [[ -f "${PROJECT_ROOT}/frontend/dist/index.html" ]] \
        || fail "frontend build did not produce index.html"
}

validate_release_staging_path() {
    local target="$1"
    [[ "$target" =~ ^/opt/vpngate-manager\.(install|upgrade)\.[A-Za-z0-9]+$ ]] \
        || fail "unsafe release staging path"
}

prepare_release_tree() {
    local target="$1"
    local version="$2"
    local runtime_version
    validate_release_staging_path "$target"
    [[ -d "$target" && ! -L "$target" ]] || fail "release staging directory is unsafe"
    runtime_version="$(sed -n 's/^__version__ = "\([0-9][0-9A-Za-z.+-]*\)"$/\1/p' \
        "${PROJECT_ROOT}/backend/app/__init__.py")"
    [[ "$runtime_version" == "$version" ]] \
        || fail "pyproject and runtime versions do not match"
    chmod 0755 "$target"
    install -d -m 0755 "$target/backend" "$target/frontend/dist"
    cp -a "${PROJECT_ROOT}/backend/app" "$target/backend/"
    cp -a "${PROJECT_ROOT}/backend/alembic" "$target/backend/"
    install -m 0644 "${PROJECT_ROOT}/backend/alembic.ini" "$target/backend/alembic.ini"
    install -m 0644 "${PROJECT_ROOT}/backend/pyproject.toml" "$target/backend/pyproject.toml"
    install -m 0644 "${PROJECT_ROOT}/backend/README.md" "$target/backend/README.md"
    cp -a "${PROJECT_ROOT}/frontend/dist/." "$target/frontend/dist/"
    "$PYTHON_BIN" -m venv "$target/venv"
    "$target/venv/bin/python" -m pip install --disable-pip-version-check --upgrade pip
    "$target/venv/bin/python" -m pip install --disable-pip-version-check "$target/backend"
    printf '%s\n' "$version" >"$target/VERSION"
    chmod 0644 "$target/VERSION"
    chown -R root:root "$target"
    [[ -x "$target/venv/bin/vpngate-root-helper" ]] \
        || fail "release root helper entry point is missing"
}

install_release_helper() {
    local release_dir="$1"
    [[ "$release_dir" == "$APP_DIR" ]] || fail "unexpected release directory"
    command -v visudo >/dev/null 2>&1 || fail "visudo from sudo is required"
    visudo -cf "${PROJECT_ROOT}/deploy/sudoers/vpngate-manager" >/dev/null \
        || fail "bundled sudoers policy is invalid"
    install -d -m 0755 /usr/local/libexec /etc/sudoers.d
    install -m 0755 -o root -g root \
        "${release_dir}/venv/bin/vpngate-root-helper" "$ROOT_HELPER_PATH"
    install -m 0440 -o root -g root \
        "${PROJECT_ROOT}/deploy/sudoers/vpngate-manager" "$SUDOERS_FILE"
    visudo -cf "$SUDOERS_FILE" >/dev/null \
        || fail "installed sudoers policy is invalid"
}

install_service_assets() {
    install -m 0644 -o root -g root \
        "${PROJECT_ROOT}/deploy/systemd/vpngate-manager.service" "$SERVICE_FILE"
    if [[ -d /etc/nginx/sites-available && -d /etc/nginx/sites-enabled ]]; then
        install -m 0644 -o root -g root \
            "${PROJECT_ROOT}/deploy/nginx/vpngate-manager.conf" \
            /etc/nginx/sites-available/vpngate-manager.conf
        ln -sfn /etc/nginx/sites-available/vpngate-manager.conf \
            /etc/nginx/sites-enabled/vpngate-manager.conf
    else
        install -m 0644 -o root -g root \
            "${PROJECT_ROOT}/deploy/nginx/vpngate-manager.conf" \
            /etc/nginx/conf.d/vpngate-manager.conf
    fi
    nginx -t
    systemctl daemon-reload
}

run_database_migrations() {
    (cd "$APP_DIR/backend" \
        && run_as_service_user_with_env "$APP_DIR/venv/bin/alembic" upgrade head)
}

verify_installed_version() {
    local expected_version="$1"
    local health_payload
    health_payload="$(curl --fail --silent --show-error --max-time 5 \
        http://127.0.0.1:8765/healthz)"
    [[ "$health_payload" == *"\"version\":\"${expected_version}\""* ]] \
        || fail "running backend version does not match the installed release"
}
