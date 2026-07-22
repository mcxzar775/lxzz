UV ?= uv
PNPM ?= pnpm
UV_CACHE_DIR ?= $(CURDIR)/work/uv-cache
PNPM_STORE_DIR ?= $(CURDIR)/work/pnpm-store
export UV_CACHE_DIR

.PHONY: install-dev backend-sync frontend-sync test backend-test frontend-test shell-check build backend-build frontend-build acceptance release release-check verify-release

install-dev: backend-sync frontend-sync

backend-sync:
	cd backend && $(UV) sync --group dev

frontend-sync:
	cd frontend && $(PNPM) install --frozen-lockfile --store-dir "$(PNPM_STORE_DIR)"

test: backend-test frontend-test shell-check

backend-test: backend-sync
	cd backend && $(UV) run python -m compileall -q app tests ../tools
	cd backend && $(UV) run mypy app tests ../tools/release_archive.py
	cd backend && $(UV) run python -m pytest

acceptance: backend-sync
	cd backend && $(UV) run python -m pytest tests/test_acceptance.py tests/test_startup_recovery.py

frontend-test: frontend-sync
	cd frontend && $(PNPM) run typecheck

shell-check:
	@for script in scripts/*.sh; do bash -n "$$script"; done
	@if command -v shellcheck >/dev/null 2>&1; then shellcheck scripts/*.sh; else echo "shellcheck not installed; skipped"; fi

build: backend-build frontend-build

backend-build: backend-sync
	cd backend && $(UV) build

frontend-build: frontend-sync
	cd frontend && $(PNPM) run build

release: build
	bash scripts/build-release.sh

verify-release:
	bash scripts/verify-release.sh

release-check: test release
	bash scripts/release-check.sh
