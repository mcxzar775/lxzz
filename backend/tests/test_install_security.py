from pathlib import Path


def test_sudoers_grants_only_the_fixed_root_helper() -> None:
    project_root = Path(__file__).resolve().parents[2]
    policy = (project_root / "deploy/sudoers/vpngate-manager").read_text(
        encoding="utf-8"
    )

    assert "NOPASSWD: ALL" not in policy
    command_lines = [line for line in policy.splitlines() if "NOPASSWD:" in line]
    assert command_lines == [
        "vpngate-manager ALL=(root) NOPASSWD: "
        "/usr/local/libexec/vpngate-manager-helper *"
    ]


def test_service_account_cannot_modify_helper_or_application_code() -> None:
    project_root = Path(__file__).resolve().parents[2]
    release_library = (project_root / "scripts/release-lib.sh").read_text(
        encoding="utf-8"
    )

    assert "install -m 0755 -o root -g root" in release_library
    assert '"${PROJECT_ROOT}/deploy/bin/vpngate-manager-helper.sh" "$ROOT_HELPER_PATH"' in release_library
    assert 'chown -R root:root "$target"' in release_library


def test_release_root_is_traversable_by_the_service_account() -> None:
    project_root = Path(__file__).resolve().parents[2]
    release_library = (project_root / "scripts/release-lib.sh").read_text(
        encoding="utf-8"
    )

    assert 'chmod 0755 "$target"' in release_library
    assert release_library.index('chmod 0755 "$target"') < release_library.index(
        'install -d -m 0755 "$target/backend"'
    )


def test_runtime_does_not_execute_relocated_virtualenv_entry_points() -> None:
    project_root = Path(__file__).resolve().parents[2]
    release_library = (project_root / "scripts/release-lib.sh").read_text(
        encoding="utf-8"
    )
    service = (project_root / "deploy/systemd/vpngate-manager.service").read_text(
        encoding="utf-8"
    )
    helper = (project_root / "deploy/bin/vpngate-manager-helper.sh").read_text(
        encoding="utf-8"
    )

    assert 'venv/bin/alembic"' not in release_library
    assert "venv/bin/uvicorn" not in service
    assert "venv/bin/vpngate-root-helper" not in release_library
    assert "/venv/bin/python -I -m uvicorn" in service
    assert '"$VPNGATE_PYTHON" -I -m app.root_helper' in helper


def test_3proxy_source_download_is_versioned_and_checksum_verified() -> None:
    project_root = Path(__file__).resolve().parents[2]
    installer = (project_root / "scripts/install.sh").read_text(encoding="utf-8")

    assert 'readonly THREEPROXY_VERSION="0.9.6"' in installer
    assert 'readonly THREEPROXY_SHA256="5645111f' in installer
    assert "sha256sum --check --status" in installer
    assert "archive/refs/tags/${THREEPROXY_VERSION}.tar.gz" in installer


def test_installer_defaults_all_switch_execution_to_disabled() -> None:
    project_root = Path(__file__).resolve().parents[2]
    installer = (project_root / "scripts/install.sh").read_text(encoding="utf-8")

    assert "VPNGATE_AUTO_SWITCH_MAX_PER_HOUR=5" in installer
    assert "VPNGATE_ENABLE_AUTO_SWITCH=false" in installer
    assert "VPNGATE_ENABLE_REAL_CONNECTIONS=false" in installer
    assert "VPNGATE_ENABLE_REAL_AUTO_SWITCH=false" in installer


def test_maintenance_scripts_are_present_and_serialized() -> None:
    project_root = Path(__file__).resolve().parents[2]
    for name in (
        "install.sh",
        "upgrade.sh",
        "repair.sh",
        "diagnose.sh",
        "install-from-github.sh",
        "reset-password.sh",
        "uninstall.sh",
    ):
        path = project_root / "scripts" / name
        assert path.is_file()
        text = path.read_text(encoding="utf-8")
        if name not in {"diagnose.sh", "install-from-github.sh"}:
            assert "acquire_maintenance_lock" in text


def test_installer_reloads_preexisting_nginx_process() -> None:
    project_root = Path(__file__).resolve().parents[2]
    installer = (project_root / "scripts/install.sh").read_text(encoding="utf-8")

    assert "systemctl enable nginx.service" in installer
    assert "systemctl reload-or-restart nginx.service" in installer
    assert installer.index("systemctl enable nginx.service") < installer.index(
        "systemctl reload-or-restart nginx.service"
    )


def test_environment_file_is_never_sourced_as_root() -> None:
    project_root = Path(__file__).resolve().parents[2]
    scripts = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (project_root / "scripts").glob("*.sh")
    )

    assert 'source "$ENV_FILE"' not in scripts
    assert "run_as_service_user_with_env" in scripts
    assert "configuration contains an invalid assignment" in scripts
    assert "env -i" in scripts


def test_upgrade_backs_up_and_rolls_back_before_reporting_success() -> None:
    project_root = Path(__file__).resolve().parents[2]
    upgrade = (project_root / "scripts/upgrade.sh").read_text(encoding="utf-8")

    assert "create_upgrade_backup" in upgrade
    assert "database.sqlite3" in upgrade
    assert "run_database_migrations" in upgrade
    assert "rollback_upgrade" in upgrade
    assert "wait_for_health 30" in upgrade
    assert "verify_installed_version" in upgrade
    assert "VPNGATE_UPGRADE_ALLOW_EXTERNAL_DATABASE" in upgrade
    main_section = upgrade.split("main() {", maxsplit=1)[1]
    assert main_section.index("systemctl stop vpngate-manager.service") < main_section.index(
        'cp -a -- "$DATABASE_PATH" "${UPGRADE_BACKUP}/database.sqlite3"'
    )


def test_noninteractive_passwords_use_private_files_not_password_argv() -> None:
    project_root = Path(__file__).resolve().parents[2]
    installer = (project_root / "scripts/install.sh").read_text(encoding="utf-8")
    resetter = (project_root / "scripts/reset-password.sh").read_text(
        encoding="utf-8"
    )

    assert "--password-file" in installer
    assert "--password-file" in resetter
    assert "chmod 0600" in installer
    assert "chmod 0600" in resetter
    assert '--password "$VPNGATE_ADMIN_PASSWORD"' not in installer
    assert '--password "$VPNGATE_RESET_PASSWORD"' not in resetter


def test_optional_shell_guards_return_success_under_errexit() -> None:
    project_root = Path(__file__).resolve().parents[2]
    scripts = [
        project_root / "scripts/install.sh",
        project_root / "scripts/reset-password.sh",
        project_root / "scripts/repair.sh",
        project_root / "scripts/upgrade.sh",
        project_root / "scripts/uninstall.sh",
    ]

    for script in scripts:
        text = script.read_text(encoding="utf-8")
        assert "] || return\n" not in text


def test_uninstall_cleans_managed_resources_before_removing_helper() -> None:
    project_root = Path(__file__).resolve().parents[2]
    uninstall = (project_root / "scripts/uninstall.sh").read_text(encoding="utf-8")

    assert '"$ROOT_HELPER_PATH" connection-purge "$identifier"' in uninstall
    assert "runtime_connection_ids" in uninstall
    assert uninstall.index("purge_managed_runtime") < uninstall.index(
        'rm -f "$ROOT_HELPER_PATH"'
    )
    assert "service account preserved" in uninstall


def test_systemd_preserves_runtime_state_for_verified_cleanup() -> None:
    project_root = Path(__file__).resolve().parents[2]
    unit = (project_root / "deploy/systemd/vpngate-manager.service").read_text(
        encoding="utf-8"
    )

    assert "RuntimeDirectoryPreserve=yes" in unit
    assert "ProtectSystem=strict" in unit
    assert "WorkingDirectory=/opt/vpngate-manager/backend" in unit
