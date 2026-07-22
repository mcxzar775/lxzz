import ast
import logging
from pathlib import Path
import secrets

import pytest
from pydantic import ValidationError
from pydantic import SecretStr

from app.core.config import Settings
from app.core.logging import REDACTED, JsonFormatter, redact, redact_text
from app.services.network import (
    MockNetworkExecutor,
    NetworkCommand,
    NetworkOperation,
    RealNetworkExecutor,
    build_network_executor,
)


def test_sensitive_fields_are_redacted_recursively() -> None:
    password_value = secrets.token_urlsafe(24)
    api_key_value = secrets.token_urlsafe(24)
    payload = {
        "username": "operator",
        "password": password_value,
        "nested": {"api_key": api_key_value, "status": "ok"},
    }
    assert redact(payload) == {
        "username": "operator",
        "password": REDACTED,
        "nested": {"api_key": REDACTED, "status": "ok"},
    }
    record = logging.LogRecord("test", logging.INFO, "", 0, "event", (), None)
    record.fields = payload
    rendered = JsonFormatter().format(record)
    assert password_value not in rendered
    assert api_key_value not in rendered


def test_sensitive_free_text_and_headers_are_redacted() -> None:
    secret_value = secrets.token_urlsafe(24)
    rendered = redact_text(
        f"token={secret_value}\nAuthorization: Bearer {secret_value}\n"
        f"Cookie: session={secret_value}; csrf={secret_value}"
    )

    assert secret_value not in rendered
    assert rendered.count(REDACTED) == 3

    record = logging.LogRecord(
        "test", logging.ERROR, "", 0, f"password={secret_value}", (), None
    )
    assert secret_value not in JsonFormatter().format(record)


def test_network_executor_is_mock_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("VPNGATE_ENABLE_REAL_NETWORK", raising=False)
    executor = build_network_executor(enable_real_network=False)
    assert isinstance(executor, MockNetworkExecutor)
    result = executor.run(
        NetworkCommand(NetworkOperation.SELF_TEST), timeout_seconds=1
    )
    assert result.stdout == "mock execution"
    with pytest.raises(RuntimeError):
        RealNetworkExecutor(
            enabled=True,
            sudo_path="/usr/bin/sudo",
            helper_path="/usr/local/libexec/vpngate-manager-helper",
        )


def test_disabled_setting_wins_even_if_environment_gate_is_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("VPNGATE_ENABLE_REAL_NETWORK", "true")

    assert isinstance(
        build_network_executor(enable_real_network=False), MockNetworkExecutor
    )


def test_production_requires_secure_session_cookie() -> None:
    with pytest.raises(ValidationError):
        Settings(environment="production", cookie_secure=False)
    settings = Settings(environment="production", cookie_secure=True)
    assert settings.cookie_secure is True


def test_namespace_dns_settings_require_unique_public_addresses() -> None:
    with pytest.raises(ValidationError):
        Settings(namespace_dns_servers=("127.0.0.1",))
    with pytest.raises(ValidationError):
        Settings(namespace_dns_servers=("1.1.1.1", "1.1.1.1"))


def test_namespace_dns_settings_load_from_json_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("VPNGATE_NAMESPACE_DNS_SERVERS", '["9.9.9.9"]')

    assert Settings().namespace_dns_servers == ("9.9.9.9",)


def test_real_openvpn_setting_requires_real_network_gate() -> None:
    with pytest.raises(ValidationError):
        Settings(enable_real_network=False, enable_real_openvpn=True)
    with pytest.raises(ValidationError):
        Settings(
            enable_real_network=True,
            enable_real_firewall=False,
            enable_real_openvpn=True,
        )


def test_real_socks_setting_requires_openvpn_and_network_gates() -> None:
    with pytest.raises(ValidationError):
        Settings(
            enable_real_network=True,
            enable_real_openvpn=False,
            enable_real_socks5=True,
        )
    settings = Settings(
        enable_real_network=True,
        enable_real_openvpn=True,
        enable_real_socks5=True,
        enable_real_firewall=True,
    )
    assert settings.enable_real_socks5 is True


def test_socks_port_pool_must_be_ordered() -> None:
    with pytest.raises(ValidationError):
        Settings(socks_port_start=22000, socks_port_end=21000)


def test_real_firewall_setting_requires_real_network_gate() -> None:
    with pytest.raises(ValidationError):
        Settings(enable_real_network=False, enable_real_firewall=True)
    settings = Settings(
        enable_real_network=True,
        enable_real_firewall=True,
        firewall_backend="nftables",
    )
    assert settings.firewall_backend == "nftables"


def test_real_full_scans_require_all_network_feature_gates() -> None:
    with pytest.raises(ValidationError):
        Settings(enable_real_full_scans=True)
    settings = Settings(
        enable_real_network=True,
        enable_real_firewall=True,
        enable_real_openvpn=True,
        enable_real_full_scans=True,
    )
    assert settings.enable_real_full_scans is True


def test_external_ip_intelligence_requires_a_secret_token() -> None:
    with pytest.raises(ValidationError):
        Settings(enable_real_ip_intelligence=True)
    settings = Settings(
        enable_real_ip_intelligence=True,
        ipinfo_api_token=SecretStr("test-token-not-a-real-credential"),
    )
    assert settings.enable_real_ip_intelligence is True
    assert "test-token" not in repr(settings)


def test_real_unlock_checks_require_protected_openvpn_namespace() -> None:
    with pytest.raises(ValidationError):
        Settings(enable_real_unlock_checks=True)
    settings = Settings(
        enable_real_network=True,
        enable_real_firewall=True,
        enable_real_openvpn=True,
        enable_real_unlock_checks=True,
    )
    assert settings.enable_real_unlock_checks is True


def test_real_connection_lifecycle_requires_every_runtime_gate() -> None:
    with pytest.raises(ValidationError):
        Settings(enable_real_connections=True)
    settings = Settings(
        enable_real_network=True,
        enable_real_firewall=True,
        enable_real_openvpn=True,
        enable_real_socks5=True,
        enable_real_full_scans=True,
        enable_real_connections=True,
    )
    assert settings.enable_real_connections is True


def test_real_auto_switch_requires_every_real_runtime_gate() -> None:
    with pytest.raises(ValidationError):
        Settings(enable_real_auto_switch=True)
    settings = Settings(
        enable_real_network=True,
        enable_real_firewall=True,
        enable_real_openvpn=True,
        enable_real_socks5=True,
        enable_real_full_scans=True,
        enable_real_unlock_checks=True,
        enable_real_auto_switch=True,
    )
    assert settings.enable_real_auto_switch is True


def test_auto_switch_policy_setting_names_are_enumerated() -> None:
    settings = Settings(
        auto_switch_allowed_network_types="RESIDENTIAL_LIKELY,PUBLIC_VPN",
        auto_switch_required_services="netflix,chatgpt",
    )
    assert settings.auto_switch_max_per_hour == 5
    with pytest.raises(ValidationError):
        Settings(auto_switch_allowed_network_types="PUBLIC_VPN,arbitrary")
    with pytest.raises(ValidationError):
        Settings(auto_switch_required_services="netflix,arbitrary")


def test_scan_timeouts_and_concurrency_are_bounded() -> None:
    with pytest.raises(ValidationError):
        Settings(scan_concurrency=11)
    with pytest.raises(ValidationError):
        Settings(
            scan_connect_timeout_seconds=20,
            scan_total_timeout_seconds=10,
        )


def test_backend_never_uses_shell_true() -> None:
    app_root = Path(__file__).resolve().parents[1] / "app"
    for path in app_root.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                for keyword in node.keywords:
                    assert not (
                        keyword.arg == "shell"
                        and isinstance(keyword.value, ast.Constant)
                        and keyword.value.value is True
                    ), f"shell=True is forbidden in {path}"
