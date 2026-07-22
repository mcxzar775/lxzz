import pytest

from app.services.vpngate.openvpn import (
    DANGEROUS_DIRECTIVES,
    sanitize_openvpn_config,
    validate_stored_openvpn_config,
)
from app.services.vpngate.types import OpenVPNConfigError
from vpngate_helpers import make_openvpn_config


def test_sanitizes_valid_config_and_builds_stable_hash() -> None:
    raw = b"# ignored source comment\n" + make_openvpn_config()
    first = sanitize_openvpn_config(raw, expected_ip="8.8.8.8")
    second = sanitize_openvpn_config(make_openvpn_config(), expected_ip="8.8.8.8")

    assert first.text == second.text
    assert first.config_hash == second.config_hash
    assert len(first.config_hash) == 64
    assert first.remote_ip == "8.8.8.8"
    assert first.remote_port == 1194
    assert first.protocol == "udp"
    assert "ignored source comment" not in first.text


@pytest.mark.parametrize("directive", sorted(DANGEROUS_DIRECTIVES))
def test_rejects_every_dangerous_directive(directive: str) -> None:
    raw = make_openvpn_config(extra_directive=f"{directive} /tmp/untrusted")

    with pytest.raises(OpenVPNConfigError) as captured:
        sanitize_openvpn_config(raw, expected_ip="8.8.8.8")

    assert captured.value.code == "dangerous_directive"
    assert "/tmp/untrusted" not in str(captured.value)


def test_rejects_unknown_directive_and_arbitrary_path() -> None:
    raw = make_openvpn_config(extra_directive="log /tmp/untrusted.log")

    with pytest.raises(OpenVPNConfigError, match="unsupported_directive"):
        sanitize_openvpn_config(raw, expected_ip="8.8.8.8")


def test_rejects_remote_address_mismatch() -> None:
    raw = make_openvpn_config(ip_address="1.1.1.1")

    with pytest.raises(OpenVPNConfigError, match="remote_address_mismatch"):
        sanitize_openvpn_config(raw, expected_ip="8.8.8.8")


def test_rejects_private_remote_address() -> None:
    raw = make_openvpn_config(ip_address="10.0.0.10")

    with pytest.raises(OpenVPNConfigError, match="remote_address_mismatch"):
        sanitize_openvpn_config(raw, expected_ip="10.0.0.10")


def test_rejects_conflicting_protocols() -> None:
    raw = make_openvpn_config(protocol="udp").replace(
        b"remote 8.8.8.8 1194", b"remote 8.8.8.8 1194 tcp"
    )

    with pytest.raises(OpenVPNConfigError, match="protocol_mismatch"):
        sanitize_openvpn_config(raw, expected_ip="8.8.8.8")


@pytest.mark.parametrize("directive", ["cipher none", "auth null", "compress lz4"])
def test_rejects_insecure_transport_options(directive: str) -> None:
    raw = make_openvpn_config(extra_directive=directive)

    with pytest.raises(OpenVPNConfigError):
        sanitize_openvpn_config(raw, expected_ip="8.8.8.8")


def test_privileged_revalidation_accepts_only_exact_canonical_config() -> None:
    canonical = sanitize_openvpn_config(
        make_openvpn_config(), expected_ip="8.8.8.8"
    ).text.encode("utf-8")

    assert validate_stored_openvpn_config(canonical).remote_ip == "8.8.8.8"
    with pytest.raises(OpenVPNConfigError, match="stored_config_not_canonical"):
        validate_stored_openvpn_config(b"# comment\n" + canonical)
    with pytest.raises(OpenVPNConfigError, match="dangerous_directive"):
        validate_stored_openvpn_config(canonical + b"up /tmp/untrusted\n")
