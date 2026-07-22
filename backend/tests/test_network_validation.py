from pathlib import Path

import pytest

from app.services.network.validation import (
    ResourceValidationError,
    tun_name,
    validate_managed_config_path,
    validate_port,
    validate_remote_endpoint,
    validate_tun_name,
)


def test_validates_generated_tun_names() -> None:
    assert tun_name(12) == "tun12"
    assert validate_tun_name("tun12") == "tun12"

    with pytest.raises(ResourceValidationError, match="invalid_tun_name"):
        validate_tun_name("tun0;id")


@pytest.mark.parametrize("value", [False, 0, -1, 65536])
def test_rejects_invalid_ports(value: int) -> None:
    with pytest.raises(ResourceValidationError, match="invalid_port"):
        validate_port(value)


def test_validates_public_remote_endpoint() -> None:
    endpoint = validate_remote_endpoint("8.8.8.8", 1194, "UDP")

    assert endpoint.address == "8.8.8.8"
    assert endpoint.port == 1194
    assert endpoint.protocol == "udp"


@pytest.mark.parametrize("address", ["127.0.0.1", "10.0.0.1", "not-an-ip"])
def test_rejects_non_public_remote_endpoint(address: str) -> None:
    with pytest.raises(ResourceValidationError, match="invalid_remote_address"):
        validate_remote_endpoint(address, 1194, "udp")


def test_accepts_only_exact_managed_config_filename(tmp_path: Path) -> None:
    root = tmp_path / "configs"
    root.mkdir()
    expected = root / "node-9.ovpn"

    assert (
        validate_managed_config_path(expected, directory=root, node_id=9) == expected
    )
    with pytest.raises(ResourceValidationError, match="invalid_managed_path"):
        validate_managed_config_path(
            root / "../credentials", directory=root, node_id=9
        )
    with pytest.raises(ResourceValidationError, match="invalid_managed_path"):
        validate_managed_config_path(root / "node-8.ovpn", directory=root, node_id=9)
