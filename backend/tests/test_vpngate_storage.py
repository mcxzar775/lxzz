from pathlib import Path
import stat

import pytest

from app.services.vpngate.storage import SecureConfigStore


def test_writes_config_with_owner_only_permissions(tmp_path: Path) -> None:
    store = SecureConfigStore(tmp_path / "configs")

    written = store.write(7, "client\n")

    assert written == store.directory / "node-7.ovpn"
    assert written.read_text(encoding="utf-8") == "client\n"
    assert stat.S_IMODE(written.stat().st_mode) == 0o600
    assert stat.S_IMODE(store.directory.stat().st_mode) == 0o700
    assert not list(store.directory.glob("*.tmp"))


def test_refuses_untrusted_node_identifier(tmp_path: Path) -> None:
    store = SecureConfigStore(tmp_path / "configs")

    with pytest.raises(ValueError, match="positive"):
        store.write(0, "client\n")
