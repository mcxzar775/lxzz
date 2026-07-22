from collections.abc import Callable
import os
from pathlib import Path
import shutil
from typing import Literal

from app.core.config import Settings
from app.schemas.admin import DiagnosticCheckRead


DiagnosticStatus = Literal["PASS", "WARN", "FAIL", "SKIP"]


def _dependency_check(
    *,
    key: str,
    label: str,
    available: bool,
    required: bool,
) -> DiagnosticCheckRead:
    if available:
        return DiagnosticCheckRead(
            key=key,
            label=label,
            status="PASS",
            detail="available",
        )
    return DiagnosticCheckRead(
        key=key,
        label=label,
        status="FAIL" if required else "SKIP",
        detail="required_dependency_missing" if required else "feature_disabled",
    )


def build_runtime_checks(
    settings: Settings,
    *,
    executable_lookup: Callable[[str], str | None] = shutil.which,
) -> list[DiagnosticCheckRead]:
    """Inspect runtime prerequisites without executing privileged commands."""

    helper = Path(settings.root_helper_path)
    checks = [
        _dependency_check(
            key="tun_device",
            label="TUN device",
            available=Path("/dev/net/tun").exists(),
            required=settings.enable_real_openvpn,
        ),
        _dependency_check(
            key="iproute2",
            label="iproute2",
            available=executable_lookup("ip") is not None,
            required=settings.enable_real_network,
        ),
        _dependency_check(
            key="openvpn",
            label="OpenVPN",
            available=executable_lookup("openvpn") is not None,
            required=settings.enable_real_openvpn,
        ),
        _dependency_check(
            key="socks5",
            label="3proxy SOCKS5",
            available=executable_lookup("3proxy") is not None,
            required=settings.enable_real_socks5,
        ),
        _dependency_check(
            key="firewall",
            label="nftables or iptables",
            available=(
                executable_lookup("nft") is not None
                or executable_lookup("iptables") is not None
            ),
            required=settings.enable_real_firewall,
        ),
        _dependency_check(
            key="root_helper",
            label="Restricted root helper",
            available=helper.is_file() and os.access(helper, os.X_OK),
            required=settings.enable_real_network,
        ),
    ]
    return checks
