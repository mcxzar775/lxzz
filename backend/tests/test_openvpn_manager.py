from dataclasses import dataclass, field
from pathlib import Path
import stat

import pytest

from app.services.network import CommandResult, NetworkCommand, NetworkOperation
from app.services.network.executor import RealNetworkExecutor
from app.services.network.openvpn_manager import (
    OpenVPNManager,
    OpenVPNOperationError,
)
from app.services.vpngate.openvpn import sanitize_openvpn_config
from app.services.vpngate.storage import SecureConfigStore
from vpngate_helpers import make_openvpn_config


@dataclass
class OpenVPNExecutor:
    ready_codes: list[int] = field(default_factory=lambda: [0])
    start_code: int = 0
    stop_code: int = 0
    status_code: int = 0
    status_pid: int = 4321
    commands: list[NetworkCommand] = field(default_factory=list)

    def run(self, command: NetworkCommand, *, timeout_seconds: float) -> CommandResult:
        assert 0 < timeout_seconds <= 120
        self.commands.append(command)
        if command.operation is NetworkOperation.OPENVPN_START:
            return CommandResult(command, self.start_code, "", "")
        if command.operation is NetworkOperation.OPENVPN_STOP:
            return CommandResult(command, self.stop_code, "", "")
        if command.operation is NetworkOperation.OPENVPN_STATUS:
            stdout = str(self.status_pid) if self.status_code == 0 else ""
            return CommandResult(command, self.status_code, stdout, "")
        if command.operation is NetworkOperation.OPENVPN_TUN_READY:
            code = self.ready_codes.pop(0) if self.ready_codes else 3
            return CommandResult(command, code, "", "")
        raise AssertionError(f"unexpected operation: {command.operation}")


@dataclass
class FakeTime:
    now: float = 0.0

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += seconds


def _canonical_config() -> str:
    return sanitize_openvpn_config(
        make_openvpn_config(), expected_ip="8.8.8.8"
    ).text


def test_start_stages_config_waits_for_tun_and_returns_managed_pid(
    tmp_path: Path,
) -> None:
    executor = OpenVPNExecutor(ready_codes=[3, 0])
    fake_time = FakeTime()
    store = SecureConfigStore(tmp_path / "configs")
    manager = OpenVPNManager(
        executor,
        store,
        tun_timeout_seconds=5,
        poll_interval_seconds=0.5,
        clock=fake_time.monotonic,
        sleeper=fake_time.sleep,
    )

    runtime = manager.start(2, node_id=9, sanitized_config=_canonical_config())

    assert runtime.running is True
    assert runtime.pid == 4321
    assert runtime.namespace == "lxvpn-2"
    assert runtime.tun_device == "tun0"
    assert [command.operation for command in executor.commands] == [
        NetworkOperation.OPENVPN_START,
        NetworkOperation.OPENVPN_TUN_READY,
        NetworkOperation.OPENVPN_TUN_READY,
        NetworkOperation.OPENVPN_STATUS,
    ]
    config_path = store.path_for(9)
    assert stat.S_IMODE(config_path.stat().st_mode) == 0o600


def test_rejects_tampered_config_before_executor_or_storage(tmp_path: Path) -> None:
    executor = OpenVPNExecutor()
    store = SecureConfigStore(tmp_path / "configs")
    manager = OpenVPNManager(executor, store)
    tampered = _canonical_config() + "up /tmp/untrusted\n"

    with pytest.raises(OpenVPNOperationError, match="openvpn_config_invalid"):
        manager.start(1, node_id=1, sanitized_config=tampered)

    assert executor.commands == []
    assert not store.path_for(1).exists()


def test_stage_config_supports_killswitch_before_openvpn_start(tmp_path: Path) -> None:
    executor = OpenVPNExecutor()
    store = SecureConfigStore(tmp_path / "configs")
    manager = OpenVPNManager(executor, store)

    staged = manager.stage_config(9, _canonical_config())

    assert staged == store.path_for(9)
    assert stat.S_IMODE(staged.stat().st_mode) == 0o600
    assert executor.commands == []


def test_tun_timeout_stops_started_process(tmp_path: Path) -> None:
    executor = OpenVPNExecutor(ready_codes=[3, 3, 3])
    fake_time = FakeTime()
    manager = OpenVPNManager(
        executor,
        SecureConfigStore(tmp_path / "configs"),
        tun_timeout_seconds=1,
        poll_interval_seconds=0.5,
        clock=fake_time.monotonic,
        sleeper=fake_time.sleep,
    )

    with pytest.raises(OpenVPNOperationError, match="openvpn_tun_timeout"):
        manager.start(1, node_id=1, sanitized_config=_canonical_config())

    assert executor.commands[-1].operation is NetworkOperation.OPENVPN_STOP


def test_start_failure_reports_failed_cleanup(tmp_path: Path) -> None:
    executor = OpenVPNExecutor(start_code=1, stop_code=1)
    manager = OpenVPNManager(executor, SecureConfigStore(tmp_path / "configs"))

    with pytest.raises(
        OpenVPNOperationError, match="openvpn_start_failed_cleanup_failed"
    ):
        manager.start(1, node_id=1, sanitized_config=_canonical_config())


def test_status_and_stop_are_idempotent_when_process_is_absent(tmp_path: Path) -> None:
    executor = OpenVPNExecutor(status_code=3)
    manager = OpenVPNManager(executor, SecureConfigStore(tmp_path / "configs"))

    runtime = manager.stop(1, node_id=1)

    assert runtime.running is False
    assert runtime.pid is None


def test_real_executor_requires_separate_openvpn_gate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("VPNGATE_ENABLE_REAL_NETWORK", "true")
    executor = RealNetworkExecutor(
        enabled=True,
        sudo_path="/usr/bin/sudo",
        helper_path="/usr/local/libexec/vpngate-manager-helper",
    )
    manager = OpenVPNManager(
        executor,
        SecureConfigStore(tmp_path / "configs"),
        allow_real_openvpn=False,
    )

    with pytest.raises(OpenVPNOperationError, match="VPNGATE_ENABLE_REAL_OPENVPN"):
        manager.status(1, node_id=1)
