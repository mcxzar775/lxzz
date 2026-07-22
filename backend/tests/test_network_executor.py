import subprocess
from typing import Any

import pytest

from app.services.network import NetworkCommand, NetworkOperation
from app.services.network.executor import (
    MAX_COMMAND_OUTPUT_BYTES,
    MockNetworkExecutor,
    NetworkCommandExecutionError,
    RealNetworkExecutor,
)


def test_mock_executor_records_only_validated_operations() -> None:
    executor = MockNetworkExecutor()
    command = NetworkCommand(NetworkOperation.NAMESPACE_CREATE, ("lxvpn-9",))

    result = executor.run(command, timeout_seconds=2)

    assert executor.commands == [command]
    assert result.returncode == 0
    assert result.command == command


def test_real_executor_requires_explicit_environment_gate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("VPNGATE_ENABLE_REAL_NETWORK", raising=False)

    with pytest.raises(RuntimeError, match="VPNGATE_ENABLE_REAL_NETWORK=true"):
        RealNetworkExecutor(
            enabled=True,
            sudo_path="/usr/bin/sudo",
            helper_path="/usr/local/libexec/vpngate-manager-helper",
        )


def test_real_executor_invokes_only_noninteractive_fixed_helper(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("VPNGATE_ENABLE_REAL_NETWORK", "true")
    captured: dict[str, Any] = {}

    def fake_run(*args: Any, **kwargs: Any) -> subprocess.CompletedProcess[str]:
        captured["argv"] = args[0]
        captured["kwargs"] = kwargs
        return subprocess.CompletedProcess(
            args[0], 0, stdout="token=private-value\nok", stderr=""
        )

    monkeypatch.setattr(subprocess, "run", fake_run)
    executor = RealNetworkExecutor(
        enabled=True,
        sudo_path="/usr/bin/sudo",
        helper_path="/usr/local/libexec/vpngate-manager-helper",
    )
    command = NetworkCommand(NetworkOperation.NAMESPACE_CREATE, ("lxvpn-5",))

    result = executor.run(command, timeout_seconds=3)

    assert captured["argv"] == (
        "/usr/bin/sudo",
        "-n",
        "--",
        "/usr/local/libexec/vpngate-manager-helper",
        "namespace-create",
        "lxvpn-5",
    )
    kwargs = captured["kwargs"]
    assert "shell" not in kwargs
    assert kwargs["timeout"] == 3
    assert kwargs["close_fds"] is True
    assert "private-value" not in result.stdout
    assert "[REDACTED]" in result.stdout


def test_real_executor_bounds_external_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("VPNGATE_ENABLE_REAL_NETWORK", "true")

    def fake_run(*args: Any, **kwargs: Any) -> subprocess.CompletedProcess[str]:
        del kwargs
        return subprocess.CompletedProcess(
            args[0], 1, stdout="x" * (MAX_COMMAND_OUTPUT_BYTES + 100), stderr=""
        )

    monkeypatch.setattr(subprocess, "run", fake_run)
    executor = RealNetworkExecutor(
        enabled=True,
        sudo_path="/usr/bin/sudo",
        helper_path="/usr/local/libexec/vpngate-manager-helper",
    )

    result = executor.run(
        NetworkCommand(NetworkOperation.SELF_TEST), timeout_seconds=2
    )

    assert result.stdout.endswith("[TRUNCATED]")
    assert len(result.stdout.encode("utf-8")) < MAX_COMMAND_OUTPUT_BYTES + 100


def test_real_executor_normalizes_timeout_without_output_leak(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("VPNGATE_ENABLE_REAL_NETWORK", "true")

    def fake_run(*args: Any, **kwargs: Any) -> subprocess.CompletedProcess[str]:
        del kwargs
        raise subprocess.TimeoutExpired(args[0], 1, output="secret output")

    monkeypatch.setattr(subprocess, "run", fake_run)
    executor = RealNetworkExecutor(
        enabled=True,
        sudo_path="/usr/bin/sudo",
        helper_path="/usr/local/libexec/vpngate-manager-helper",
    )

    with pytest.raises(NetworkCommandExecutionError, match="command_timeout") as captured:
        executor.run(NetworkCommand(NetworkOperation.SELF_TEST), timeout_seconds=1)

    assert "secret output" not in str(captured.value)


@pytest.mark.parametrize("timeout", [0, -1, 121])
def test_executors_reject_unbounded_timeouts(timeout: float) -> None:
    executor = MockNetworkExecutor()

    with pytest.raises(ValueError, match="invalid_timeout"):
        executor.run(NetworkCommand(NetworkOperation.SELF_TEST), timeout_seconds=timeout)
