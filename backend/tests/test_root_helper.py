import subprocess
import json
from pathlib import Path
import os
import stat
from types import SimpleNamespace
from typing import Any

import pytest

from app import root_helper
from app.services.network import CommandValidationError, NetworkCommand, NetworkOperation
from app.services.vpngate.openvpn import sanitize_openvpn_config
from app.services.network.socks5 import SecureSocksSpecStore, Socks5Spec
from vpngate_helpers import make_openvpn_config


def test_helper_parses_only_known_fixed_operation() -> None:
    command = root_helper.parse_command(["namespace-create", "lxvpn-6"])

    assert command.operation is NetworkOperation.NAMESPACE_CREATE
    assert command.arguments == ("lxvpn-6",)


@pytest.mark.parametrize(
    "arguments",
    [
        [],
        ["run", "id"],
        ["namespace-create", "lxvpn-1;id"],
        ["namespace-delete", "lxvpn-1", "extra"],
    ],
)
def test_helper_rejects_unknown_or_injected_arguments(arguments: list[str]) -> None:
    with pytest.raises(CommandValidationError):
        root_helper.parse_command(arguments)


def test_helper_self_test_does_not_start_subprocess(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden_run(*args: Any, **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        del args, kwargs
        raise AssertionError("subprocess must not run")

    monkeypatch.setattr(subprocess, "run", forbidden_run)
    command = root_helper.parse_command(["self-test"])

    assert root_helper.execute(command) == 0


def test_helper_connection_purge_bypasses_enable_gate_only_for_fixed_cleanup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: list[tuple[str, ...]] = []

    def fake_purge(command: NetworkCommand) -> int:
        captured.append(command.arguments)
        return 0

    monkeypatch.setattr(
        root_helper,
        "_purge_connection",
        fake_purge,
    )
    monkeypatch.setattr(
        root_helper,
        "real_network_enabled",
        lambda: (_ for _ in ()).throw(AssertionError("cleanup must bypass feature gate")),
    )

    command = root_helper.parse_command(["connection-purge", "7"])

    assert root_helper.execute(command) == 0
    assert captured == [("7",)]


def test_helper_connection_purge_cleans_only_derived_resources(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cleaned: list[tuple[str, int]] = []
    monkeypatch.setattr(root_helper, "_stop_socks", lambda command: 0)
    monkeypatch.setattr(root_helper, "_stop_openvpn", lambda command: 0)
    monkeypatch.setattr(root_helper, "_find_ip_binary", lambda: "/usr/sbin/ip")
    monkeypatch.setattr(root_helper, "_read_firewall_state", lambda _identifier: None)
    monkeypatch.setattr(
        root_helper,
        "_cleanup_firewall_backend",
        lambda spec, backend, **_kwargs: cleaned.append((backend, spec.connection_id)),
    )
    monkeypatch.setattr(
        root_helper,
        "_firewall_backend_has_residue",
        lambda *_args, **_kwargs: False,
    )
    monkeypatch.setattr(root_helper, "_delete_firewall_state", lambda _identifier: None)
    monkeypatch.setattr(root_helper, "_delete_namespace_dns", lambda command: 0)
    monkeypatch.setattr(root_helper, "_namespace_exists", lambda namespace: False)
    monkeypatch.setattr(root_helper, "_host_veth_exists", lambda _ip, _veth: False)

    command = root_helper.parse_command(["connection-purge", "7"])

    assert root_helper._purge_connection(command) == 0
    assert cleaned == [("nftables", 7), ("iptables", 7)]


def test_helper_requires_root_owned_configuration_gate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden_run(*args: Any, **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        del args, kwargs
        raise AssertionError("subprocess must not run")

    monkeypatch.setattr(subprocess, "run", forbidden_run)
    monkeypatch.setattr(root_helper, "real_network_enabled", lambda: False)
    command = root_helper.parse_command(["namespace-delete", "lxvpn-1"])

    assert root_helper.execute(command) == 78


def test_helper_enable_parser_requires_exact_true_assignment() -> None:
    assert root_helper._enabled_from_text("VPNGATE_ENABLE_REAL_NETWORK=true\n")
    assert not root_helper._enabled_from_text("VPNGATE_ENABLE_REAL_NETWORK=false\n")
    assert not root_helper._enabled_from_text("VPNGATE_ENABLE_REAL_NETWORK=true # unsafe\n")
    assert not root_helper._enabled_from_text(
        "VPNGATE_ENABLE_REAL_NETWORK=false\nVPNGATE_ENABLE_REAL_NETWORK=true\n"
    )


def test_helper_openvpn_gate_requires_network_firewall_and_openvpn_flags() -> None:
    enabled = (
        "VPNGATE_ENABLE_REAL_NETWORK=true\n"
        "VPNGATE_ENABLE_REAL_FIREWALL=true\n"
        "VPNGATE_ENABLE_REAL_OPENVPN=true\n"
    )

    assert root_helper._openvpn_enabled_from_text(enabled)
    assert not root_helper._openvpn_enabled_from_text(
        "VPNGATE_ENABLE_REAL_NETWORK=true\nVPNGATE_ENABLE_REAL_OPENVPN=false\n"
    )
    assert not root_helper._openvpn_enabled_from_text(
        enabled.replace(
            "VPNGATE_ENABLE_REAL_FIREWALL=true",
            "VPNGATE_ENABLE_REAL_FIREWALL=false",
        )
    )


def test_helper_socks_gate_requires_all_exact_feature_flags() -> None:
    enabled = (
        "VPNGATE_ENABLE_REAL_NETWORK=true\n"
        "VPNGATE_ENABLE_REAL_FIREWALL=true\n"
        "VPNGATE_ENABLE_REAL_OPENVPN=true\n"
        "VPNGATE_ENABLE_REAL_SOCKS5=true\n"
    )

    assert root_helper._socks_enabled_from_text(enabled)
    assert not root_helper._socks_enabled_from_text(
        enabled.replace("VPNGATE_ENABLE_REAL_OPENVPN=true", "VPNGATE_ENABLE_REAL_OPENVPN=false")
    )
    assert root_helper._socks_port_range_from_text(enabled) == (21000, 21999)
    assert root_helper._socks_port_range_from_text(
        enabled + "VPNGATE_SOCKS_PORT_START=22000\nVPNGATE_SOCKS_PORT_END=22010\n"
    ) == (22000, 22010)
    assert root_helper._socks_port_range_from_text(
        enabled + "VPNGATE_SOCKS_PORT_START=22000;id\n"
    ) is None


def test_helper_maps_operation_to_fixed_ip_binary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    def fake_run(*args: Any, **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        captured["argv"] = args[0]
        captured["kwargs"] = kwargs
        return subprocess.CompletedProcess(args[0], 0)

    monkeypatch.setattr(root_helper, "_find_ip_binary", lambda: "/usr/sbin/ip")
    monkeypatch.setattr(root_helper, "real_network_enabled", lambda: True)
    monkeypatch.setattr(subprocess, "run", fake_run)
    command = root_helper.parse_command(["veth-delete", "lvh4"])

    assert root_helper.execute(command) == 0
    assert captured["argv"] == ("/usr/sbin/ip", "link", "delete", "lvh4")
    assert "shell" not in captured["kwargs"]
    assert captured["kwargs"]["timeout"] == root_helper.HELPER_TIMEOUT_SECONDS


def test_helper_writes_and_removes_only_managed_namespace_dns(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_root = tmp_path / "netns"
    monkeypatch.setattr(root_helper, "NETNS_CONFIG_DIRECTORY", config_root)
    monkeypatch.setattr(root_helper, "real_network_enabled", lambda: True)
    write_command = root_helper.parse_command(
        ["namespace-dns-write", "lxvpn-2", "1.1.1.1", "8.8.8.8"]
    )

    assert root_helper.execute(write_command) == 0
    target = config_root / "lxvpn-2/resolv.conf"
    assert target.read_text(encoding="utf-8") == (
        "nameserver 1.1.1.1\nnameserver 8.8.8.8\n"
    )
    assert stat.S_IMODE(target.stat().st_mode) == 0o644
    assert stat.S_IMODE(target.parent.stat().st_mode) == 0o755

    delete_command = root_helper.parse_command(
        ["namespace-dns-delete", "lxvpn-2"]
    )
    assert root_helper.execute(delete_command) == 0
    assert root_helper.execute(delete_command) == 0
    assert not target.exists()


def test_helper_refuses_symlinked_namespace_dns_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_root = tmp_path / "netns"
    outside = tmp_path / "outside"
    config_root.mkdir()
    outside.mkdir()
    (config_root / "lxvpn-2").symlink_to(outside, target_is_directory=True)
    monkeypatch.setattr(root_helper, "NETNS_CONFIG_DIRECTORY", config_root)
    monkeypatch.setattr(root_helper, "real_network_enabled", lambda: True)
    command = root_helper.parse_command(
        ["namespace-dns-write", "lxvpn-2", "1.1.1.1"]
    )

    assert root_helper.execute(command) == 126
    assert not (outside / "resolv.conf").exists()


def test_helper_namespace_delete_is_idempotent_without_ip_binary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(root_helper, "NETNS_RUN_DIRECTORIES", (tmp_path,))
    monkeypatch.setattr(root_helper, "real_network_enabled", lambda: True)
    monkeypatch.setattr(
        root_helper,
        "_find_ip_binary",
        lambda: (_ for _ in ()).throw(AssertionError("ip must not be resolved")),
    )
    command = root_helper.parse_command(["namespace-delete", "lxvpn-9"])

    assert root_helper.execute(command) == 0


def test_helper_revalidates_stored_openvpn_config_before_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_root = tmp_path / "configs"
    config_root.mkdir(mode=0o700)
    canonical = sanitize_openvpn_config(
        make_openvpn_config(), expected_ip="8.8.8.8"
    ).text
    target = config_root / "node-4.ovpn"
    target.write_text(canonical, encoding="utf-8")
    target.chmod(0o600)
    monkeypatch.setattr(root_helper, "OPENVPN_CONFIG_DIRECTORY", config_root)
    monkeypatch.setattr(root_helper, "_service_uid", os.geteuid)

    assert root_helper._validate_openvpn_config_file("4") == target

    target.write_text(canonical + "up /tmp/untrusted\n", encoding="utf-8")
    target.chmod(0o600)
    with pytest.raises(RuntimeError, match="unsafe_openvpn_config"):
        root_helper._validate_openvpn_config_file("4")


def test_helper_refuses_symlinked_openvpn_config(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_root = tmp_path / "configs"
    config_root.mkdir(mode=0o700)
    outside = tmp_path / "outside.ovpn"
    outside.write_bytes(make_openvpn_config())
    (config_root / "node-4.ovpn").symlink_to(outside)
    monkeypatch.setattr(root_helper, "OPENVPN_CONFIG_DIRECTORY", config_root)
    monkeypatch.setattr(root_helper, "_service_uid", os.geteuid)

    with pytest.raises(RuntimeError, match="unsafe_openvpn_config"):
        root_helper._validate_openvpn_config_file("4")


def test_helper_openvpn_start_uses_only_fixed_paths_and_arguments(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}
    config_path = tmp_path / "node-3.ovpn"
    config_path.write_text("validated", encoding="utf-8")
    runtime_directory = tmp_path / "run/openvpn"
    log_directory = tmp_path / "log/openvpn"
    monkeypatch.setattr(root_helper, "OPENVPN_RUNTIME_DIRECTORY", runtime_directory)
    monkeypatch.setattr(root_helper, "OPENVPN_LOG_DIRECTORY", log_directory)
    monkeypatch.setattr(root_helper, "_managed_openvpn_pid", lambda _: None)
    monkeypatch.setattr(
        root_helper,
        "_load_validated_openvpn_config",
        lambda _: (config_path, b"validated"),
    )
    monkeypatch.setattr(root_helper, "_find_openvpn_binary", lambda: "/usr/sbin/openvpn")

    def fake_run(*args: Any, **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        captured["argv"] = args[0]
        captured["kwargs"] = kwargs
        return subprocess.CompletedProcess(args[0], 0)

    monkeypatch.setattr(subprocess, "run", fake_run)
    command = root_helper.parse_command(["openvpn-start", "lxvpn-2", "2", "3"])

    assert root_helper._start_openvpn(command, "/usr/sbin/ip") == 0
    argv = captured["argv"]
    assert argv[:6] == (
        "/usr/sbin/ip",
        "netns",
        "exec",
        "lxvpn-2",
        "/usr/sbin/openvpn",
        "--config",
    )
    assert str(runtime_directory / "openvpn-2.ovpn") in argv
    assert (runtime_directory / "openvpn-2.ovpn").read_bytes() == b"validated"
    assert str(runtime_directory / "openvpn-2.pid") in argv
    assert str(log_directory / "openvpn-2.log") in argv
    assert ("--script-security", "1") == (
        argv[argv.index("--script-security")],
        argv[argv.index("--script-security") + 1],
    )
    assert "shell" not in captured["kwargs"]


def test_helper_refuses_to_signal_unmanaged_pid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    killed: list[tuple[int, int]] = []
    monkeypatch.setattr(
        root_helper,
        "_managed_openvpn_pid",
        lambda _: (_ for _ in ()).throw(RuntimeError("unmanaged_openvpn_process")),
    )
    monkeypatch.setattr(os, "kill", lambda pid, sig: killed.append((pid, sig)))
    command = root_helper.parse_command(["openvpn-stop", "2"])

    assert root_helper._stop_openvpn(command) == 126
    assert killed == []


def test_helper_accepts_pid_only_when_proc_identity_and_arguments_match(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime_directory = tmp_path / "run"
    process_directory = tmp_path / "proc/4321"
    runtime_directory.mkdir()
    process_directory.mkdir(parents=True)
    binary = tmp_path / "openvpn"
    binary.write_text("binary", encoding="utf-8")
    binary.chmod(0o755)
    (process_directory / "exe").symlink_to(binary)
    pid_path = runtime_directory / "openvpn-2.pid"
    pid_path.write_text("4321\n", encoding="ascii")
    pid_path.chmod(0o600)
    command_line = [
        str(binary),
        "--writepid",
        str(pid_path),
        "--daemon",
        "vpngate-2",
        "--config",
        str(runtime_directory / "openvpn-2.ovpn"),
    ]
    (process_directory / "cmdline").write_bytes(
        b"\x00".join(item.encode("utf-8") for item in command_line) + b"\x00"
    )
    monkeypatch.setattr(root_helper, "OPENVPN_RUNTIME_DIRECTORY", runtime_directory)
    monkeypatch.setattr(root_helper, "PROC_DIRECTORY", tmp_path / "proc")
    monkeypatch.setattr(root_helper, "OPENVPN_BINARY_CANDIDATES", (str(binary),))

    assert root_helper._managed_openvpn_pid("2") == 4321

    (process_directory / "cmdline").write_bytes(b"unrelated\x00process\x00")
    with pytest.raises(RuntimeError, match="unmanaged_openvpn_process"):
        root_helper._managed_openvpn_pid("2")


def test_helper_tun_ready_requires_up_link_and_default_route(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    outputs = [
        "7: tun0: <POINTOPOINT,UP,LOWER_UP> mtu 1500 state UNKNOWN\n",
        "default via 10.8.0.1 dev tun0\n",
    ]

    def fake_run(*args: Any, **kwargs: Any) -> subprocess.CompletedProcess[str]:
        del kwargs
        return subprocess.CompletedProcess(args[0], 0, stdout=outputs.pop(0), stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    command = root_helper.parse_command(["openvpn-tun-ready", "lxvpn-2", "2"])

    assert root_helper._openvpn_tun_ready(command, "/usr/sbin/ip") == 0


def test_execute_requires_separate_openvpn_gate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(root_helper, "real_network_enabled", lambda: True)
    monkeypatch.setattr(root_helper, "real_openvpn_enabled", lambda: False)
    monkeypatch.setattr(
        root_helper,
        "_find_ip_binary",
        lambda: (_ for _ in ()).throw(AssertionError("ip must not run")),
    )
    command = root_helper.parse_command(["openvpn-status", "2"])

    assert root_helper.execute(command) == 78


def test_helper_revalidates_canonical_socks_spec_and_rejects_tampering(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spec_directory = tmp_path / "specs"
    store = SecureSocksSpecStore(spec_directory)
    spec = Socks5Spec(
        connection_id=2,
        endpoint_id=7,
        port=21002,
        username="proxy_user",
        password="abcdefghijklmnopqrstuvwxyz_123456",
        client_ip_allowlist=("198.51.100.7/32",),
        max_connections=20,
        timeout_seconds=90,
    )
    target = store.write(spec)
    monkeypatch.setattr(root_helper, "SOCKS_SPEC_DIRECTORY", spec_directory)
    monkeypatch.setattr(root_helper, "_service_uid", os.geteuid)
    monkeypatch.setattr(root_helper, "trusted_socks_port_range", lambda: (21000, 21999))

    validated = root_helper._load_validated_socks_spec("2", "7")

    assert validated.connection_id == 2
    assert validated.port == 21002
    assert validated.client_ip_allowlist == ("198.51.100.7/32",)
    target.write_bytes(target.read_bytes() + b" \n")
    target.chmod(0o600)
    with pytest.raises(RuntimeError, match="unsafe_socks_spec"):
        root_helper._load_validated_socks_spec("2", "7")


def test_helper_refuses_symlinked_socks_spec(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spec_directory = tmp_path / "specs"
    spec_directory.mkdir(mode=0o700)
    outside = tmp_path / "outside.json"
    outside.write_text("{}\n", encoding="utf-8")
    (spec_directory / "endpoint-7.json").symlink_to(outside)
    monkeypatch.setattr(root_helper, "SOCKS_SPEC_DIRECTORY", spec_directory)
    monkeypatch.setattr(root_helper, "_service_uid", os.geteuid)
    monkeypatch.setattr(root_helper, "trusted_socks_port_range", lambda: (21000, 21999))

    with pytest.raises(RuntimeError, match="unsafe_socks_spec"):
        root_helper._load_validated_socks_spec("2", "7")


def test_helper_socks_start_uses_fixed_paths_without_password_in_argv(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}
    runtime_directory = tmp_path / "run/socks"
    log_directory = tmp_path / "log/socks"
    password = "abcdefghijklmnopqrstuvwxyz_123456"
    spec = root_helper._ValidatedSocksSpec(
        connection_id=2,
        endpoint_id=7,
        port=21002,
        username="proxy_user",
        password=password,
        client_ip_allowlist=("198.51.100.7/32",),
        bind_address="0.0.0.0",
        max_connections=20,
        timeout_seconds=90,
    )
    monkeypatch.setattr(root_helper, "SOCKS_RUNTIME_DIRECTORY", runtime_directory)
    monkeypatch.setattr(root_helper, "SOCKS_LOG_DIRECTORY", log_directory)
    monkeypatch.setattr(root_helper, "_tun_ready", lambda *_: 0)
    monkeypatch.setattr(root_helper, "_managed_socks_pid", lambda _: None)
    monkeypatch.setattr(root_helper, "_find_socks_binary", lambda: "/usr/bin/3proxy")
    monkeypatch.setattr(root_helper, "_load_validated_socks_spec", lambda *_: spec)
    monkeypatch.setattr(root_helper, "_killswitch_active", lambda *_, **__: True)
    monkeypatch.setattr(root_helper, "_service_uid", os.geteuid)
    monkeypatch.setattr(root_helper, "_service_gid", os.getegid)
    monkeypatch.setattr("app.root_helper.time.sleep", lambda _: None)

    class FakeProcess:
        pid = 7654

        def poll(self) -> None:
            return None

    def fake_popen(*args: Any, **kwargs: Any) -> FakeProcess:
        captured["argv"] = args[0]
        captured["kwargs"] = kwargs
        return FakeProcess()

    monkeypatch.setattr(subprocess, "Popen", fake_popen)
    command = root_helper.parse_command(["socks5-start", "lxvpn-2", "2", "7"])

    assert root_helper._start_socks(command, "/usr/sbin/ip") == 0
    assert captured["argv"] == (
        "/usr/sbin/ip",
        "netns",
        "exec",
        "lxvpn-2",
        "/usr/bin/3proxy",
        str(runtime_directory / "socks-2.cfg"),
    )
    assert password not in captured["argv"]
    assert "shell" not in captured["kwargs"]
    assert captured["kwargs"]["start_new_session"] is True
    config_text = (runtime_directory / "socks-2.cfg").read_text(encoding="utf-8")
    assert f"users proxy_user:CL:{password}" in config_text
    assert "allow proxy_user 10.220.0.5/32" in config_text
    assert (runtime_directory / "socks-2.pid").read_text(encoding="ascii") == "7654\n"
    assert stat.S_IMODE((runtime_directory / "socks-2.cfg").stat().st_mode) == 0o600


def test_helper_accepts_socks_pid_only_for_managed_binary_and_config(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime_directory = tmp_path / "run"
    process_directory = tmp_path / "proc/7654"
    runtime_directory.mkdir()
    process_directory.mkdir(parents=True)
    binary = tmp_path / "3proxy"
    binary.write_text("binary", encoding="utf-8")
    binary.chmod(0o755)
    (process_directory / "exe").symlink_to(binary)
    pid_path = runtime_directory / "socks-2.pid"
    pid_path.write_text("7654\n", encoding="ascii")
    pid_path.chmod(0o600)
    config_path = runtime_directory / "socks-2.cfg"
    config_path.write_text("socks -p21002 -i0.0.0.0 -e0.0.0.0\n", encoding="utf-8")
    config_path.chmod(0o600)
    (process_directory / "cmdline").write_bytes(
        f"{binary}\0{config_path}\0".encode("utf-8")
    )
    monkeypatch.setattr(root_helper, "SOCKS_RUNTIME_DIRECTORY", runtime_directory)
    monkeypatch.setattr(root_helper, "PROC_DIRECTORY", tmp_path / "proc")
    monkeypatch.setattr(root_helper, "SOCKS_BINARY_CANDIDATES", (str(binary),))

    assert root_helper._managed_socks_pid("2") == 7654
    assert root_helper._managed_socks_port("2") == 21002

    (process_directory / "cmdline").write_bytes(b"unrelated\0process\0")
    with pytest.raises(RuntimeError, match="unmanaged_socks_process"):
        root_helper._managed_socks_pid("2")


def test_helper_socks_ready_uses_fixed_namespace_ss_probe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}
    monkeypatch.setattr(root_helper, "_managed_socks_pid", lambda _: 7654)
    monkeypatch.setattr(root_helper, "_managed_socks_port", lambda _: 21002)
    monkeypatch.setattr(root_helper, "_find_ss_binary", lambda: "/usr/bin/ss")

    def fake_run(*args: Any, **kwargs: Any) -> subprocess.CompletedProcess[str]:
        captured["argv"] = args[0]
        captured["kwargs"] = kwargs
        return subprocess.CompletedProcess(
            args[0], 0, stdout="LISTEN 0 100 0.0.0.0:21002 0.0.0.0:*\n", stderr=""
        )

    monkeypatch.setattr(subprocess, "run", fake_run)
    command = root_helper.parse_command(["socks5-ready", "lxvpn-2", "2", "21002"])

    assert root_helper._socks_ready(command, "/usr/sbin/ip") == 0
    assert captured["argv"] == (
        "/usr/sbin/ip",
        "netns",
        "exec",
        "lxvpn-2",
        "/usr/bin/ss",
        "-H",
        "-ltn",
        "sport = :21002",
    )
    assert "shell" not in captured["kwargs"]


def test_helper_refuses_to_signal_unmanaged_socks_pid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    killed: list[tuple[int, int]] = []
    monkeypatch.setattr(
        root_helper,
        "_managed_socks_pid",
        lambda _: (_ for _ in ()).throw(RuntimeError("unmanaged_socks_process")),
    )
    monkeypatch.setattr(os, "kill", lambda pid, sig: killed.append((pid, sig)))
    command = root_helper.parse_command(["socks5-stop", "2"])

    assert root_helper._stop_socks(command) == 126
    assert killed == []


def test_execute_requires_separate_socks_gate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(root_helper, "real_network_enabled", lambda: True)
    monkeypatch.setattr(root_helper, "real_socks5_enabled", lambda: False)
    monkeypatch.setattr(
        root_helper,
        "_find_ip_binary",
        lambda: (_ for _ in ()).throw(AssertionError("ip must not run")),
    )
    command = root_helper.parse_command(["socks5-status", "2"])

    assert root_helper.execute(command) == 78


def test_helper_firewall_gate_requires_network_and_exact_flag() -> None:
    enabled = (
        "VPNGATE_ENABLE_REAL_NETWORK=true\n"
        "VPNGATE_ENABLE_REAL_FIREWALL=true\n"
    )

    assert root_helper._firewall_enabled_from_text(enabled)
    assert not root_helper._firewall_enabled_from_text(
        "VPNGATE_ENABLE_REAL_NETWORK=false\nVPNGATE_ENABLE_REAL_FIREWALL=true\n"
    )
    assert not root_helper._firewall_enabled_from_text(
        "VPNGATE_ENABLE_REAL_NETWORK=true\nVPNGATE_ENABLE_REAL_FIREWALL=true # no\n"
    )


def test_helper_full_scan_gate_requires_all_exact_network_flags() -> None:
    enabled = (
        "VPNGATE_ENABLE_REAL_NETWORK=true\n"
        "VPNGATE_ENABLE_REAL_FIREWALL=true\n"
        "VPNGATE_ENABLE_REAL_OPENVPN=true\n"
        "VPNGATE_ENABLE_REAL_FULL_SCANS=true\n"
    )

    assert root_helper._full_scans_enabled_from_text(enabled)
    assert not root_helper._full_scans_enabled_from_text(
        enabled.replace(
            "VPNGATE_ENABLE_REAL_FULL_SCANS=true",
            "VPNGATE_ENABLE_REAL_FULL_SCANS=false",
        )
    )


def test_helper_unlock_gate_requires_all_exact_network_flags() -> None:
    enabled = (
        "VPNGATE_ENABLE_REAL_NETWORK=true\n"
        "VPNGATE_ENABLE_REAL_FIREWALL=true\n"
        "VPNGATE_ENABLE_REAL_OPENVPN=true\n"
        "VPNGATE_ENABLE_REAL_UNLOCK_CHECKS=true\n"
    )

    assert root_helper._unlock_checks_enabled_from_text(enabled)
    assert not root_helper._unlock_checks_enabled_from_text(
        enabled.replace(
            "VPNGATE_ENABLE_REAL_UNLOCK_CHECKS=true",
            "VPNGATE_ENABLE_REAL_UNLOCK_CHECKS=false",
        )
    )

def test_helper_auto_backend_prefers_nftables_without_probing_iptables(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(root_helper, "_find_nft_binary", lambda: "/usr/sbin/nft")
    monkeypatch.setattr(
        root_helper,
        "_find_iptables_binary",
        lambda: (_ for _ in ()).throw(AssertionError("must not mix backends")),
    )

    assert root_helper._select_firewall_backend("auto") == (
        "nftables",
        "/usr/sbin/nft",
    )


def test_helper_applies_and_removes_connection_scoped_firewall_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime_directory = tmp_path / "firewall"
    applied: list[tuple[str, int]] = []
    cleaned: list[tuple[str, int]] = []
    monkeypatch.setattr(root_helper, "FIREWALL_RUNTIME_DIRECTORY", runtime_directory)
    monkeypatch.setattr(root_helper, "_namespace_exists", lambda _: True)
    monkeypatch.setattr(root_helper, "_ip_forward_enabled", lambda: True)
    monkeypatch.setattr(
        root_helper,
        "_load_validated_openvpn_config",
        lambda _: (tmp_path / "node-3.ovpn", b"validated"),
    )
    monkeypatch.setattr(
        root_helper,
        "validate_stored_openvpn_config",
        lambda _: SimpleNamespace(
            remote_ip="8.8.8.8", remote_port=1194, protocol="udp"
        ),
    )
    monkeypatch.setattr(root_helper, "trusted_socks_port_range", lambda: (21000, 21999))
    monkeypatch.setattr(
        root_helper, "_select_firewall_backend", lambda _: ("nftables", "/usr/sbin/nft")
    )

    def fake_apply(spec: Any, **kwargs: Any) -> int:
        del kwargs
        applied.append((spec.namespace, spec.connection_id))
        return 0

    def fake_cleanup(spec: Any, backend: str, **kwargs: Any) -> None:
        del kwargs
        cleaned.append((backend, spec.connection_id))

    monkeypatch.setattr(
        root_helper,
        "_apply_nft_rules",
        fake_apply,
    )
    monkeypatch.setattr(root_helper, "_firewall_backend_active", lambda *_, **__: True)
    monkeypatch.setattr(root_helper, "_firewall_backend_has_residue", lambda *_, **__: False)
    monkeypatch.setattr(
        root_helper,
        "_cleanup_firewall_backend",
        fake_cleanup,
    )
    command = root_helper.parse_command(
        [
            "killswitch-apply",
            "lxvpn-2",
            "2",
            "3",
            "8.8.8.8",
            "1194",
            "udp",
            "21002",
            "auto",
            "198.51.100.7/32",
        ]
    )

    assert root_helper._apply_killswitch(command, "/usr/sbin/ip") == 0
    state_path = runtime_directory / "killswitch-2.backend"
    assert state_path.read_text(encoding="ascii") == (
        '{"backend":"nftables","node_id":3,"socks_port":21002,"version":1}\n'
    )
    assert stat.S_IMODE(state_path.stat().st_mode) == 0o600
    assert applied == [("lxvpn-2", 2)]

    monkeypatch.setattr(root_helper, "_managed_socks_pid", lambda _: None)
    monkeypatch.setattr(root_helper, "_managed_openvpn_pid", lambda _: None)
    remove = root_helper.parse_command(["killswitch-remove", "lxvpn-2", "2"])
    assert root_helper._remove_killswitch(remove, "/usr/sbin/ip") == 0
    assert cleaned == [("nftables", 2)]
    assert not state_path.exists()


@pytest.mark.parametrize(
    ("validated", "port_range"),
    [
        (
            SimpleNamespace(
                remote_ip="9.9.9.9", remote_port=1194, protocol="udp"
            ),
            (21000, 21999),
        ),
        (
            SimpleNamespace(
                remote_ip="8.8.8.8", remote_port=1194, protocol="udp"
            ),
            (22000, 22999),
        ),
    ],
)
def test_helper_binds_killswitch_to_stored_node_and_socks_pool(
    validated: SimpleNamespace,
    port_range: tuple[int, int],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(root_helper, "_namespace_exists", lambda _: True)
    monkeypatch.setattr(root_helper, "_ip_forward_enabled", lambda: True)
    monkeypatch.setattr(
        root_helper,
        "_load_validated_openvpn_config",
        lambda _: (Path("node-3.ovpn"), b"validated"),
    )
    monkeypatch.setattr(
        root_helper, "validate_stored_openvpn_config", lambda _: validated
    )
    monkeypatch.setattr(root_helper, "trusted_socks_port_range", lambda: port_range)
    monkeypatch.setattr(
        root_helper,
        "_select_firewall_backend",
        lambda _: (_ for _ in ()).throw(AssertionError("firewall must not run")),
    )
    command = root_helper.parse_command(
        [
            "killswitch-apply",
            "lxvpn-2",
            "2",
            "3",
            "8.8.8.8",
            "1194",
            "udp",
            "21002",
            "auto",
            "-",
        ]
    )

    assert root_helper._apply_killswitch(command, "/usr/sbin/ip") == 126


def test_helper_scan_killswitch_omits_socks_pool_and_public_mapping(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime_directory = tmp_path / "firewall"
    monkeypatch.setattr(root_helper, "FIREWALL_RUNTIME_DIRECTORY", runtime_directory)
    monkeypatch.setattr(root_helper, "_namespace_exists", lambda _: True)
    monkeypatch.setattr(root_helper, "_ip_forward_enabled", lambda: True)
    monkeypatch.setattr(root_helper, "_managed_socks_pid", lambda _: None)
    monkeypatch.setattr(root_helper, "_managed_openvpn_pid", lambda _: None)
    monkeypatch.setattr(
        root_helper,
        "_load_validated_openvpn_config",
        lambda _: (tmp_path / "node-3.ovpn", b"validated"),
    )
    monkeypatch.setattr(
        root_helper,
        "validate_stored_openvpn_config",
        lambda _: SimpleNamespace(
            remote_ip="8.8.8.8", remote_port=1194, protocol="udp"
        ),
    )
    monkeypatch.setattr(
        root_helper,
        "trusted_socks_port_range",
        lambda: (_ for _ in ()).throw(AssertionError("SOCKS pool must not be read")),
    )
    monkeypatch.setattr(
        root_helper, "_select_firewall_backend", lambda _: ("nftables", "/usr/sbin/nft")
    )
    monkeypatch.setattr(root_helper, "_apply_nft_rules", lambda *_args, **_kwargs: 0)
    monkeypatch.setattr(root_helper, "_firewall_backend_active", lambda *_, **__: True)
    command = root_helper.parse_command(
        [
            "killswitch-apply",
            "lxvpn-2",
            "2",
            "3",
            "8.8.8.8",
            "1194",
            "udp",
            "-",
            "auto",
            "-",
        ]
    )

    assert root_helper._apply_killswitch(command, "/usr/sbin/ip") == 0
    assert '"socks_port":null' in (
        runtime_directory / "killswitch-2.backend"
    ).read_text(encoding="ascii")


def test_helper_requires_killswitch_state_to_match_node_and_socks_port(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = root_helper._FirewallState(
        backend="nftables",
        node_id=3,
        socks_port=21002,
    )
    monkeypatch.setattr(root_helper, "_read_firewall_state", lambda _: state)
    monkeypatch.setattr(
        root_helper, "_firewall_backend_active", lambda *_, **__: True
    )

    assert root_helper._killswitch_active(
        "lxvpn-2",
        "2",
        ip_binary="/usr/sbin/ip",
        node_id="3",
        socks_port=21002,
    )
    assert not root_helper._killswitch_active(
        "lxvpn-2", "2", ip_binary="/usr/sbin/ip", node_id="4"
    )
    assert not root_helper._killswitch_active(
        "lxvpn-2", "2", ip_binary="/usr/sbin/ip", socks_port=21003
    )


def test_helper_killswitch_apply_refuses_disabled_ip_forwarding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(root_helper, "_namespace_exists", lambda _: True)
    monkeypatch.setattr(root_helper, "_ip_forward_enabled", lambda: False)
    monkeypatch.setattr(
        root_helper,
        "_select_firewall_backend",
        lambda _: (_ for _ in ()).throw(AssertionError("firewall must not run")),
    )
    command = root_helper.parse_command(
        [
            "killswitch-apply",
            "lxvpn-2",
            "2",
            "3",
            "8.8.8.8",
            "1194",
            "udp",
            "21002",
            "auto",
            "-",
        ]
    )

    assert root_helper._apply_killswitch(command, "/usr/sbin/ip") == 78


def test_helper_refuses_firewall_removal_while_proxy_runs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(root_helper, "_managed_socks_pid", lambda _: 7654)
    monkeypatch.setattr(
        root_helper,
        "_cleanup_firewall_backend",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("active firewall must stay installed")
        ),
    )
    command = root_helper.parse_command(["killswitch-remove", "lxvpn-2", "2"])

    assert root_helper._remove_killswitch(command, "/usr/sbin/ip") == 126


def test_execute_requires_killswitch_before_openvpn_start(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(root_helper, "real_network_enabled", lambda: True)
    monkeypatch.setattr(root_helper, "real_openvpn_enabled", lambda: True)
    monkeypatch.setattr(root_helper, "_find_ip_binary", lambda: "/usr/sbin/ip")
    monkeypatch.setattr(root_helper, "_killswitch_active", lambda *_args, **_kwargs: False)
    monkeypatch.setattr(
        root_helper,
        "_start_openvpn",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("OpenVPN must not start")
        ),
    )
    command = root_helper.parse_command(["openvpn-start", "lxvpn-2", "2", "3"])

    assert root_helper.execute(command) == 3


def test_execute_requires_separate_firewall_gate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(root_helper, "real_network_enabled", lambda: True)
    monkeypatch.setattr(root_helper, "real_firewall_enabled", lambda: False)
    monkeypatch.setattr(
        root_helper,
        "_find_ip_binary",
        lambda: (_ for _ in ()).throw(AssertionError("ip must not run")),
    )
    command = root_helper.parse_command(["killswitch-status", "lxvpn-2", "2"])

    assert root_helper.execute(command) == 78


def test_execute_requires_separate_full_scan_gate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(root_helper, "real_network_enabled", lambda: True)
    monkeypatch.setattr(root_helper, "real_full_scans_enabled", lambda: False)
    monkeypatch.setattr(
        root_helper,
        "_find_ip_binary",
        lambda: (_ for _ in ()).throw(AssertionError("ip must not run")),
    )
    command = root_helper.parse_command(["node-exit-probe", "lxvpn-2", "2"])

    assert root_helper.execute(command) == 78


def test_execute_requires_separate_unlock_check_gate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(root_helper, "real_network_enabled", lambda: True)
    monkeypatch.setattr(root_helper, "real_unlock_checks_enabled", lambda: False)
    monkeypatch.setattr(
        root_helper,
        "_find_ip_binary",
        lambda: (_ for _ in ()).throw(AssertionError("ip must not run")),
    )
    command = root_helper.parse_command(
        ["service-unlock-probe", "lxvpn-2", "2", "chatgpt"]
    )

    assert root_helper.execute(command) == 78


def test_helper_exit_probe_uses_only_fixed_https_probes(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    calls: list[tuple[str, ...]] = []
    outputs = iter(
        [
            (0, '{"ip":"8.8.8.8"}'),
            (0, "1000000"),
        ]
    )
    monkeypatch.setattr(root_helper, "_killswitch_active", lambda *_, **__: True)
    monkeypatch.setattr(root_helper, "_tun_ready", lambda *_: 0)
    monkeypatch.setattr(root_helper, "_find_curl_binary", lambda: "/usr/bin/curl")

    def fake_curl(
        _ip_binary: str,
        _namespace: str,
        _curl_binary: str,
        arguments: tuple[str, ...],
    ) -> tuple[int, str]:
        calls.append(arguments)
        return next(outputs)

    monkeypatch.setattr(root_helper, "_run_namespace_curl", fake_curl)
    command = root_helper.parse_command(["node-exit-probe", "lxvpn-2", "2"])

    assert root_helper._probe_namespace_exit(command, "/usr/sbin/ip") == 0
    payload = capsys.readouterr().out
    assert '"exit_ip":"8.8.8.8"' in payload
    assert '"download_bps":8000000' in payload
    assert calls[0][-1] == root_helper.EXIT_IP_URL
    assert calls[1][-1] == root_helper.SPEED_PROBE_URL


def test_helper_unlock_checks_classify_fixed_service_targets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []
    responses = iter(
        [
            root_helper._UnlockHTTPResult(0, 200, 10.0, "Test Patterns"),
            root_helper._UnlockHTTPResult(0, 200, 12.0, "Breaking Bad"),
            root_helper._UnlockHTTPResult(0, 403, 15.0, "cf-chl challenge"),
            root_helper._UnlockHTTPResult(0, 200, 4.0, "icon"),
            root_helper._UnlockHTTPResult(0, 101, 3.0, ""),
            root_helper._UnlockHTTPResult(0, 401, 8.0, "missing authentication"),
            root_helper._UnlockHTTPResult(
                0,
                200,
                9.0,
                'ytcfg.set({"GL":"JP"})',
            ),
        ]
    )

    def fake_http(
        _ip_binary: str,
        _namespace: str,
        _curl_binary: str,
        url: str,
        **_kwargs: object,
    ) -> root_helper._UnlockHTTPResult:
        calls.append(url)
        return next(responses)

    monkeypatch.setattr(root_helper, "_run_unlock_http", fake_http)

    netflix = root_helper._check_netflix("ip", "lxvpn-2", "curl")
    chatgpt = root_helper._check_single_service(
        "ip", "lxvpn-2", "curl", "chatgpt"
    )
    openai = root_helper._check_single_service(
        "ip", "lxvpn-2", "curl", "openai_api"
    )
    youtube = root_helper._check_single_service(
        "ip", "lxvpn-2", "curl", "youtube"
    )

    assert netflix["status"] == "FULL"
    assert chatgpt["status"] == "CHALLENGE"
    assert chatgpt["static_ok"] is True
    assert chatgpt["websocket_ok"] is True
    assert openai["status"] == "REACHABLE"
    assert youtube["status"] == "REGION_DETECTED"
    assert youtube["region"] == "JP"
    assert calls == [
        root_helper.NETFLIX_ORIGINAL_URL,
        root_helper.NETFLIX_CATALOG_URL,
        root_helper.CHATGPT_URL,
        root_helper.CHATGPT_STATIC_URL,
        root_helper.CHATGPT_URL,
        root_helper.OPENAI_API_URL,
        root_helper.YOUTUBE_URL,
    ]


def test_helper_unlock_probe_requires_tunnel_and_emits_only_summary(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(root_helper, "_killswitch_active", lambda *_, **__: True)
    monkeypatch.setattr(root_helper, "_tun_ready", lambda *_: 0)
    monkeypatch.setattr(root_helper, "_find_curl_binary", lambda: "/usr/bin/curl")
    monkeypatch.setattr(
        root_helper,
        "_check_single_service",
        lambda *_: root_helper._unlock_payload(
            service_name="openai_api",
            status="REACHABLE",
            region=None,
            latency_ms=4.0,
            failure_reason=None,
            http_status=401,
        ),
    )
    command = root_helper.parse_command(
        ["service-unlock-probe", "lxvpn-2", "2", "openai_api"]
    )

    assert root_helper._probe_namespace_unlock(command, "/usr/sbin/ip") == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "REACHABLE"
    assert set(payload) == {
        "failure_reason",
        "http_status",
        "latency_ms",
        "region",
        "secondary_http_status",
        "service_name",
        "static_ok",
        "status",
        "websocket_ok",
    }
