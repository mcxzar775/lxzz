from dataclasses import dataclass, field
from pathlib import Path
import stat

from fastapi import FastAPI
import pytest
from sqlalchemy.orm import Session, sessionmaker

from app.models.network import SocksEndpoint, VPNConnection
from app.services.network import CommandResult, NetworkCommand, NetworkOperation
from app.services.network.executor import RealNetworkExecutor
from app.services.network.socks5 import (
    CredentialCipher,
    SecureSocksSpecStore,
    Socks5Manager,
    Socks5OperationError,
    Socks5Spec,
    SocksEndpointService,
    allocate_socks_port,
    normalize_client_ip_allowlist,
)


@dataclass
class SocksExecutor:
    tun_code: int = 0
    start_code: int = 0
    stop_code: int = 0
    status_code: int = 0
    ready_codes: list[int] = field(default_factory=lambda: [0])
    status_pid: int = 7654
    fail_start_execution: bool = False
    commands: list[NetworkCommand] = field(default_factory=list)

    def run(self, command: NetworkCommand, *, timeout_seconds: float) -> CommandResult:
        assert 0 < timeout_seconds <= 120
        self.commands.append(command)
        if command.operation is NetworkOperation.OPENVPN_TUN_READY:
            return CommandResult(command, self.tun_code, "", "")
        if command.operation is NetworkOperation.SOCKS5_START:
            if self.fail_start_execution:
                raise RuntimeError("simulated executor failure")
            return CommandResult(command, self.start_code, "", "")
        if command.operation is NetworkOperation.SOCKS5_STOP:
            return CommandResult(command, self.stop_code, "", "")
        if command.operation is NetworkOperation.SOCKS5_STATUS:
            stdout = str(self.status_pid) if self.status_code == 0 else ""
            return CommandResult(command, self.status_code, stdout, "")
        if command.operation is NetworkOperation.SOCKS5_READY:
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


def _spec() -> Socks5Spec:
    return Socks5Spec(
        connection_id=2,
        endpoint_id=7,
        port=21002,
        username="proxy_user",
        password="abcdefghijklmnopqrstuvwxyz_123456",
        client_ip_allowlist=("198.51.100.7/32", "203.0.113.0/24"),
        max_connections=25,
        timeout_seconds=120,
    )


def _connection(connection_id: int = 1) -> VPNConnection:
    return VPNConnection(
        id=connection_id,
        name=f"connection-{connection_id}",
        node_id=None,
        namespace=f"lxvpn-{connection_id}",
        veth_host=f"lvh{connection_id}",
        veth_namespace=f"lvn{connection_id}",
        subnet_cidr=f"10.220.0.{(connection_id - 1) * 4}/30",
    )


def test_credential_cipher_creates_private_key_and_binds_ciphertext(
    tmp_path: Path,
) -> None:
    key_path = tmp_path / "secrets/credential.key"
    cipher = CredentialCipher.load_or_create(key_path)
    password = "abcdefghijklmnopqrstuvwxyz_123456"

    encrypted = cipher.encrypt_password(2, password)

    assert password not in encrypted
    assert cipher.decrypt_password(2, encrypted) == password
    assert stat.S_IMODE(key_path.stat().st_mode) == 0o600
    with pytest.raises(Socks5OperationError, match="credential_binding_mismatch"):
        cipher.decrypt_password(3, encrypted)


def test_credential_cipher_rejects_world_readable_or_symlinked_key(
    tmp_path: Path,
) -> None:
    key_path = tmp_path / "credential.key"
    CredentialCipher.load_or_create(key_path)
    key_path.chmod(0o644)
    with pytest.raises(Socks5OperationError, match="unsafe_credential_key"):
        CredentialCipher.load_or_create(key_path)

    key_path.unlink()
    outside = tmp_path / "outside.key"
    CredentialCipher.load_or_create(outside)
    key_path.symlink_to(outside)
    with pytest.raises(Socks5OperationError, match="unsafe_credential_key"):
        CredentialCipher.load_or_create(key_path)


def test_allowlist_is_canonical_and_rejects_injection() -> None:
    assert normalize_client_ip_allowlist(
        ["198.51.100.7", "203.0.113.0/24"]
    ) == ("198.51.100.7/32", "203.0.113.0/24")

    for unsafe in ("203.0.113.7;allow *", "127.0.0.1", "0.0.0.0/0"):
        with pytest.raises(Socks5OperationError, match="invalid_client_ip_allowlist"):
            normalize_client_ip_allowlist([unsafe])


def test_secure_spec_store_uses_fixed_private_file_and_deletes_it(
    tmp_path: Path,
) -> None:
    store = SecureSocksSpecStore(tmp_path / "specs")

    path = store.write(_spec())

    assert path == tmp_path / "specs/endpoint-7.json"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    assert '"connection_id":2' in path.read_text(encoding="utf-8")
    assert store.cleanup_stale() == 1
    assert not path.exists()
    store.delete(7)


def test_port_allocator_and_endpoint_service_encrypt_password(
    app: FastAPI, tmp_path: Path
) -> None:
    factory: sessionmaker[Session] = app.state.session_factory
    cipher = CredentialCipher.load_or_create(tmp_path / "credential.key")
    manager = Socks5Manager(SocksExecutor(), SecureSocksSpecStore(tmp_path / "specs"))
    service = SocksEndpointService(cipher, manager, port_start=21000, port_end=21002)

    with factory() as db:
        db.add_all([_connection(1), _connection(2)])
        db.flush()
        first, password = service.create(
            db,
            connection_id=1,
            username="proxy_one",
            client_ip_allowlist=["198.51.100.8"],
        )
        second, _ = service.create(
            db,
            connection_id=2,
            username="proxy_two",
            requested_port=21002,
        )

        assert first.port == 21000
        assert second.port == 21002
        assert password not in first.encrypted_password
        assert service.spec_for(first).password == password
        assert first.client_ip_allowlist == ["198.51.100.8/32"]
        service.add_traffic(first, bytes_up=120, bytes_down=340)
        assert first.bytes_up == 120
        assert first.bytes_down == 340
        with pytest.raises(Socks5OperationError, match="invalid_socks_traffic_counter"):
            service.add_traffic(first, bytes_up=-1, bytes_down=0)
        first.is_active = True
        with pytest.raises(Socks5OperationError, match="socks_endpoint_active"):
            service.rotate_password(first)
        with pytest.raises(Socks5OperationError, match="socks_port_in_use"):
            allocate_socks_port(
                db, port_start=21000, port_end=21002, requested_port=21002
            )


def test_manager_requires_tunnel_then_starts_and_removes_plaintext_spec(
    tmp_path: Path,
) -> None:
    executor = SocksExecutor(ready_codes=[3, 0])
    fake_time = FakeTime()
    store = SecureSocksSpecStore(tmp_path / "specs")
    manager = Socks5Manager(
        executor,
        store,
        ready_timeout_seconds=5,
        poll_interval_seconds=0.5,
        clock=fake_time.monotonic,
        sleeper=fake_time.sleep,
    )

    runtime = manager.start(_spec())

    assert runtime.running is True
    assert runtime.pid == 7654
    assert runtime.namespace == "lxvpn-2"
    assert not store.path_for(7).exists()
    assert [command.operation for command in executor.commands] == [
        NetworkOperation.OPENVPN_TUN_READY,
        NetworkOperation.SOCKS5_START,
        NetworkOperation.SOCKS5_READY,
        NetworkOperation.SOCKS5_READY,
        NetworkOperation.SOCKS5_STATUS,
    ]
    assert all(_spec().password not in command.arguments for command in executor.commands)


def test_manager_refuses_start_before_verified_tunnel(tmp_path: Path) -> None:
    executor = SocksExecutor(tun_code=3)
    store = SecureSocksSpecStore(tmp_path / "specs")
    manager = Socks5Manager(executor, store)

    with pytest.raises(Socks5OperationError, match="socks_tunnel_not_ready"):
        manager.start(_spec())

    assert [command.operation for command in executor.commands] == [
        NetworkOperation.OPENVPN_TUN_READY
    ]
    assert not store.path_for(7).exists()


def test_manager_ready_timeout_stops_proxy(tmp_path: Path) -> None:
    executor = SocksExecutor(ready_codes=[3, 3, 3])
    fake_time = FakeTime()
    manager = Socks5Manager(
        executor,
        SecureSocksSpecStore(tmp_path / "specs"),
        ready_timeout_seconds=1,
        poll_interval_seconds=0.5,
        clock=fake_time.monotonic,
        sleeper=fake_time.sleep,
    )

    with pytest.raises(Socks5OperationError, match="socks_ready_timeout"):
        manager.start(_spec())

    assert executor.commands[-1].operation is NetworkOperation.SOCKS5_STOP


def test_manager_executor_failure_deletes_spec_and_rolls_back(tmp_path: Path) -> None:
    executor = SocksExecutor(fail_start_execution=True)
    store = SecureSocksSpecStore(tmp_path / "specs")
    manager = Socks5Manager(executor, store)

    with pytest.raises(Socks5OperationError, match="socks_command_failed"):
        manager.start(_spec())

    assert not store.path_for(7).exists()
    assert executor.commands[-1].operation is NetworkOperation.SOCKS5_STOP


def test_real_executor_requires_separate_socks_gate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("VPNGATE_ENABLE_REAL_NETWORK", "true")
    executor = RealNetworkExecutor(
        enabled=True,
        sudo_path="/usr/bin/sudo",
        helper_path="/usr/local/libexec/vpngate-manager-helper",
    )
    manager = Socks5Manager(
        executor,
        SecureSocksSpecStore(tmp_path / "specs"),
        allow_real_socks5=False,
    )

    with pytest.raises(Socks5OperationError, match="VPNGATE_ENABLE_REAL_SOCKS5"):
        manager.status(_spec())
