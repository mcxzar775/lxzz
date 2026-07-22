import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import stat
import tempfile
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, replace

from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.network import SocksEndpoint, VPNConnection
from app.services.network.commands import (
    MAX_NAMESPACE_RESOURCES,
    NetworkCommand,
    NetworkOperation,
    namespace_name,
)
from app.services.network.executor import NetworkExecutor, RealNetworkExecutor
from app.services.network.validation import ResourceValidationError, validate_port


SOCKS_USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{2,63}$")
SOCKS_PASSWORD_PATTERN = re.compile(r"^[A-Za-z0-9_-]{20,128}$")
MAX_ALLOWLIST_ENTRIES = 64
MAX_SOCKS_SPEC_BYTES = 32 * 1024


class Socks5OperationError(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class Socks5Spec:
    connection_id: int
    endpoint_id: int
    port: int
    username: str
    password: str
    client_ip_allowlist: tuple[str, ...] = ()
    bind_address: str = "0.0.0.0"
    max_connections: int = 100
    timeout_seconds: int = 300


@dataclass(frozen=True)
class Socks5Runtime:
    connection_id: int
    endpoint_id: int
    namespace: str
    port: int
    running: bool
    pid: int | None
    bytes_up: int = 0
    bytes_down: int = 0


def validate_socks_username(value: str) -> str:
    if SOCKS_USERNAME_PATTERN.fullmatch(value) is None:
        raise Socks5OperationError("invalid_socks_username")
    return value


def validate_socks_password(value: str) -> str:
    if SOCKS_PASSWORD_PATTERN.fullmatch(value) is None:
        raise Socks5OperationError("invalid_socks_password")
    return value


def generate_socks_password() -> str:
    password = secrets.token_urlsafe(32)
    return validate_socks_password(password)


def normalize_client_ip_allowlist(values: Iterable[str]) -> tuple[str, ...]:
    normalized: list[str] = []
    for value in values:
        if not isinstance(value, str) or not value or len(value) > 64:
            raise Socks5OperationError("invalid_client_ip_allowlist")
        try:
            if "/" in value:
                network = ipaddress.ip_network(value, strict=True)
            else:
                address = ipaddress.ip_address(value)
                network = ipaddress.ip_network(
                    f"{address}/{address.max_prefixlen}", strict=True
                )
        except ValueError as exc:
            raise Socks5OperationError("invalid_client_ip_allowlist") from exc
        if not isinstance(network, ipaddress.IPv4Network) or any(
            (
                network.network_address.is_unspecified,
                network.network_address.is_multicast,
                network.network_address.is_loopback,
                network.network_address.is_link_local,
            )
        ):
            raise Socks5OperationError("invalid_client_ip_allowlist")
        normalized.append(str(network))
    if len(normalized) > MAX_ALLOWLIST_ENTRIES or len(set(normalized)) != len(normalized):
        raise Socks5OperationError("invalid_client_ip_allowlist")
    return tuple(normalized)


def validate_socks_spec(spec: Socks5Spec) -> Socks5Spec:
    for identifier in (spec.connection_id, spec.endpoint_id):
        if (
            isinstance(identifier, bool)
            or identifier <= 0
            or identifier > 2_147_483_647
        ):
            raise Socks5OperationError("invalid_socks_resource_id")
    if spec.connection_id > MAX_NAMESPACE_RESOURCES:
        raise Socks5OperationError("invalid_socks_resource_id")
    try:
        validate_port(spec.port, minimum=1024)
    except ResourceValidationError as exc:
        raise Socks5OperationError("invalid_socks_port") from exc
    validate_socks_username(spec.username)
    validate_socks_password(spec.password)
    normalized_allowlist = normalize_client_ip_allowlist(spec.client_ip_allowlist)
    if spec.client_ip_allowlist != normalized_allowlist:
        raise Socks5OperationError("noncanonical_client_ip_allowlist")
    if spec.bind_address != "0.0.0.0":
        raise Socks5OperationError("invalid_socks_bind_address")
    if (
        isinstance(spec.max_connections, bool)
        or spec.max_connections < 1
        or spec.max_connections > 1000
    ):
        raise Socks5OperationError("invalid_socks_max_connections")
    if (
        isinstance(spec.timeout_seconds, bool)
        or spec.timeout_seconds < 10
        or spec.timeout_seconds > 3600
    ):
        raise Socks5OperationError("invalid_socks_timeout")
    return spec


class CredentialCipher:
    def __init__(self, key: bytes) -> None:
        try:
            self._fernet = Fernet(key)
        except (TypeError, ValueError) as exc:
            raise Socks5OperationError("invalid_credential_key") from exc

    @classmethod
    def load_or_create(cls, key_path: str | Path) -> "CredentialCipher":
        path = Path(key_path)
        if "\x00" in str(path) or path.is_symlink() or path.parent.is_symlink():
            raise Socks5OperationError("unsafe_credential_key")
        try:
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            parent_metadata = path.parent.lstat()
            if (
                path.parent.is_symlink()
                or not stat.S_ISDIR(parent_metadata.st_mode)
                or parent_metadata.st_uid != os.geteuid()
                or parent_metadata.st_mode & 0o022
            ):
                raise Socks5OperationError("unsafe_credential_key")
            if path.exists():
                metadata = path.lstat()
                if (
                    not stat.S_ISREG(metadata.st_mode)
                    or metadata.st_uid != os.geteuid()
                    or metadata.st_mode & 0o077
                    or metadata.st_size < 32
                    or metadata.st_size > 256
                ):
                    raise Socks5OperationError("unsafe_credential_key")
                key = path.read_bytes().strip()
            else:
                descriptor = os.open(
                    path,
                    os.O_WRONLY
                    | os.O_CREAT
                    | os.O_EXCL
                    | os.O_CLOEXEC
                    | os.O_NOFOLLOW,
                    0o600,
                )
                try:
                    key = Fernet.generate_key()
                    with os.fdopen(descriptor, "wb") as handle:
                        descriptor = -1
                        handle.write(key + b"\n")
                        handle.flush()
                        os.fsync(handle.fileno())
                finally:
                    if descriptor >= 0:
                        os.close(descriptor)
                os.chmod(path, 0o600)
        except Socks5OperationError:
            raise
        except OSError as exc:
            raise Socks5OperationError("credential_key_unavailable") from exc
        return cls(key)

    def encrypt_password(self, connection_id: int, password: str) -> str:
        validate_socks_password(password)
        if isinstance(connection_id, bool) or connection_id <= 0:
            raise Socks5OperationError("invalid_socks_resource_id")
        payload = json.dumps(
            {"connection_id": connection_id, "password": password, "version": 1},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return self._fernet.encrypt(payload).decode("ascii")

    def decrypt_password(self, connection_id: int, encrypted_password: str) -> str:
        try:
            plaintext = self._fernet.decrypt(
                encrypted_password.encode("ascii"), ttl=None
            )
            payload = json.loads(plaintext.decode("utf-8"))
        except (InvalidToken, UnicodeError, ValueError, TypeError, json.JSONDecodeError) as exc:
            raise Socks5OperationError("credential_decryption_failed") from exc
        if (
            not isinstance(payload, dict)
            or set(payload) != {"connection_id", "password", "version"}
            or payload.get("connection_id") != connection_id
            or payload.get("version") != 1
            or not isinstance(payload.get("password"), str)
        ):
            raise Socks5OperationError("credential_binding_mismatch")
        return validate_socks_password(payload["password"])


class SecureSocksSpecStore:
    def __init__(self, directory: str | Path) -> None:
        self._directory = Path(directory)

    def path_for(self, endpoint_id: int) -> Path:
        if isinstance(endpoint_id, bool) or endpoint_id <= 0:
            raise Socks5OperationError("invalid_socks_resource_id")
        return self._directory / f"endpoint-{endpoint_id}.json"

    def write(self, spec: Socks5Spec) -> Path:
        validate_socks_spec(spec)
        payload = json.dumps(
            {
                "bind_address": spec.bind_address,
                "client_ip_allowlist": list(spec.client_ip_allowlist),
                "connection_id": spec.connection_id,
                "endpoint_id": spec.endpoint_id,
                "max_connections": spec.max_connections,
                "password": spec.password,
                "port": spec.port,
                "timeout_seconds": spec.timeout_seconds,
                "username": spec.username,
                "version": 1,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8") + b"\n"
        if len(payload) > MAX_SOCKS_SPEC_BYTES:
            raise Socks5OperationError("socks_spec_too_large")
        target = self.path_for(spec.endpoint_id)
        descriptor = -1
        temporary_path: Path | None = None
        try:
            self._directory.mkdir(mode=0o700, parents=True, exist_ok=True)
            if self._directory.is_symlink() or target.is_symlink():
                raise Socks5OperationError("unsafe_socks_spec_path")
            os.chmod(self._directory, 0o700)
            descriptor, temporary_name = tempfile.mkstemp(
                prefix=f".endpoint-{spec.endpoint_id}-",
                suffix=".tmp",
                dir=self._directory,
            )
            temporary_path = Path(temporary_name)
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb") as handle:
                descriptor = -1
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary_path, target)
            os.chmod(target, 0o600)
            return target
        except Socks5OperationError:
            raise
        except OSError as exc:
            raise Socks5OperationError("socks_spec_write_failed") from exc
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            if temporary_path is not None:
                temporary_path.unlink(missing_ok=True)

    def delete(self, endpoint_id: int) -> None:
        target = self.path_for(endpoint_id)
        if target.is_symlink():
            raise Socks5OperationError("unsafe_socks_spec_path")
        try:
            target.unlink(missing_ok=True)
        except OSError as exc:
            raise Socks5OperationError("socks_spec_delete_failed") from exc

    def cleanup_stale(self) -> int:
        if not self._directory.exists():
            return 0
        if self._directory.is_symlink():
            raise Socks5OperationError("unsafe_socks_spec_path")
        removed = 0
        try:
            for path in self._directory.iterdir():
                if (
                    re.fullmatch(r"endpoint-[1-9][0-9]{0,9}\.json", path.name)
                    and path.is_file()
                    and not path.is_symlink()
                ):
                    path.unlink()
                    removed += 1
        except OSError as exc:
            raise Socks5OperationError("socks_spec_cleanup_failed") from exc
        return removed


def allocate_socks_port(
    db: Session,
    *,
    port_start: int,
    port_end: int,
    requested_port: int | None = None,
) -> int:
    try:
        validate_port(port_start, minimum=1024)
        validate_port(port_end, minimum=port_start)
    except ResourceValidationError as exc:
        raise Socks5OperationError("invalid_socks_port_pool") from exc
    used_ports = set(db.scalars(select(SocksEndpoint.port)).all())
    if requested_port is not None:
        try:
            validate_port(requested_port, minimum=port_start, maximum=port_end)
        except ResourceValidationError as exc:
            raise Socks5OperationError("invalid_socks_port") from exc
        if requested_port in used_ports:
            raise Socks5OperationError("socks_port_in_use")
        return requested_port
    for port in range(port_start, port_end + 1):
        if port not in used_ports:
            return port
    raise Socks5OperationError("socks_port_pool_exhausted")


class Socks5Manager:
    def __init__(
        self,
        executor: NetworkExecutor,
        spec_store: SecureSocksSpecStore,
        *,
        allow_real_socks5: bool = False,
        ready_timeout_seconds: float = 15.0,
        poll_interval_seconds: float = 0.25,
        clock: Callable[[], float] = time.monotonic,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        if ready_timeout_seconds <= 0 or ready_timeout_seconds > 120:
            raise ValueError("invalid_socks_ready_timeout")
        if poll_interval_seconds <= 0 or poll_interval_seconds > ready_timeout_seconds:
            raise ValueError("invalid_socks_poll_interval")
        self._executor = executor
        self._spec_store = spec_store
        self._allow_real_socks5 = allow_real_socks5
        self._ready_timeout_seconds = ready_timeout_seconds
        self._poll_interval_seconds = poll_interval_seconds
        self._clock = clock
        self._sleeper = sleeper

    def _run(self, command: NetworkCommand, *, timeout_seconds: float = 20.0) -> int:
        if isinstance(self._executor, RealNetworkExecutor) and not self._allow_real_socks5:
            raise Socks5OperationError(
                "real SOCKS5 execution requires VPNGATE_ENABLE_REAL_SOCKS5=true"
            )
        try:
            result = self._executor.run(command, timeout_seconds=timeout_seconds)
        except Exception as exc:
            raise Socks5OperationError("socks_command_failed") from exc
        return result.returncode

    @staticmethod
    def _start_command(spec: Socks5Spec) -> NetworkCommand:
        return NetworkCommand(
            NetworkOperation.SOCKS5_START,
            (
                namespace_name(spec.connection_id),
                str(spec.connection_id),
                str(spec.endpoint_id),
            ),
        )

    @staticmethod
    def _stop_command(connection_id: int) -> NetworkCommand:
        return NetworkCommand(NetworkOperation.SOCKS5_STOP, (str(connection_id),))

    @staticmethod
    def _status_command(connection_id: int) -> NetworkCommand:
        return NetworkCommand(NetworkOperation.SOCKS5_STATUS, (str(connection_id),))

    @staticmethod
    def _ready_command(spec: Socks5Spec) -> NetworkCommand:
        return NetworkCommand(
            NetworkOperation.SOCKS5_READY,
            (
                namespace_name(spec.connection_id),
                str(spec.connection_id),
                str(spec.port),
            ),
        )

    @staticmethod
    def _tun_ready_command(connection_id: int) -> NetworkCommand:
        return NetworkCommand(
            NetworkOperation.OPENVPN_TUN_READY,
            (namespace_name(connection_id), str(connection_id)),
        )

    def _rollback_stop(self, connection_id: int) -> bool:
        try:
            return self._run(self._stop_command(connection_id)) == 0
        except Socks5OperationError:
            return False

    def _raise_after_rollback(self, connection_id: int, code: str) -> None:
        if not self._rollback_stop(connection_id):
            raise Socks5OperationError(f"{code}_cleanup_failed")
        raise Socks5OperationError(code)

    def status(self, spec: Socks5Spec) -> Socks5Runtime:
        validate_socks_spec(spec)
        command = self._status_command(spec.connection_id)
        if isinstance(self._executor, RealNetworkExecutor) and not self._allow_real_socks5:
            raise Socks5OperationError(
                "real SOCKS5 execution requires VPNGATE_ENABLE_REAL_SOCKS5=true"
            )
        try:
            result = self._executor.run(command, timeout_seconds=10.0)
        except Exception as exc:
            raise Socks5OperationError("socks_status_failed") from exc
        if result.returncode not in {0, 3}:
            raise Socks5OperationError("socks_status_failed")
        raw_pid = result.stdout.strip()
        parsed_pid = int(raw_pid) if raw_pid.isascii() and raw_pid.isdecimal() else 0
        pid = parsed_pid if 1 < parsed_pid <= 2_147_483_647 else None
        return Socks5Runtime(
            connection_id=spec.connection_id,
            endpoint_id=spec.endpoint_id,
            namespace=namespace_name(spec.connection_id),
            port=spec.port,
            running=result.returncode == 0,
            pid=pid,
        )

    def stop(self, spec: Socks5Spec) -> Socks5Runtime:
        validate_socks_spec(spec)
        if self._run(self._stop_command(spec.connection_id)) != 0:
            raise Socks5OperationError("socks_stop_failed")
        return self.status(spec)

    def start(self, spec: Socks5Spec) -> Socks5Runtime:
        validate_socks_spec(spec)
        if self._run(self._tun_ready_command(spec.connection_id), timeout_seconds=10.0) != 0:
            raise Socks5OperationError("socks_tunnel_not_ready")
        self._spec_store.write(spec)
        try:
            start_code = self._run(self._start_command(spec))
        except Socks5OperationError as exc:
            cleanup_ok = self._rollback_stop(spec.connection_id)
            try:
                self._spec_store.delete(spec.endpoint_id)
            except Socks5OperationError:
                cleanup_ok = False
            if not cleanup_ok:
                raise Socks5OperationError("socks_command_failed_cleanup_failed") from exc
            raise
        try:
            self._spec_store.delete(spec.endpoint_id)
        except Socks5OperationError:
            self._raise_after_rollback(
                spec.connection_id, "socks_spec_cleanup_failed"
            )
        if start_code != 0:
            self._raise_after_rollback(spec.connection_id, "socks_start_failed")

        deadline = self._clock() + self._ready_timeout_seconds
        ready_command = self._ready_command(spec)
        while True:
            result_code = self._run(ready_command, timeout_seconds=10.0)
            if result_code == 0:
                runtime = self.status(spec)
                if not runtime.running:
                    self._raise_after_rollback(
                        spec.connection_id, "socks_process_exited"
                    )
                return runtime
            if result_code != 3:
                self._raise_after_rollback(
                    spec.connection_id, "socks_ready_check_failed"
                )
            remaining = deadline - self._clock()
            if remaining <= 0:
                self._raise_after_rollback(spec.connection_id, "socks_ready_timeout")
            self._sleeper(min(self._poll_interval_seconds, remaining))


class SocksEndpointService:
    def __init__(
        self,
        cipher: CredentialCipher,
        manager: Socks5Manager,
        *,
        port_start: int = 21000,
        port_end: int = 21999,
    ) -> None:
        try:
            validate_port(port_start, minimum=1024)
            validate_port(port_end, minimum=port_start)
        except ResourceValidationError as exc:
            raise ValueError("invalid_socks_port_pool") from exc
        self._cipher = cipher
        self._manager = manager
        self._port_start = port_start
        self._port_end = port_end

    def create(
        self,
        db: Session,
        *,
        connection_id: int,
        username: str,
        requested_port: int | None = None,
        password: str | None = None,
        client_ip_allowlist: Iterable[str] = (),
        max_connections: int = 100,
        timeout_seconds: int = 300,
    ) -> tuple[SocksEndpoint, str]:
        if db.get(VPNConnection, connection_id) is None:
            raise Socks5OperationError("connection_not_found")
        existing = db.scalar(
            select(SocksEndpoint.id).where(
                SocksEndpoint.connection_id == connection_id
            )
        )
        if existing is not None:
            raise Socks5OperationError("socks_endpoint_exists")
        normalized_username = validate_socks_username(username)
        plaintext_password = validate_socks_password(password or generate_socks_password())
        allowlist = normalize_client_ip_allowlist(client_ip_allowlist)
        port = allocate_socks_port(
            db,
            port_start=self._port_start,
            port_end=self._port_end,
            requested_port=requested_port,
        )
        provisional_spec = Socks5Spec(
            connection_id=connection_id,
            endpoint_id=1,
            port=port,
            username=normalized_username,
            password=plaintext_password,
            client_ip_allowlist=allowlist,
            max_connections=max_connections,
            timeout_seconds=timeout_seconds,
        )
        validate_socks_spec(provisional_spec)
        endpoint = SocksEndpoint(
            connection_id=connection_id,
            bind_address=provisional_spec.bind_address,
            port=port,
            username=normalized_username,
            encrypted_password=self._cipher.encrypt_password(
                connection_id, plaintext_password
            ),
            client_ip_allowlist=list(allowlist),
            max_connections=max_connections,
            timeout_seconds=timeout_seconds,
            is_active=False,
        )
        db.add(endpoint)
        try:
            db.flush()
        except IntegrityError as exc:
            db.rollback()
            raise Socks5OperationError("socks_port_in_use") from exc
        return endpoint, plaintext_password

    def spec_for(self, endpoint: SocksEndpoint) -> Socks5Spec:
        return validate_socks_spec(
            Socks5Spec(
                connection_id=endpoint.connection_id,
                endpoint_id=endpoint.id,
                port=endpoint.port,
                username=endpoint.username,
                password=self._cipher.decrypt_password(
                    endpoint.connection_id, endpoint.encrypted_password
                ),
                client_ip_allowlist=tuple(endpoint.client_ip_allowlist),
                bind_address=endpoint.bind_address,
                max_connections=endpoint.max_connections,
                timeout_seconds=endpoint.timeout_seconds,
            )
        )

    def rotate_password(self, endpoint: SocksEndpoint) -> str:
        if endpoint.is_active:
            raise Socks5OperationError("socks_endpoint_active")
        password = generate_socks_password()
        endpoint.encrypted_password = self._cipher.encrypt_password(
            endpoint.connection_id, password
        )
        return password

    @staticmethod
    def add_traffic(
        endpoint: SocksEndpoint,
        *,
        bytes_up: int,
        bytes_down: int,
    ) -> None:
        maximum = 9_223_372_036_854_775_807
        if any(
            isinstance(value, bool) or value < 0 or value > maximum
            for value in (bytes_up, bytes_down)
        ):
            raise Socks5OperationError("invalid_socks_traffic_counter")
        if endpoint.bytes_up > maximum - bytes_up or endpoint.bytes_down > maximum - bytes_down:
            raise Socks5OperationError("socks_traffic_counter_overflow")
        endpoint.bytes_up += bytes_up
        endpoint.bytes_down += bytes_down

    def status(self, endpoint: SocksEndpoint) -> Socks5Runtime:
        runtime = self._manager.status(self.spec_for(endpoint))
        endpoint.is_active = runtime.running
        return replace(
            runtime,
            bytes_up=endpoint.bytes_up,
            bytes_down=endpoint.bytes_down,
        )

    def start(self, endpoint: SocksEndpoint) -> Socks5Runtime:
        runtime = self._manager.start(self.spec_for(endpoint))
        endpoint.is_active = runtime.running
        return replace(
            runtime,
            bytes_up=endpoint.bytes_up,
            bytes_down=endpoint.bytes_down,
        )

    def stop(self, endpoint: SocksEndpoint) -> Socks5Runtime:
        runtime = self._manager.stop(self.spec_for(endpoint))
        endpoint.is_active = runtime.running
        return replace(
            runtime,
            bytes_up=endpoint.bytes_up,
            bytes_down=endpoint.bytes_down,
        )
