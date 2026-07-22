import os
from pathlib import Path
import grp
import ipaddress
import json
import pwd
import re
import signal
import stat
import subprocess
import sys
import tempfile
import time
from collections.abc import Sequence
from dataclasses import dataclass

from app.services.network.commands import (
    CommandValidationError,
    INTERNAL_NETWORK,
    NetworkCommand,
    NetworkOperation,
    build_ip_argv,
    host_veth_name,
    namespace_name,
    namespace_veth_name,
)
from app.services.network.firewall_rules import (
    FirewallRuleSpec,
    IptablesRuleSet,
    NftRuleSet,
    iptables_rule_set,
    nft_rule_set,
)
from app.services.vpngate.openvpn import (
    MAX_CONFIG_BYTES,
    validate_stored_openvpn_config,
)
from app.services.vpngate.types import OpenVPNConfigError


HELPER_TIMEOUT_SECONDS = 20
ENVIRONMENT_FILE = Path("/etc/vpngate-manager/vpngate.env")
NETNS_CONFIG_DIRECTORY = Path("/etc/netns")
NETNS_RUN_DIRECTORIES = (Path("/run/netns"), Path("/var/run/netns"))
OPENVPN_CONFIG_DIRECTORY = Path("/var/lib/vpngate-manager/openvpn-configs")
OPENVPN_RUNTIME_DIRECTORY = Path("/run/vpngate-manager/openvpn")
OPENVPN_LOG_DIRECTORY = Path("/var/log/vpngate-manager/openvpn")
OPENVPN_SERVICE_ACCOUNT = "vpngate-manager"
OPENVPN_STOP_TIMEOUT_SECONDS = 10.0
OPENVPN_BINARY_CANDIDATES = (
    "/usr/sbin/openvpn",
    "/usr/bin/openvpn",
    "/sbin/openvpn",
)
SOCKS_SPEC_DIRECTORY = Path("/var/lib/vpngate-manager/socks-configs")
SOCKS_RUNTIME_DIRECTORY = Path("/run/vpngate-manager/socks")
SOCKS_LOG_DIRECTORY = Path("/var/log/vpngate-manager/socks")
SOCKS_SERVICE_ACCOUNT = "vpngate-manager"
SOCKS_STOP_TIMEOUT_SECONDS = 10.0
SOCKS_MAX_SPEC_BYTES = 32 * 1024
SOCKS_BINARY_CANDIDATES = (
    "/usr/bin/3proxy",
    "/usr/sbin/3proxy",
    "/usr/local/bin/3proxy",
    "/usr/local/sbin/3proxy",
)
SS_BINARY_CANDIDATES = (
    "/usr/bin/ss",
    "/usr/sbin/ss",
    "/bin/ss",
    "/sbin/ss",
)
FIREWALL_RUNTIME_DIRECTORY = Path("/run/vpngate-manager/firewall")
IP_FORWARD_PATH = Path("/proc/sys/net/ipv4/ip_forward")
NFT_BINARY_CANDIDATES = (
    "/usr/sbin/nft",
    "/usr/bin/nft",
    "/sbin/nft",
    "/bin/nft",
)
IPTABLES_BINARY_CANDIDATES = (
    "/usr/sbin/iptables",
    "/usr/bin/iptables",
    "/sbin/iptables",
    "/bin/iptables",
)
CURL_BINARY_CANDIDATES = (
    "/usr/bin/curl",
    "/bin/curl",
)
EXIT_IP_URL = "https://api.ipify.org?format=json"
SPEED_PROBE_URL = "https://speed.cloudflare.com/__down?bytes=262144"
NETFLIX_ORIGINAL_URL = "https://www.netflix.com/title/80018499"
NETFLIX_CATALOG_URL = "https://www.netflix.com/title/70143836"
CHATGPT_URL = "https://chatgpt.com/"
CHATGPT_STATIC_URL = "https://chatgpt.com/favicon.ico"
OPENAI_API_URL = "https://api.openai.com/v1/models"
YOUTUBE_URL = "https://www.youtube.com/premium"
SOCKS_USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{2,63}$")
SOCKS_PASSWORD_PATTERN = re.compile(r"^[A-Za-z0-9_-]{20,128}$")
ENVIRONMENT_ASSIGNMENT_PATTERN = re.compile(
    r"^(VPNGATE_[A-Z0-9_]+)=([^\x00-\x1f\x7f]*)$"
)
PROC_DIRECTORY = Path("/proc")
SAFE_ENVIRONMENT = {
    "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
}


@dataclass(frozen=True)
class _FirewallState:
    backend: str
    node_id: int
    socks_port: int | None


@dataclass(frozen=True)
class _UnlockHTTPResult:
    returncode: int
    http_status: int | None
    latency_ms: float | None
    body: str


def _find_ip_binary() -> str:
    for candidate in ("/usr/sbin/ip", "/usr/bin/ip", "/sbin/ip", "/bin/ip"):
        path = Path(candidate)
        if path.is_file() and os.access(path, os.X_OK):
            return candidate
    raise RuntimeError("ip_binary_not_found")


def _find_openvpn_binary() -> str:
    for candidate in OPENVPN_BINARY_CANDIDATES:
        path = Path(candidate)
        if path.is_file() and os.access(path, os.X_OK):
            return candidate
    raise RuntimeError("openvpn_binary_not_found")


def _find_socks_binary() -> str:
    for candidate in SOCKS_BINARY_CANDIDATES:
        path = Path(candidate)
        if path.is_file() and os.access(path, os.X_OK):
            return candidate
    raise RuntimeError("socks_binary_not_found")


def _find_ss_binary() -> str:
    for candidate in SS_BINARY_CANDIDATES:
        path = Path(candidate)
        if path.is_file() and os.access(path, os.X_OK):
            return candidate
    raise RuntimeError("ss_binary_not_found")


def _find_nft_binary() -> str:
    for candidate in NFT_BINARY_CANDIDATES:
        path = Path(candidate)
        if path.is_file() and os.access(path, os.X_OK):
            return candidate
    raise RuntimeError("nft_binary_not_found")


def _find_iptables_binary() -> str:
    for candidate in IPTABLES_BINARY_CANDIDATES:
        path = Path(candidate)
        if path.is_file() and os.access(path, os.X_OK):
            return candidate
    raise RuntimeError("iptables_binary_not_found")


def _find_curl_binary() -> str:
    for candidate in CURL_BINARY_CANDIDATES:
        path = Path(candidate)
        if path.is_file() and os.access(path, os.X_OK):
            return candidate
    raise RuntimeError("curl_binary_not_found")


def _trusted_assignments_from_text(value: str) -> dict[str, str] | None:
    assignments: dict[str, str] = {}
    for line in value.splitlines():
        if not line or line.startswith("#"):
            continue
        match = ENVIRONMENT_ASSIGNMENT_PATTERN.fullmatch(line)
        if match is None or match.group(1) in assignments:
            return None
        assignments[match.group(1)] = match.group(2)
    return assignments


def _enabled_from_text(value: str) -> bool:
    assignments = _trusted_assignments_from_text(value)
    return (
        assignments is not None
        and assignments.get("VPNGATE_ENABLE_REAL_NETWORK") == "true"
    )


def _openvpn_enabled_from_text(value: str) -> bool:
    assignments = _trusted_assignments_from_text(value)
    return (
        assignments is not None
        and _firewall_enabled_from_text(value)
        and assignments.get("VPNGATE_ENABLE_REAL_OPENVPN") == "true"
    )


def _socks_enabled_from_text(value: str) -> bool:
    assignments = _trusted_assignments_from_text(value)
    return (
        assignments is not None
        and _openvpn_enabled_from_text(value)
        and assignments.get("VPNGATE_ENABLE_REAL_SOCKS5") == "true"
    )


def _firewall_enabled_from_text(value: str) -> bool:
    assignments = _trusted_assignments_from_text(value)
    return (
        assignments is not None
        and _enabled_from_text(value)
        and assignments.get("VPNGATE_ENABLE_REAL_FIREWALL") == "true"
    )


def _full_scans_enabled_from_text(value: str) -> bool:
    assignments = _trusted_assignments_from_text(value)
    return (
        assignments is not None
        and _openvpn_enabled_from_text(value)
        and assignments.get("VPNGATE_ENABLE_REAL_FULL_SCANS") == "true"
    )


def _unlock_checks_enabled_from_text(value: str) -> bool:
    assignments = _trusted_assignments_from_text(value)
    return (
        assignments is not None
        and _openvpn_enabled_from_text(value)
        and assignments.get("VPNGATE_ENABLE_REAL_UNLOCK_CHECKS") == "true"
    )


def _socks_port_range_from_text(value: str) -> tuple[int, int] | None:
    assignments = _trusted_assignments_from_text(value)
    if assignments is None:
        return None
    start_text = assignments.get("VPNGATE_SOCKS_PORT_START", "21000")
    end_text = assignments.get("VPNGATE_SOCKS_PORT_END", "21999")
    if (
        not start_text.isascii()
        or not start_text.isdecimal()
        or not end_text.isascii()
        or not end_text.isdecimal()
    ):
        return None
    start = int(start_text, 10)
    end = int(end_text, 10)
    if not 1024 <= start <= end <= 65535:
        return None
    if str(start) != start_text or str(end) != end_text:
        return None
    return start, end


def _read_trusted_environment() -> str | None:
    try:
        metadata = ENVIRONMENT_FILE.lstat()
        if (
            ENVIRONMENT_FILE.is_symlink()
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != 0
            or metadata.st_mode & 0o022
            or metadata.st_size > 64 * 1024
        ):
            return None
        content = ENVIRONMENT_FILE.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return None
    return content if _trusted_assignments_from_text(content) is not None else None


def real_network_enabled() -> bool:
    content = _read_trusted_environment()
    return content is not None and _enabled_from_text(content)


def real_openvpn_enabled() -> bool:
    content = _read_trusted_environment()
    return content is not None and _openvpn_enabled_from_text(content)


def real_socks5_enabled() -> bool:
    content = _read_trusted_environment()
    return content is not None and _socks_enabled_from_text(content)


def real_firewall_enabled() -> bool:
    content = _read_trusted_environment()
    return content is not None and _firewall_enabled_from_text(content)


def real_full_scans_enabled() -> bool:
    content = _read_trusted_environment()
    return content is not None and _full_scans_enabled_from_text(content)


def real_unlock_checks_enabled() -> bool:
    content = _read_trusted_environment()
    return content is not None and _unlock_checks_enabled_from_text(content)


def trusted_socks_port_range() -> tuple[int, int] | None:
    content = _read_trusted_environment()
    return None if content is None else _socks_port_range_from_text(content)


def parse_command(arguments: Sequence[str]) -> NetworkCommand:
    if not arguments:
        raise CommandValidationError("missing_operation")
    try:
        operation = NetworkOperation(arguments[0])
    except ValueError as exc:
        raise CommandValidationError("invalid_operation") from exc
    return NetworkCommand(operation=operation, arguments=tuple(arguments[1:]))


def _safe_owned_directory(path: Path, *, create: bool) -> bool:
    try:
        if create:
            path.mkdir(mode=0o755, parents=False, exist_ok=True)
        metadata = path.lstat()
    except OSError:
        return False
    return (
        not path.is_symlink()
        and stat.S_ISDIR(metadata.st_mode)
        and metadata.st_uid == os.geteuid()
        and metadata.st_mode & 0o022 == 0
    )


def _write_namespace_dns(command: NetworkCommand) -> int:
    namespace = command.arguments[0]
    try:
        NETNS_CONFIG_DIRECTORY.mkdir(mode=0o755, parents=True, exist_ok=True)
    except OSError:
        print("dns_directory_failed", file=sys.stderr)
        return 126
    if not _safe_owned_directory(NETNS_CONFIG_DIRECTORY, create=False):
        print("unsafe_dns_directory", file=sys.stderr)
        return 126
    namespace_directory = NETNS_CONFIG_DIRECTORY / namespace
    if not _safe_owned_directory(namespace_directory, create=True):
        print("unsafe_namespace_dns_directory", file=sys.stderr)
        return 126
    target = namespace_directory / "resolv.conf"
    if target.is_symlink():
        print("unsafe_dns_target", file=sys.stderr)
        return 126
    descriptor = -1
    temporary_path: Path | None = None
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=".resolv-", suffix=".tmp", dir=namespace_directory
        )
        temporary_path = Path(temporary_name)
        os.fchmod(descriptor, 0o644)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            descriptor = -1
            for server in command.arguments[1:]:
                handle.write(f"nameserver {server}\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, target)
        os.chmod(target, 0o644)
        return 0
    except OSError:
        print("dns_write_failed", file=sys.stderr)
        return 126
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def _delete_namespace_dns(command: NetworkCommand) -> int:
    if not NETNS_CONFIG_DIRECTORY.exists():
        return 0
    if not _safe_owned_directory(NETNS_CONFIG_DIRECTORY, create=False):
        print("unsafe_dns_directory", file=sys.stderr)
        return 126
    namespace_directory = NETNS_CONFIG_DIRECTORY / command.arguments[0]
    if not namespace_directory.exists() and not namespace_directory.is_symlink():
        return 0
    if namespace_directory.is_symlink():
        print("unsafe_namespace_dns_directory", file=sys.stderr)
        return 126
    if not _safe_owned_directory(namespace_directory, create=False):
        print("unsafe_namespace_dns_directory", file=sys.stderr)
        return 126
    target = namespace_directory / "resolv.conf"
    try:
        if target.is_symlink():
            print("unsafe_dns_target", file=sys.stderr)
            return 126
        target.unlink(missing_ok=True)
        namespace_directory.rmdir()
    except FileNotFoundError:
        return 0
    except OSError:
        print("dns_delete_failed", file=sys.stderr)
        return 126
    return 0


def _namespace_exists(namespace: str) -> bool:
    return any((directory / namespace).exists() for directory in NETNS_RUN_DIRECTORIES)


def _host_veth_exists(ip_binary: str, interface: str) -> bool | None:
    try:
        completed = subprocess.run(
            (ip_binary, "link", "show", "dev", interface),
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=HELPER_TIMEOUT_SECONDS,
            close_fds=True,
            env=SAFE_ENVIRONMENT,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if completed.returncode == 0:
        return True
    if completed.returncode == 1:
        return False
    return None


def _service_uid() -> int:
    try:
        return pwd.getpwnam(OPENVPN_SERVICE_ACCOUNT).pw_uid
    except KeyError as exc:
        raise RuntimeError("service_account_not_found") from exc


def _service_gid() -> int:
    try:
        return grp.getgrnam(SOCKS_SERVICE_ACCOUNT).gr_gid
    except KeyError as exc:
        raise RuntimeError("service_account_not_found") from exc


@dataclass(frozen=True)
class _ValidatedSocksSpec:
    connection_id: int
    endpoint_id: int
    port: int
    username: str
    password: str
    client_ip_allowlist: tuple[str, ...]
    bind_address: str
    max_connections: int
    timeout_seconds: int


def _openvpn_config_path(node_id: str) -> Path:
    return OPENVPN_CONFIG_DIRECTORY / f"node-{node_id}.ovpn"


def _openvpn_pid_path(connection_id: str) -> Path:
    return OPENVPN_RUNTIME_DIRECTORY / f"openvpn-{connection_id}.pid"


def _openvpn_log_path(connection_id: str) -> Path:
    return OPENVPN_LOG_DIRECTORY / f"openvpn-{connection_id}.log"


def _staged_openvpn_config_path(connection_id: str) -> Path:
    return OPENVPN_RUNTIME_DIRECTORY / f"openvpn-{connection_id}.ovpn"


def _load_validated_openvpn_config(node_id: str) -> tuple[Path, bytes]:
    config_path = _openvpn_config_path(node_id)
    descriptor = -1
    try:
        directory_metadata = OPENVPN_CONFIG_DIRECTORY.lstat()
        service_uid = _service_uid()
        if (
            OPENVPN_CONFIG_DIRECTORY.is_symlink()
            or not stat.S_ISDIR(directory_metadata.st_mode)
            or directory_metadata.st_uid not in {0, service_uid}
            or directory_metadata.st_mode & 0o077
        ):
            raise RuntimeError("unsafe_openvpn_config")
        descriptor = os.open(
            config_path,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid not in {0, service_uid}
            or metadata.st_mode & 0o077
            or metadata.st_size <= 0
            or metadata.st_size > MAX_CONFIG_BYTES
        ):
            raise RuntimeError("unsafe_openvpn_config")
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            raw_config = handle.read(MAX_CONFIG_BYTES + 1)
        if len(raw_config) > MAX_CONFIG_BYTES:
            raise RuntimeError("unsafe_openvpn_config")
        validate_stored_openvpn_config(raw_config)
    except (OSError, OpenVPNConfigError) as exc:
        raise RuntimeError("unsafe_openvpn_config") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    return config_path, raw_config


def _validate_openvpn_config_file(node_id: str) -> Path:
    config_path, _ = _load_validated_openvpn_config(node_id)
    return config_path


def _ensure_root_directory(path: Path, *, mode: int) -> None:
    try:
        path.mkdir(mode=mode, parents=True, exist_ok=True)
        metadata = path.lstat()
        if (
            path.is_symlink()
            or not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_mode & 0o022
        ):
            raise RuntimeError("unsafe_openvpn_directory")
        os.chmod(path, mode)
    except OSError as exc:
        raise RuntimeError("unsafe_openvpn_directory") from exc


def _firewall_state_path(connection_id: str) -> Path:
    return FIREWALL_RUNTIME_DIRECTORY / f"killswitch-{connection_id}.backend"


def _firewall_state_bytes(state: _FirewallState) -> bytes:
    return json.dumps(
        {
            "backend": state.backend,
            "node_id": state.node_id,
            "socks_port": state.socks_port,
            "version": 1,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii") + b"\n"


def _write_firewall_state(
    connection_id: str,
    backend: str,
    *,
    node_id: int,
    socks_port: int | None,
) -> None:
    if backend not in {"nftables", "iptables"}:
        raise RuntimeError("invalid_firewall_backend")
    state = _FirewallState(
        backend=backend,
        node_id=node_id,
        socks_port=socks_port,
    )
    payload = _firewall_state_bytes(state)
    _ensure_root_directory(FIREWALL_RUNTIME_DIRECTORY, mode=0o750)
    target = _firewall_state_path(connection_id)
    if target.is_symlink():
        raise RuntimeError("unsafe_firewall_state")
    descriptor = -1
    temporary_path: Path | None = None
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".killswitch-{connection_id}-",
            suffix=".tmp",
            dir=FIREWALL_RUNTIME_DIRECTORY,
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
    except OSError as exc:
        raise RuntimeError("firewall_state_write_failed") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def _read_firewall_state(connection_id: str) -> _FirewallState | None:
    target = _firewall_state_path(connection_id)
    if not target.exists() and not target.is_symlink():
        return None
    try:
        metadata = target.lstat()
        if (
            target.is_symlink()
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_mode & 0o077
            or metadata.st_size <= 0
            or metadata.st_size > 1024
        ):
            raise RuntimeError("unsafe_firewall_state")
        raw_state = target.read_bytes()
        payload = json.loads(raw_state.decode("ascii"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("unsafe_firewall_state") from exc
    if (
        not isinstance(payload, dict)
        or set(payload) != {"backend", "node_id", "socks_port", "version"}
        or payload.get("version") != 1
        or payload.get("backend") not in {"nftables", "iptables"}
        or isinstance(payload.get("node_id"), bool)
        or not isinstance(payload.get("node_id"), int)
        or not 1 <= payload["node_id"] <= 2_147_483_647
        or (
            payload.get("socks_port") is not None
            and (
                isinstance(payload.get("socks_port"), bool)
                or not isinstance(payload.get("socks_port"), int)
                or not 1024 <= payload["socks_port"] <= 65535
            )
        )
    ):
        raise RuntimeError("unsafe_firewall_state")
    state = _FirewallState(
        backend=payload["backend"],
        node_id=payload["node_id"],
        socks_port=payload["socks_port"],
    )
    if _firewall_state_bytes(state) != raw_state:
        raise RuntimeError("unsafe_firewall_state")
    return state


def _delete_firewall_state(connection_id: str) -> None:
    target = _firewall_state_path(connection_id)
    if target.is_symlink():
        raise RuntimeError("unsafe_firewall_state")
    try:
        target.unlink(missing_ok=True)
    except OSError as exc:
        raise RuntimeError("firewall_state_delete_failed") from exc


def _ip_forward_enabled() -> bool:
    try:
        return IP_FORWARD_PATH.read_text(encoding="ascii").strip() == "1"
    except (OSError, UnicodeError):
        return False


def _firewall_addresses(connection_id: int) -> tuple[str, str]:
    network_address = int(INTERNAL_NETWORK.network_address) + (connection_id - 1) * 4
    subnet = ipaddress.IPv4Network((network_address, 30))
    host_address, namespace_address = tuple(subnet.hosts())
    return str(host_address), str(namespace_address)


def _firewall_spec_from_command(command: NetworkCommand) -> FirewallRuleSpec:
    (
        namespace,
        connection_id_text,
        _,
        remote_address,
        remote_port,
        remote_protocol,
        socks_port,
        _,
        allowlist_text,
    ) = command.arguments
    connection_id = int(connection_id_text, 10)
    host_address, namespace_address = _firewall_addresses(connection_id)
    allowlist = () if allowlist_text == "-" else tuple(allowlist_text.split(","))
    return FirewallRuleSpec(
        connection_id=connection_id,
        namespace=namespace,
        host_veth=host_veth_name(connection_id),
        namespace_veth=namespace_veth_name(connection_id),
        host_address=host_address,
        namespace_address=namespace_address,
        remote_address=remote_address,
        remote_port=int(remote_port, 10),
        remote_protocol=remote_protocol,
        socks_port=None if socks_port == "-" else int(socks_port, 10),
        client_ip_allowlist=allowlist,
    )


def _select_firewall_backend(requested: str) -> tuple[str, str]:
    if requested == "nftables":
        return requested, _find_nft_binary()
    if requested == "iptables":
        return requested, _find_iptables_binary()
    if requested != "auto":
        raise RuntimeError("invalid_firewall_backend")
    try:
        return "nftables", _find_nft_binary()
    except RuntimeError:
        return "iptables", _find_iptables_binary()


def _run_nft_script(argv: tuple[str, ...], script: str) -> int:
    try:
        completed = subprocess.run(
            argv,
            input=script,
            text=True,
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=HELPER_TIMEOUT_SECONDS,
            close_fds=True,
            env=SAFE_ENVIRONMENT,
        )
    except subprocess.TimeoutExpired:
        return 124
    except OSError:
        return 126
    return completed.returncode


def _run_quiet(argv: tuple[str, ...]) -> int:
    try:
        completed = subprocess.run(
            argv,
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=HELPER_TIMEOUT_SECONDS,
            close_fds=True,
            env=SAFE_ENVIRONMENT,
        )
    except subprocess.TimeoutExpired:
        return 124
    except OSError:
        return 126
    return completed.returncode


def _cleanup_nft_rules(
    spec: FirewallRuleSpec,
    rules: NftRuleSet,
    *,
    ip_binary: str,
    nft_binary: str,
) -> None:
    _run_quiet((nft_binary, "delete", "table", "inet", rules.host_table))
    if _namespace_exists(spec.namespace):
        _run_quiet(
            (
                ip_binary,
                "netns",
                "exec",
                spec.namespace,
                nft_binary,
                "delete",
                "table",
                "inet",
                rules.namespace_table,
            )
        )


def _apply_nft_rules(
    spec: FirewallRuleSpec,
    *,
    ip_binary: str,
    nft_binary: str,
) -> int:
    rules = nft_rule_set(spec)
    _cleanup_nft_rules(spec, rules, ip_binary=ip_binary, nft_binary=nft_binary)
    namespace_code = _run_nft_script(
        (
            ip_binary,
            "netns",
            "exec",
            spec.namespace,
            nft_binary,
            "-f",
            "-",
        ),
        rules.namespace_script,
    )
    if namespace_code != 0:
        _cleanup_nft_rules(spec, rules, ip_binary=ip_binary, nft_binary=nft_binary)
        return namespace_code
    host_code = _run_nft_script(
        (nft_binary, "-f", "-"),
        rules.host_script,
    )
    if host_code != 0:
        _cleanup_nft_rules(spec, rules, ip_binary=ip_binary, nft_binary=nft_binary)
    return host_code


def _nft_rules_active(
    spec: FirewallRuleSpec,
    *,
    ip_binary: str,
    nft_binary: str,
) -> bool:
    if not _namespace_exists(spec.namespace):
        return False
    rules = nft_rule_set(spec)
    host_code = _run_quiet(
        (nft_binary, "list", "table", "inet", rules.host_table)
    )
    namespace_code = _run_quiet(
        (
            ip_binary,
            "netns",
            "exec",
            spec.namespace,
            nft_binary,
            "list",
            "table",
            "inet",
            rules.namespace_table,
        )
    )
    return host_code == 0 and namespace_code == 0


def _nft_rules_present(
    spec: FirewallRuleSpec,
    *,
    ip_binary: str,
    nft_binary: str,
) -> bool:
    rules = nft_rule_set(spec)
    host_present = (
        _run_quiet((nft_binary, "list", "table", "inet", rules.host_table)) == 0
    )
    namespace_present = False
    if _namespace_exists(spec.namespace):
        namespace_present = (
            _run_quiet(
                (
                    ip_binary,
                    "netns",
                    "exec",
                    spec.namespace,
                    nft_binary,
                    "list",
                    "table",
                    "inet",
                    rules.namespace_table,
                )
            )
            == 0
        )
    return host_present or namespace_present


def _iptables_argv(
    binary: str,
    arguments: tuple[str, ...],
    *,
    namespace: str | None = None,
    ip_binary: str,
) -> tuple[str, ...]:
    base = (binary, "-w", "5", *arguments)
    if namespace is None:
        return base
    return (ip_binary, "netns", "exec", namespace, *base)


def _cleanup_iptables_rules(
    spec: FirewallRuleSpec,
    rules: IptablesRuleSet,
    *,
    ip_binary: str,
    iptables_binary: str,
) -> None:
    for arguments in rules.host_cleanup:
        _run_quiet(
            _iptables_argv(
                iptables_binary, arguments, namespace=None, ip_binary=ip_binary
            )
        )
    if _namespace_exists(spec.namespace):
        for arguments in rules.namespace_cleanup:
            _run_quiet(
                _iptables_argv(
                    iptables_binary,
                    arguments,
                    namespace=spec.namespace,
                    ip_binary=ip_binary,
                )
            )


def _apply_iptables_rules(
    spec: FirewallRuleSpec,
    *,
    ip_binary: str,
    iptables_binary: str,
) -> int:
    rules = iptables_rule_set(spec)
    _cleanup_iptables_rules(
        spec, rules, ip_binary=ip_binary, iptables_binary=iptables_binary
    )
    for arguments in rules.namespace_apply:
        code = _run_quiet(
            _iptables_argv(
                iptables_binary,
                arguments,
                namespace=spec.namespace,
                ip_binary=ip_binary,
            )
        )
        if code != 0:
            _cleanup_iptables_rules(
                spec, rules, ip_binary=ip_binary, iptables_binary=iptables_binary
            )
            return code
    for arguments in rules.host_apply:
        code = _run_quiet(
            _iptables_argv(
                iptables_binary, arguments, namespace=None, ip_binary=ip_binary
            )
        )
        if code != 0:
            _cleanup_iptables_rules(
                spec, rules, ip_binary=ip_binary, iptables_binary=iptables_binary
            )
            return code
    return 0


def _iptables_rules_active(
    spec: FirewallRuleSpec,
    *,
    ip_binary: str,
    iptables_binary: str,
) -> bool:
    if not _namespace_exists(spec.namespace):
        return False
    rules = iptables_rule_set(spec)
    checks = [
        _iptables_argv(
            iptables_binary,
            ("-S", rules.host_chains[2]),
            namespace=None,
            ip_binary=ip_binary,
        ),
        _iptables_argv(
            iptables_binary,
            ("-t", "nat", "-S", rules.host_chains[0]),
            namespace=None,
            ip_binary=ip_binary,
        ),
        _iptables_argv(
            iptables_binary,
            ("-S", rules.namespace_chains[0]),
            namespace=spec.namespace,
            ip_binary=ip_binary,
        ),
    ]
    return all(_run_quiet(argv) == 0 for argv in checks)


def _iptables_rules_present(
    spec: FirewallRuleSpec,
    *,
    ip_binary: str,
    iptables_binary: str,
) -> bool:
    rules = iptables_rule_set(spec)
    checks = [
        _iptables_argv(
            iptables_binary,
            ("-S", rules.host_chains[2]),
            namespace=None,
            ip_binary=ip_binary,
        ),
        _iptables_argv(
            iptables_binary,
            ("-t", "nat", "-S", rules.host_chains[0]),
            namespace=None,
            ip_binary=ip_binary,
        ),
    ]
    if _namespace_exists(spec.namespace):
        checks.append(
            _iptables_argv(
                iptables_binary,
                ("-S", rules.namespace_chains[0]),
                namespace=spec.namespace,
                ip_binary=ip_binary,
            )
        )
    return any(_run_quiet(argv) == 0 for argv in checks)


def _has_argument_pair(arguments: list[str], option: str, value: str) -> bool:
    return any(
        arguments[index] == option and arguments[index + 1] == value
        for index in range(len(arguments) - 1)
    )


def _stage_openvpn_config(connection_id: str, raw_config: bytes) -> Path:
    target = _staged_openvpn_config_path(connection_id)
    if target.is_symlink():
        raise RuntimeError("unsafe_openvpn_runtime_path")
    descriptor = -1
    temporary_path: Path | None = None
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".openvpn-{connection_id}-",
            suffix=".tmp",
            dir=OPENVPN_RUNTIME_DIRECTORY,
        )
        temporary_path = Path(temporary_name)
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(raw_config)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, target)
        os.chmod(target, 0o600)
        return target
    except OSError as exc:
        raise RuntimeError("openvpn_config_stage_failed") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def _socks_spec_path(endpoint_id: str) -> Path:
    return SOCKS_SPEC_DIRECTORY / f"endpoint-{endpoint_id}.json"


def _socks_pid_path(connection_id: str) -> Path:
    return SOCKS_RUNTIME_DIRECTORY / f"socks-{connection_id}.pid"


def _socks_config_path(connection_id: str) -> Path:
    return SOCKS_RUNTIME_DIRECTORY / f"socks-{connection_id}.cfg"


def _socks_log_path(connection_id: str) -> Path:
    return SOCKS_LOG_DIRECTORY / f"socks-{connection_id}.log"


def _canonical_socks_spec_bytes(payload: dict[str, object]) -> bytes:
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8") + b"\n"


def _parse_socks_spec(
    raw_spec: bytes,
    *,
    connection_id: str,
    endpoint_id: str,
    port_range: tuple[int, int],
) -> _ValidatedSocksSpec:
    try:
        payload = json.loads(raw_spec.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("unsafe_socks_spec") from exc
    expected_keys = {
        "bind_address",
        "client_ip_allowlist",
        "connection_id",
        "endpoint_id",
        "max_connections",
        "password",
        "port",
        "timeout_seconds",
        "username",
        "version",
    }
    if (
        not isinstance(payload, dict)
        or set(payload) != expected_keys
        or _canonical_socks_spec_bytes(payload) != raw_spec
    ):
        raise RuntimeError("unsafe_socks_spec")
    parsed_connection_id = payload.get("connection_id")
    parsed_endpoint_id = payload.get("endpoint_id")
    port = payload.get("port")
    username = payload.get("username")
    password = payload.get("password")
    allowlist = payload.get("client_ip_allowlist")
    bind_address = payload.get("bind_address")
    max_connections = payload.get("max_connections")
    timeout_seconds = payload.get("timeout_seconds")
    if (
        payload.get("version") != 1
        or isinstance(parsed_connection_id, bool)
        or not isinstance(parsed_connection_id, int)
        or parsed_connection_id != int(connection_id, 10)
        or isinstance(parsed_endpoint_id, bool)
        or not isinstance(parsed_endpoint_id, int)
        or parsed_endpoint_id != int(endpoint_id, 10)
        or isinstance(port, bool)
        or not isinstance(port, int)
        or port < port_range[0]
        or port > port_range[1]
        or not isinstance(username, str)
        or SOCKS_USERNAME_PATTERN.fullmatch(username) is None
        or not isinstance(password, str)
        or SOCKS_PASSWORD_PATTERN.fullmatch(password) is None
        or bind_address != "0.0.0.0"
        or isinstance(max_connections, bool)
        or not isinstance(max_connections, int)
        or max_connections < 1
        or max_connections > 1000
        or isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, int)
        or timeout_seconds < 10
        or timeout_seconds > 3600
        or not isinstance(allowlist, list)
        or len(allowlist) > 64
    ):
        raise RuntimeError("unsafe_socks_spec")
    normalized_allowlist: list[str] = []
    for value in allowlist:
        if not isinstance(value, str) or len(value) > 64:
            raise RuntimeError("unsafe_socks_spec")
        try:
            network = ipaddress.ip_network(value, strict=True)
        except ValueError as exc:
            raise RuntimeError("unsafe_socks_spec") from exc
        if (
            not isinstance(network, ipaddress.IPv4Network)
            or str(network) != value
            or network.network_address.is_unspecified
            or network.network_address.is_multicast
            or network.network_address.is_loopback
            or network.network_address.is_link_local
        ):
            raise RuntimeError("unsafe_socks_spec")
        normalized_allowlist.append(value)
    if len(set(normalized_allowlist)) != len(normalized_allowlist):
        raise RuntimeError("unsafe_socks_spec")
    return _ValidatedSocksSpec(
        connection_id=parsed_connection_id,
        endpoint_id=parsed_endpoint_id,
        port=port,
        username=username,
        password=password,
        client_ip_allowlist=tuple(normalized_allowlist),
        bind_address=bind_address,
        max_connections=max_connections,
        timeout_seconds=timeout_seconds,
    )


def _load_validated_socks_spec(
    connection_id: str,
    endpoint_id: str,
) -> _ValidatedSocksSpec:
    port_range = trusted_socks_port_range()
    if port_range is None:
        raise RuntimeError("invalid_socks_port_pool")
    spec_path = _socks_spec_path(endpoint_id)
    descriptor = -1
    try:
        directory_metadata = SOCKS_SPEC_DIRECTORY.lstat()
        service_uid = _service_uid()
        if (
            SOCKS_SPEC_DIRECTORY.is_symlink()
            or not stat.S_ISDIR(directory_metadata.st_mode)
            or directory_metadata.st_uid not in {0, service_uid}
            or directory_metadata.st_mode & 0o077
        ):
            raise RuntimeError("unsafe_socks_spec")
        descriptor = os.open(
            spec_path,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid not in {0, service_uid}
            or metadata.st_mode & 0o077
            or metadata.st_size <= 0
            or metadata.st_size > SOCKS_MAX_SPEC_BYTES
        ):
            raise RuntimeError("unsafe_socks_spec")
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            raw_spec = handle.read(SOCKS_MAX_SPEC_BYTES + 1)
        if len(raw_spec) > SOCKS_MAX_SPEC_BYTES:
            raise RuntimeError("unsafe_socks_spec")
        return _parse_socks_spec(
            raw_spec,
            connection_id=connection_id,
            endpoint_id=endpoint_id,
            port_range=port_range,
        )
    except RuntimeError:
        raise
    except OSError as exc:
        raise RuntimeError("unsafe_socks_spec") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _render_socks_config(spec: _ValidatedSocksSpec) -> bytes:
    service_uid = _service_uid()
    service_gid = _service_gid()
    lines = [
        "nscache 65536",
        (
            "timeouts 1 5 30 60 "
            f"{spec.timeout_seconds} {spec.timeout_seconds} 15 60"
        ),
        f"maxconn {spec.max_connections}",
        f"users {spec.username}:CL:{spec.password}",
        "auth strong",
    ]
    host_address, _ = _firewall_addresses(spec.connection_id)
    lines.append(f"allow {spec.username} {host_address}/32")
    lines.extend(
        [
            "deny *",
            f"setgid {service_gid}",
            f"setuid {service_uid}",
            (
                f"socks -p{spec.port} -i{spec.bind_address} "
                f"-e{spec.bind_address}"
            ),
            "flush",
        ]
    )
    return ("\n".join(lines) + "\n").encode("utf-8")


def _stage_socks_config(connection_id: str, spec: _ValidatedSocksSpec) -> Path:
    target = _socks_config_path(connection_id)
    if target.is_symlink():
        raise RuntimeError("unsafe_socks_runtime_path")
    descriptor = -1
    temporary_path: Path | None = None
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".socks-{connection_id}-",
            suffix=".tmp",
            dir=SOCKS_RUNTIME_DIRECTORY,
        )
        temporary_path = Path(temporary_name)
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(_render_socks_config(spec))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, target)
        os.chmod(target, 0o600)
        return target
    except OSError as exc:
        raise RuntimeError("socks_config_stage_failed") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def _write_socks_pid(connection_id: str, pid: int) -> None:
    target = _socks_pid_path(connection_id)
    if target.is_symlink():
        raise RuntimeError("unsafe_socks_runtime_path")
    descriptor = -1
    temporary_path: Path | None = None
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".socks-{connection_id}-",
            suffix=".pid",
            dir=SOCKS_RUNTIME_DIRECTORY,
        )
        temporary_path = Path(temporary_name)
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="ascii", newline="\n") as handle:
            descriptor = -1
            handle.write(f"{pid}\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, target)
        os.chmod(target, 0o600)
    except OSError as exc:
        raise RuntimeError("socks_pid_write_failed") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def _managed_socks_pid(connection_id: str) -> int | None:
    pid_path = _socks_pid_path(connection_id)
    if not pid_path.exists() and not pid_path.is_symlink():
        return None
    try:
        metadata = pid_path.lstat()
        if (
            pid_path.is_symlink()
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_mode & 0o022
            or metadata.st_size <= 0
            or metadata.st_size > 32
        ):
            raise RuntimeError("invalid_socks_pid_file")
        raw_pid = pid_path.read_text(encoding="ascii").strip()
        if not raw_pid.isdecimal() or str(int(raw_pid, 10)) != raw_pid:
            raise RuntimeError("invalid_socks_pid_file")
        pid = int(raw_pid, 10)
        if pid <= 1:
            raise RuntimeError("invalid_socks_pid_file")
        process_directory = PROC_DIRECTORY / str(pid)
        if not process_directory.exists():
            pid_path.unlink(missing_ok=True)
            _socks_config_path(connection_id).unlink(missing_ok=True)
            return None
        executable = (process_directory / "exe").resolve(strict=True)
        allowed_executables = {
            Path(candidate).resolve(strict=True)
            for candidate in SOCKS_BINARY_CANDIDATES
            if Path(candidate).exists()
        }
        if executable not in allowed_executables:
            raise RuntimeError("unmanaged_socks_process")
        raw_command_line = (process_directory / "cmdline").read_bytes()
        if len(raw_command_line) > 64 * 1024:
            raise RuntimeError("unmanaged_socks_process")
        arguments = [
            item.decode("utf-8", errors="strict")
            for item in raw_command_line.rstrip(b"\x00").split(b"\x00")
        ]
        if str(_socks_config_path(connection_id)) not in arguments[1:]:
            raise RuntimeError("unmanaged_socks_process")
    except RuntimeError:
        raise
    except (OSError, UnicodeError, ValueError) as exc:
        raise RuntimeError("invalid_socks_pid_file") from exc
    return pid


def _managed_openvpn_pid(connection_id: str) -> int | None:
    pid_path = _openvpn_pid_path(connection_id)
    if not pid_path.exists() and not pid_path.is_symlink():
        return None
    try:
        metadata = pid_path.lstat()
        if (
            pid_path.is_symlink()
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_mode & 0o022
            or metadata.st_size <= 0
            or metadata.st_size > 32
        ):
            raise RuntimeError("invalid_openvpn_pid_file")
        raw_pid = pid_path.read_text(encoding="ascii").strip()
        if not raw_pid.isdecimal() or str(int(raw_pid, 10)) != raw_pid:
            raise RuntimeError("invalid_openvpn_pid_file")
        pid = int(raw_pid, 10)
        if pid <= 1:
            raise RuntimeError("invalid_openvpn_pid_file")
        process_directory = PROC_DIRECTORY / str(pid)
        if not process_directory.exists():
            pid_path.unlink(missing_ok=True)
            return None
        executable = (process_directory / "exe").resolve(strict=True)
        allowed_executables = {
            Path(candidate).resolve(strict=True)
            for candidate in OPENVPN_BINARY_CANDIDATES
            if Path(candidate).exists()
        }
        if executable not in allowed_executables:
            raise RuntimeError("unmanaged_openvpn_process")
        raw_command_line = (process_directory / "cmdline").read_bytes()
        if len(raw_command_line) > 64 * 1024:
            raise RuntimeError("unmanaged_openvpn_process")
        arguments = [
            item.decode("utf-8", errors="strict")
            for item in raw_command_line.rstrip(b"\x00").split(b"\x00")
        ]
        if not _has_argument_pair(arguments, "--writepid", str(pid_path)) or not _has_argument_pair(
            arguments, "--daemon", f"vpngate-{connection_id}"
        ) or not _has_argument_pair(
            arguments, "--config", str(_staged_openvpn_config_path(connection_id))
        ):
            raise RuntimeError("unmanaged_openvpn_process")
    except (OSError, UnicodeError, ValueError) as exc:
        raise RuntimeError("invalid_openvpn_pid_file") from exc
    return pid


def _firewall_identity_spec(namespace: str, connection_id: str) -> FirewallRuleSpec:
    identifier = int(connection_id, 10)
    host_address, namespace_address = _firewall_addresses(identifier)
    return FirewallRuleSpec(
        connection_id=identifier,
        namespace=namespace,
        host_veth=host_veth_name(identifier),
        namespace_veth=namespace_veth_name(identifier),
        host_address=host_address,
        namespace_address=namespace_address,
        remote_address="8.8.8.8",
        remote_port=1,
        remote_protocol="udp",
        socks_port=21000,
        client_ip_allowlist=(),
    )


def _cleanup_firewall_backend(
    spec: FirewallRuleSpec,
    backend: str,
    *,
    ip_binary: str,
) -> None:
    if backend == "nftables":
        nft_binary = _find_nft_binary()
        _cleanup_nft_rules(
            spec,
            nft_rule_set(spec),
            ip_binary=ip_binary,
            nft_binary=nft_binary,
        )
        return
    if backend == "iptables":
        iptables_binary = _find_iptables_binary()
        _cleanup_iptables_rules(
            spec,
            iptables_rule_set(spec),
            ip_binary=ip_binary,
            iptables_binary=iptables_binary,
        )
        return
    raise RuntimeError("invalid_firewall_backend")


def _firewall_backend_active(
    spec: FirewallRuleSpec,
    backend: str,
    *,
    ip_binary: str,
) -> bool:
    if backend == "nftables":
        return _nft_rules_active(
            spec,
            ip_binary=ip_binary,
            nft_binary=_find_nft_binary(),
        )
    if backend == "iptables":
        return _iptables_rules_active(
            spec,
            ip_binary=ip_binary,
            iptables_binary=_find_iptables_binary(),
        )
    raise RuntimeError("invalid_firewall_backend")


def _firewall_backend_has_residue(
    spec: FirewallRuleSpec,
    backend: str,
    *,
    ip_binary: str,
) -> bool:
    if backend == "nftables":
        return _nft_rules_present(
            spec,
            ip_binary=ip_binary,
            nft_binary=_find_nft_binary(),
        )
    if backend == "iptables":
        return _iptables_rules_present(
            spec,
            ip_binary=ip_binary,
            iptables_binary=_find_iptables_binary(),
        )
    raise RuntimeError("invalid_firewall_backend")


def _killswitch_active(
    namespace: str,
    connection_id: str,
    *,
    ip_binary: str,
    node_id: str | None = None,
    socks_port: int | None = None,
) -> bool:
    state = _read_firewall_state(connection_id)
    if state is None:
        return False
    if node_id is not None and state.node_id != int(node_id, 10):
        return False
    if socks_port is not None and state.socks_port != socks_port:
        return False
    spec = _firewall_identity_spec(namespace, connection_id)
    return _firewall_backend_active(spec, state.backend, ip_binary=ip_binary)


def _apply_killswitch(command: NetworkCommand, ip_binary: str) -> int:
    namespace, connection_id = command.arguments[:2]
    if not _namespace_exists(namespace):
        print("namespace_not_found", file=sys.stderr)
        return 3
    if not _ip_forward_enabled():
        print("ipv4_forwarding_disabled", file=sys.stderr)
        return 78
    spec = _firewall_spec_from_command(command)
    node_id = command.arguments[2]
    requested_backend = command.arguments[7]
    try:
        _, raw_config = _load_validated_openvpn_config(node_id)
        validated_config = validate_stored_openvpn_config(raw_config)
        if (
            validated_config.remote_ip != spec.remote_address
            or validated_config.remote_port != spec.remote_port
            or validated_config.protocol != spec.remote_protocol
        ):
            raise RuntimeError("firewall_remote_mismatch")
        if spec.socks_port is not None:
            port_range = trusted_socks_port_range()
            if (
                port_range is None
                or spec.socks_port < port_range[0]
                or spec.socks_port > port_range[1]
            ):
                raise RuntimeError("invalid_socks_port_pool")
        if (
            _managed_socks_pid(connection_id) is not None
            or _managed_openvpn_pid(connection_id) is not None
        ):
            raise RuntimeError("firewall_reconfigure_while_process_running")
        previous_state = _read_firewall_state(connection_id)
        if previous_state is not None:
            _cleanup_firewall_backend(
                spec, previous_state.backend, ip_binary=ip_binary
            )
            if _firewall_backend_has_residue(
                spec, previous_state.backend, ip_binary=ip_binary
            ):
                raise RuntimeError("firewall_cleanup_failed")
            _delete_firewall_state(connection_id)
        backend, binary = _select_firewall_backend(requested_backend)
        _write_firewall_state(
            connection_id,
            backend,
            node_id=int(node_id, 10),
            socks_port=spec.socks_port,
        )
        if backend == "nftables":
            returncode = _apply_nft_rules(
                spec, ip_binary=ip_binary, nft_binary=binary
            )
        else:
            returncode = _apply_iptables_rules(
                spec, ip_binary=ip_binary, iptables_binary=binary
            )
        if returncode != 0 or not _firewall_backend_active(
            spec, backend, ip_binary=ip_binary
        ):
            _cleanup_firewall_backend(spec, backend, ip_binary=ip_binary)
            if _firewall_backend_has_residue(
                spec, backend, ip_binary=ip_binary
            ):
                return 126
            _delete_firewall_state(connection_id)
            return returncode if returncode != 0 else 126
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 126
    print(backend)
    return 0


def _killswitch_status(command: NetworkCommand, ip_binary: str) -> int:
    namespace, connection_id = command.arguments
    try:
        state = _read_firewall_state(connection_id)
        if state is None:
            return 3
        spec = _firewall_identity_spec(namespace, connection_id)
        if not _firewall_backend_active(
            spec, state.backend, ip_binary=ip_binary
        ):
            return 3
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 126
    print(state.backend)
    return 0


def _remove_killswitch(command: NetworkCommand, ip_binary: str) -> int:
    namespace, connection_id = command.arguments
    try:
        if _managed_socks_pid(connection_id) is not None:
            raise RuntimeError("socks_process_still_running")
        if _managed_openvpn_pid(connection_id) is not None:
            raise RuntimeError("openvpn_process_still_running")
        state = _read_firewall_state(connection_id)
        if state is None:
            return 0
        spec = _firewall_identity_spec(namespace, connection_id)
        _cleanup_firewall_backend(spec, state.backend, ip_binary=ip_binary)
        if _firewall_backend_has_residue(
            spec, state.backend, ip_binary=ip_binary
        ):
            raise RuntimeError("firewall_cleanup_failed")
        _delete_firewall_state(connection_id)
        return 0
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 126


def _start_openvpn(command: NetworkCommand, ip_binary: str) -> int:
    namespace, connection_id, node_id = command.arguments
    try:
        existing_pid = _managed_openvpn_pid(connection_id)
        if existing_pid is not None:
            print(existing_pid)
            return 0
        openvpn_binary = _find_openvpn_binary()
        _ensure_root_directory(OPENVPN_RUNTIME_DIRECTORY, mode=0o750)
        _ensure_root_directory(OPENVPN_LOG_DIRECTORY, mode=0o750)
        _, raw_config = _load_validated_openvpn_config(node_id)
        config_path = _stage_openvpn_config(connection_id, raw_config)
        pid_path = _openvpn_pid_path(connection_id)
        log_path = _openvpn_log_path(connection_id)
        if pid_path.is_symlink() or log_path.is_symlink():
            raise RuntimeError("unsafe_openvpn_runtime_path")
    except RuntimeError as exc:
        _staged_openvpn_config_path(connection_id).unlink(missing_ok=True)
        print(str(exc), file=sys.stderr)
        return 126

    argv = (
        ip_binary,
        "netns",
        "exec",
        namespace,
        openvpn_binary,
        "--config",
        str(config_path),
        "--writepid",
        str(pid_path),
        "--log-append",
        str(log_path),
        "--daemon",
        f"vpngate-{connection_id}",
        "--script-security",
        "1",
        "--auth-nocache",
        "--persist-key",
        "--persist-tun",
        "--user",
        OPENVPN_SERVICE_ACCOUNT,
        "--group",
        OPENVPN_SERVICE_ACCOUNT,
    )
    previous_umask = os.umask(0o077)
    try:
        completed = subprocess.run(
            argv,
            check=False,
            stdin=subprocess.DEVNULL,
            timeout=HELPER_TIMEOUT_SECONDS,
            close_fds=True,
            env=SAFE_ENVIRONMENT,
        )
    except subprocess.TimeoutExpired:
        _staged_openvpn_config_path(connection_id).unlink(missing_ok=True)
        print("openvpn_start_timeout", file=sys.stderr)
        return 124
    except OSError:
        _staged_openvpn_config_path(connection_id).unlink(missing_ok=True)
        print("openvpn_start_failed", file=sys.stderr)
        return 126
    finally:
        os.umask(previous_umask)
    if completed.returncode != 0:
        _staged_openvpn_config_path(connection_id).unlink(missing_ok=True)
    return completed.returncode


def _openvpn_status(command: NetworkCommand) -> int:
    connection_id = command.arguments[0]
    try:
        pid = _managed_openvpn_pid(connection_id)
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 126
    if pid is None:
        return 3
    print(pid)
    return 0


def _stop_openvpn(command: NetworkCommand) -> int:
    connection_id = command.arguments[0]
    try:
        pid = _managed_openvpn_pid(connection_id)
        if pid is None:
            _staged_openvpn_config_path(connection_id).unlink(missing_ok=True)
            return 0
        os.kill(pid, signal.SIGTERM)
        deadline = time.monotonic() + OPENVPN_STOP_TIMEOUT_SECONDS
        while time.monotonic() < deadline:
            time.sleep(0.1)
            current_pid = _managed_openvpn_pid(connection_id)
            if current_pid is None:
                _staged_openvpn_config_path(connection_id).unlink(missing_ok=True)
                return 0
        current_pid = _managed_openvpn_pid(connection_id)
        if current_pid != pid:
            raise RuntimeError("openvpn_pid_changed")
        os.kill(pid, signal.SIGKILL)
        _openvpn_pid_path(connection_id).unlink(missing_ok=True)
        _staged_openvpn_config_path(connection_id).unlink(missing_ok=True)
        return 0
    except ProcessLookupError:
        _openvpn_pid_path(connection_id).unlink(missing_ok=True)
        _staged_openvpn_config_path(connection_id).unlink(missing_ok=True)
        return 0
    except (OSError, RuntimeError) as exc:
        print(str(exc), file=sys.stderr)
        return 126


def _tun_ready(namespace: str, ip_binary: str) -> int:
    probes = (
        (ip_binary, "-n", namespace, "-o", "link", "show", "dev", "tun0"),
        (ip_binary, "-n", namespace, "route", "show", "default", "dev", "tun0"),
    )
    outputs: list[str] = []
    for argv in probes:
        try:
            completed = subprocess.run(
                argv,
                check=False,
                capture_output=True,
                text=True,
                stdin=subprocess.DEVNULL,
                timeout=HELPER_TIMEOUT_SECONDS,
                close_fds=True,
                env=SAFE_ENVIRONMENT,
            )
        except subprocess.TimeoutExpired:
            return 124
        except OSError:
            return 126
        if completed.returncode != 0:
            return 3
        outputs.append(completed.stdout)
    link_flags = re.search(r"<([^>]*)>", outputs[0])
    if link_flags is None or "UP" not in link_flags.group(1).split(","):
        return 3
    if not any(line.strip().startswith("default") for line in outputs[1].splitlines()):
        return 3
    return 0


def _openvpn_tun_ready(command: NetworkCommand, ip_binary: str) -> int:
    return _tun_ready(command.arguments[0], ip_binary)


def _managed_socks_port(connection_id: str) -> int:
    config_path = _socks_config_path(connection_id)
    try:
        metadata = config_path.lstat()
        if (
            config_path.is_symlink()
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_mode & 0o077
            or metadata.st_size <= 0
            or metadata.st_size > SOCKS_MAX_SPEC_BYTES
        ):
            raise RuntimeError("unsafe_socks_runtime_path")
        content = config_path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise RuntimeError("unsafe_socks_runtime_path") from exc
    matches = re.findall(r"^socks -p([0-9]+) -i0\.0\.0\.0 -e0\.0\.0\.0$", content, re.MULTILINE)
    if len(matches) != 1:
        raise RuntimeError("unsafe_socks_runtime_path")
    port = int(matches[0], 10)
    if not 1024 <= port <= 65535 or str(port) != matches[0]:
        raise RuntimeError("unsafe_socks_runtime_path")
    return port


def _start_socks(command: NetworkCommand, ip_binary: str) -> int:
    namespace, connection_id, endpoint_id = command.arguments
    tun_ready_code = _tun_ready(namespace, ip_binary)
    if tun_ready_code != 0:
        print("socks_tunnel_not_ready", file=sys.stderr)
        return tun_ready_code
    try:
        existing_pid = _managed_socks_pid(connection_id)
        if existing_pid is not None:
            print(existing_pid)
            return 0
        socks_binary = _find_socks_binary()
        _ensure_root_directory(SOCKS_RUNTIME_DIRECTORY, mode=0o750)
        _ensure_root_directory(SOCKS_LOG_DIRECTORY, mode=0o750)
        spec = _load_validated_socks_spec(connection_id, endpoint_id)
        if not _killswitch_active(
            namespace,
            connection_id,
            ip_binary=ip_binary,
            socks_port=spec.port,
        ):
            raise RuntimeError("killswitch_endpoint_mismatch")
        config_path = _stage_socks_config(connection_id, spec)
        _socks_spec_path(endpoint_id).unlink(missing_ok=True)
        pid_path = _socks_pid_path(connection_id)
        log_path = _socks_log_path(connection_id)
        if pid_path.is_symlink() or log_path.is_symlink():
            raise RuntimeError("unsafe_socks_runtime_path")
    except (OSError, RuntimeError) as exc:
        _socks_config_path(connection_id).unlink(missing_ok=True)
        print(str(exc), file=sys.stderr)
        return 126

    argv = (
        ip_binary,
        "netns",
        "exec",
        namespace,
        socks_binary,
        str(config_path),
    )
    log_descriptor = -1
    process: subprocess.Popen[bytes] | None = None
    previous_umask = os.umask(0o077)
    try:
        log_descriptor = os.open(
            log_path,
            os.O_WRONLY
            | os.O_APPEND
            | os.O_CREAT
            | os.O_CLOEXEC
            | os.O_NOFOLLOW,
            0o640,
        )
        os.fchmod(log_descriptor, 0o640)
        with os.fdopen(log_descriptor, "ab", buffering=0) as log_handle:
            log_descriptor = -1
            process = subprocess.Popen(
                argv,
                stdin=subprocess.DEVNULL,
                stdout=log_handle,
                stderr=subprocess.STDOUT,
                close_fds=True,
                start_new_session=True,
                env=SAFE_ENVIRONMENT,
            )
        time.sleep(0.1)
        returncode = process.poll()
        if returncode is not None:
            _socks_config_path(connection_id).unlink(missing_ok=True)
            return returncode if returncode != 0 else 126
        _write_socks_pid(connection_id, process.pid)
        print(process.pid)
        return 0
    except OSError:
        if process is not None and process.poll() is None:
            try:
                os.kill(process.pid, signal.SIGTERM)
            except OSError:
                pass
        _socks_config_path(connection_id).unlink(missing_ok=True)
        _socks_pid_path(connection_id).unlink(missing_ok=True)
        print("socks_start_failed", file=sys.stderr)
        return 126
    except RuntimeError as exc:
        if process is not None and process.poll() is None:
            try:
                os.kill(process.pid, signal.SIGTERM)
            except OSError:
                pass
        _socks_config_path(connection_id).unlink(missing_ok=True)
        _socks_pid_path(connection_id).unlink(missing_ok=True)
        print(str(exc), file=sys.stderr)
        return 126
    finally:
        os.umask(previous_umask)
        if log_descriptor >= 0:
            os.close(log_descriptor)


def _socks_status(command: NetworkCommand) -> int:
    connection_id = command.arguments[0]
    try:
        pid = _managed_socks_pid(connection_id)
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 126
    if pid is None:
        return 3
    print(pid)
    return 0


def _stop_socks(command: NetworkCommand) -> int:
    connection_id = command.arguments[0]
    try:
        pid = _managed_socks_pid(connection_id)
        if pid is None:
            _socks_config_path(connection_id).unlink(missing_ok=True)
            return 0
        os.kill(pid, signal.SIGTERM)
        deadline = time.monotonic() + SOCKS_STOP_TIMEOUT_SECONDS
        while time.monotonic() < deadline:
            time.sleep(0.1)
            current_pid = _managed_socks_pid(connection_id)
            if current_pid is None:
                _socks_config_path(connection_id).unlink(missing_ok=True)
                return 0
        current_pid = _managed_socks_pid(connection_id)
        if current_pid != pid:
            raise RuntimeError("socks_pid_changed")
        os.kill(pid, signal.SIGKILL)
        _socks_pid_path(connection_id).unlink(missing_ok=True)
        _socks_config_path(connection_id).unlink(missing_ok=True)
        return 0
    except ProcessLookupError:
        _socks_pid_path(connection_id).unlink(missing_ok=True)
        _socks_config_path(connection_id).unlink(missing_ok=True)
        return 0
    except (OSError, RuntimeError) as exc:
        print(str(exc), file=sys.stderr)
        return 126


def _socks_ready(command: NetworkCommand, ip_binary: str) -> int:
    namespace, connection_id, port = command.arguments
    try:
        if _managed_socks_pid(connection_id) is None:
            return 3
        if _managed_socks_port(connection_id) != int(port, 10):
            raise RuntimeError("socks_port_mismatch")
        ss_binary = _find_ss_binary()
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 126
    argv = (
        ip_binary,
        "netns",
        "exec",
        namespace,
        ss_binary,
        "-H",
        "-ltn",
        f"sport = :{port}",
    )
    try:
        completed = subprocess.run(
            argv,
            check=False,
            capture_output=True,
            text=True,
            stdin=subprocess.DEVNULL,
            timeout=HELPER_TIMEOUT_SECONDS,
            close_fds=True,
            env=SAFE_ENVIRONMENT,
        )
    except subprocess.TimeoutExpired:
        return 124
    except OSError:
        return 126
    if completed.returncode != 0 or not completed.stdout.strip():
        return 3
    return 0


def _run_namespace_curl(
    ip_binary: str,
    namespace: str,
    curl_binary: str,
    arguments: tuple[str, ...],
) -> tuple[int, str]:
    argv = (
        ip_binary,
        "netns",
        "exec",
        namespace,
        curl_binary,
        "--silent",
        "--show-error",
        "--fail",
        "--connect-timeout",
        "8",
        "--max-time",
        "15",
        "--proto",
        "=https",
        "--proto-redir",
        "=https",
        "--tlsv1.2",
        *arguments,
    )
    try:
        completed = subprocess.run(
            argv,
            check=False,
            capture_output=True,
            text=True,
            stdin=subprocess.DEVNULL,
            timeout=HELPER_TIMEOUT_SECONDS,
            close_fds=True,
            env=SAFE_ENVIRONMENT,
        )
    except subprocess.TimeoutExpired:
        return 124, ""
    except OSError:
        return 126, ""
    if len(completed.stdout.encode("utf-8", errors="replace")) > 4096:
        return 126, ""
    return completed.returncode, completed.stdout.strip()


def _run_unlock_http(
    ip_binary: str,
    namespace: str,
    curl_binary: str,
    url: str,
    *,
    extra_arguments: tuple[str, ...] = (),
) -> _UnlockHTTPResult:
    marker = "\n__VPNGATE_UNLOCK_HTTP__"
    argv = (
        ip_binary,
        "netns",
        "exec",
        namespace,
        curl_binary,
        "--silent",
        "--show-error",
        "--location",
        "--max-redirs",
        "3",
        "--connect-timeout",
        "4",
        "--max-time",
        "8",
        "--proto",
        "=https",
        "--tlsv1.2",
        "--compressed",
        "--max-filesize",
        "524288",
        "--header",
        "Accept-Language: en-US,en;q=0.8",
        "--user-agent",
        "VPNGate-Multi-Exit-Manager/0.1",
        "--write-out",
        f"{marker}%{{http_code}}|%{{time_total}}",
        *extra_arguments,
        url,
    )
    try:
        completed = subprocess.run(
            argv,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            stdin=subprocess.DEVNULL,
            timeout=HELPER_TIMEOUT_SECONDS,
            close_fds=True,
            env=SAFE_ENVIRONMENT,
        )
    except subprocess.TimeoutExpired:
        return _UnlockHTTPResult(28, None, None, "")
    except OSError:
        return _UnlockHTTPResult(126, None, None, "")
    stdout = completed.stdout
    if len(stdout.encode("utf-8", errors="replace")) > 540_000:
        return _UnlockHTTPResult(126, None, None, "")
    body, separator, metadata = stdout.rpartition(marker)
    http_status: int | None = None
    latency_ms: float | None = None
    if separator:
        status_text, delimiter, time_text = metadata.partition("|")
        try:
            parsed_status = int(status_text, 10)
            parsed_latency = float(time_text) * 1000 if delimiter else -1
        except ValueError:
            parsed_status = 0
            parsed_latency = -1
        if 100 <= parsed_status <= 599:
            http_status = parsed_status
        if 0 <= parsed_latency <= 60_000:
            latency_ms = round(parsed_latency, 3)
    return _UnlockHTTPResult(
        0 if completed.returncode == 63 and http_status is not None else completed.returncode,
        http_status,
        latency_ms,
        body,
    )


def _network_failure(
    service_name: str,
    result: _UnlockHTTPResult,
) -> tuple[str, str] | None:
    if result.returncode == 0:
        return None
    if result.returncode == 28:
        return "TIMEOUT", "timeout"
    if result.returncode == 6:
        return (
            ("UNKNOWN", "dns_failed")
            if service_name == "netflix"
            else ("DNS_FAILED", "dns_failed")
        )
    if result.returncode in {35, 51, 58, 60}:
        return (
            ("UNKNOWN", "tls_failed")
            if service_name == "netflix"
            else ("TLS_FAILED", "tls_failed")
        )
    return "UNKNOWN", "probe_failed"


def _body_available(result: _UnlockHTTPResult) -> bool:
    if result.http_status != 200:
        return False
    lowered = result.body.lower()
    unavailable_markers = (
        "not available in your country",
        "not available in your region",
        "page not found",
        "sorry, we can't find that page",
    )
    return not any(marker in lowered for marker in unavailable_markers)


def _unlock_payload(
    *,
    service_name: str,
    status: str,
    region: str | None,
    latency_ms: float | None,
    failure_reason: str | None,
    http_status: int | None,
    secondary_http_status: int | None = None,
    static_ok: bool | None = None,
    websocket_ok: bool | None = None,
) -> dict[str, object]:
    return {
        "failure_reason": failure_reason,
        "http_status": http_status,
        "latency_ms": latency_ms,
        "region": region,
        "secondary_http_status": secondary_http_status,
        "service_name": service_name,
        "static_ok": static_ok,
        "status": status,
        "websocket_ok": websocket_ok,
    }


def _check_netflix(
    ip_binary: str,
    namespace: str,
    curl_binary: str,
) -> dict[str, object]:
    original = _run_unlock_http(
        ip_binary, namespace, curl_binary, NETFLIX_ORIGINAL_URL
    )
    original_failure = _network_failure("netflix", original)
    if original_failure is not None:
        failure_status, failure_reason = original_failure
        return _unlock_payload(
            service_name="netflix",
            status=failure_status,
            region=None,
            latency_ms=original.latency_ms,
            failure_reason=failure_reason,
            http_status=original.http_status,
        )
    catalog = _run_unlock_http(
        ip_binary, namespace, curl_binary, NETFLIX_CATALOG_URL
    )
    catalog_failure = _network_failure("netflix", catalog)
    latency_values = [
        value
        for value in (original.latency_ms, catalog.latency_ms)
        if value is not None
    ]
    latency = round(sum(latency_values), 3) if latency_values else None
    classification_reason: str | None
    if _body_available(catalog):
        status = "FULL"
        classification_reason = None
    elif _body_available(original):
        status = "ORIGINALS_ONLY"
        classification_reason = None if catalog_failure is None else catalog_failure[1]
    elif original.http_status in {403, 451} and catalog.http_status in {403, 451}:
        status = "BLOCKED"
        classification_reason = "http_blocked"
    elif original.http_status is not None or catalog.http_status is not None:
        status = "REACHABLE"
        classification_reason = None if catalog_failure is None else catalog_failure[1]
    else:
        status = "UNKNOWN"
        classification_reason = "probe_failed"
    return _unlock_payload(
        service_name="netflix",
        status=status,
        region=None,
        latency_ms=latency,
        failure_reason=classification_reason,
        http_status=original.http_status,
        secondary_http_status=catalog.http_status,
    )


def _region_from_body(body: str) -> str | None:
    for pattern in (
        r'"GL"\s*:\s*"([A-Z]{2})"',
        r'"countryCode"\s*:\s*"([A-Z]{2})"',
        r'"country"\s*:\s*"([A-Z]{2})"',
    ):
        matched = re.search(pattern, body)
        if matched is not None:
            return matched.group(1)
    return None


def _check_single_service(
    ip_binary: str,
    namespace: str,
    curl_binary: str,
    service_name: str,
) -> dict[str, object]:
    if service_name == "chatgpt":
        return _check_chatgpt(ip_binary, namespace, curl_binary)
    urls = {
        "openai_api": OPENAI_API_URL,
        "youtube": YOUTUBE_URL,
    }
    result = _run_unlock_http(
        ip_binary,
        namespace,
        curl_binary,
        urls[service_name],
    )
    failure = _network_failure(service_name, result)
    if failure is not None:
        failure_status, failure_reason = failure
        return _unlock_payload(
            service_name=service_name,
            status=failure_status,
            region=None,
            latency_ms=result.latency_ms,
            failure_reason=failure_reason,
            http_status=result.http_status,
        )

    http_status = result.http_status
    region = _region_from_body(result.body)
    classification_reason: str | None = None
    if service_name == "openai_api":
        if http_status in {200, 401}:
            status = "REACHABLE"
        elif http_status in {403, 451}:
            status = "HTTP_BLOCKED"
            classification_reason = "http_blocked"
        else:
            status = "UNKNOWN"
    else:
        if http_status == 200 and region is not None:
            status = "REGION_DETECTED"
        elif http_status == 200:
            status = "REACHABLE"
        elif http_status in {403, 451}:
            status = "BLOCKED"
            classification_reason = "http_blocked"
        else:
            status = "UNKNOWN"
    return _unlock_payload(
        service_name=service_name,
        status=status,
        region=region,
        latency_ms=result.latency_ms,
        failure_reason=classification_reason,
        http_status=http_status,
    )


def _check_chatgpt(
    ip_binary: str,
    namespace: str,
    curl_binary: str,
) -> dict[str, object]:
    result = _run_unlock_http(ip_binary, namespace, curl_binary, CHATGPT_URL)
    failure = _network_failure("chatgpt", result)
    if failure is not None:
        failure_status, failure_reason = failure
        return _unlock_payload(
            service_name="chatgpt",
            status=failure_status,
            region=None,
            latency_ms=result.latency_ms,
            failure_reason=failure_reason,
            http_status=result.http_status,
        )

    static_result = _run_unlock_http(
        ip_binary,
        namespace,
        curl_binary,
        CHATGPT_STATIC_URL,
    )
    websocket_result = _run_unlock_http(
        ip_binary,
        namespace,
        curl_binary,
        CHATGPT_URL,
        extra_arguments=(
            "--http1.1",
            "--header",
            "Connection: Upgrade",
            "--header",
            "Upgrade: websocket",
            "--header",
            "Sec-WebSocket-Version: 13",
            "--header",
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==",
        ),
    )
    http_status = result.http_status
    lowered = result.body.lower()
    region = _region_from_body(result.body)
    classification_reason: str | None = None
    if any(
        marker in lowered
        for marker in (
            "unsupported_country",
            "unsupported country",
            "not available in your country",
        )
    ):
        status = "UNSUPPORTED_REGION"
    elif http_status == 200:
        status = "UNLOCKED"
    elif http_status is not None and 300 <= http_status < 400:
        status = "PARTIAL"
    elif http_status == 403 and any(
        marker in lowered for marker in ("cf-chl", "challenge", "captcha")
    ):
        status = "CHALLENGE"
    elif http_status in {403, 451}:
        status = "HTTP_BLOCKED"
        classification_reason = "http_blocked"
    else:
        status = "UNKNOWN"
    latency_values = [
        value
        for value in (
            result.latency_ms,
            static_result.latency_ms,
            websocket_result.latency_ms,
        )
        if value is not None
    ]
    return _unlock_payload(
        service_name="chatgpt",
        status=status,
        region=region,
        latency_ms=round(sum(latency_values), 3) if latency_values else None,
        failure_reason=classification_reason,
        http_status=http_status,
        secondary_http_status=static_result.http_status,
        static_ok=(
            static_result.returncode == 0 and static_result.http_status == 200
        ),
        websocket_ok=(
            websocket_result.returncode == 0 and websocket_result.http_status == 101
        ),
    )


def _probe_namespace_unlock(command: NetworkCommand, ip_binary: str) -> int:
    namespace, connection_id, service_name = command.arguments
    try:
        if not _killswitch_active(
            namespace,
            connection_id,
            ip_binary=ip_binary,
        ):
            return 3
        tun_ready_code = _tun_ready(namespace, ip_binary)
        if tun_ready_code != 0:
            return tun_ready_code
        curl_binary = _find_curl_binary()
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 126
    payload = (
        _check_netflix(ip_binary, namespace, curl_binary)
        if service_name == "netflix"
        else _check_single_service(
            ip_binary,
            namespace,
            curl_binary,
            service_name,
        )
    )
    print(json.dumps(payload, sort_keys=True, separators=(",", ":")))
    return 0


def _probe_namespace_exit(command: NetworkCommand, ip_binary: str) -> int:
    namespace, connection_id = command.arguments
    try:
        if not _killswitch_active(
            namespace,
            connection_id,
            ip_binary=ip_binary,
        ):
            return 3
        tun_ready_code = _tun_ready(namespace, ip_binary)
        if tun_ready_code != 0:
            return tun_ready_code
        curl_binary = _find_curl_binary()
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 126

    started = time.monotonic()
    exit_code, exit_output = _run_namespace_curl(
        ip_binary,
        namespace,
        curl_binary,
        (
            "--header",
            "Accept: application/json",
            "--max-filesize",
            "1024",
            EXIT_IP_URL,
        ),
    )
    if exit_code != 0:
        return exit_code
    latency_ms = (time.monotonic() - started) * 1000
    try:
        exit_payload = json.loads(exit_output)
        if not isinstance(exit_payload, dict) or set(exit_payload) != {"ip"}:
            raise ValueError("invalid_exit_response")
        raw_address = exit_payload.get("ip")
        if not isinstance(raw_address, str):
            raise ValueError("invalid_exit_response")
        address = ipaddress.ip_address(raw_address)
        if not address.is_global or str(address) != raw_address:
            raise ValueError("invalid_exit_response")
    except (json.JSONDecodeError, ValueError):
        print("invalid_exit_response", file=sys.stderr)
        return 126

    speed_code, speed_output = _run_namespace_curl(
        ip_binary,
        namespace,
        curl_binary,
        (
            "--output",
            "/dev/null",
            "--write-out",
            "%{speed_download}",
            "--max-filesize",
            "262144",
            SPEED_PROBE_URL,
        ),
    )
    if speed_code != 0:
        return speed_code
    try:
        bytes_per_second = float(speed_output)
        if not 0 <= bytes_per_second <= 12_500_000_000:
            raise ValueError("invalid_speed_response")
    except ValueError:
        print("invalid_speed_response", file=sys.stderr)
        return 126
    print(
        json.dumps(
            {
                "dns_ok": True,
                "download_bps": round(bytes_per_second * 8),
                "exit_ip": str(address),
                "https_ok": True,
                "latency_ms": round(latency_ms, 3),
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


def _purge_connection(command: NetworkCommand) -> int:
    """Remove only resources derived from one validated managed connection ID."""
    connection_id = command.arguments[0]
    identifier = int(connection_id, 10)
    namespace = namespace_name(identifier)
    host_veth = host_veth_name(identifier)
    socks_code = _stop_socks(
        NetworkCommand(NetworkOperation.SOCKS5_STOP, (connection_id,))
    )
    if socks_code != 0:
        return socks_code
    openvpn_code = _stop_openvpn(
        NetworkCommand(NetworkOperation.OPENVPN_STOP, (connection_id,))
    )
    if openvpn_code != 0:
        return openvpn_code
    try:
        ip_binary = _find_ip_binary()
        spec = _firewall_identity_spec(namespace, connection_id)
        state = _read_firewall_state(connection_id)
        backends = (
            (state.backend,)
            if state is not None
            else ("nftables", "iptables")
        )
        for backend in backends:
            try:
                _cleanup_firewall_backend(spec, backend, ip_binary=ip_binary)
            except RuntimeError as exc:
                if str(exc) in {"nft_binary_not_found", "iptables_binary_not_found"}:
                    if state is not None:
                        raise RuntimeError("firewall_binary_not_found") from exc
                    continue
                raise
            if _firewall_backend_has_residue(
                spec,
                backend,
                ip_binary=ip_binary,
            ):
                raise RuntimeError("firewall_cleanup_failed")
        _delete_firewall_state(connection_id)
        dns_code = _delete_namespace_dns(
            NetworkCommand(NetworkOperation.NAMESPACE_DNS_DELETE, (namespace,))
        )
        if dns_code != 0:
            return dns_code
        if _namespace_exists(namespace):
            namespace_argv = build_ip_argv(
                NetworkCommand(NetworkOperation.NAMESPACE_DELETE, (namespace,)),
                ip_binary=ip_binary,
            )
            if namespace_argv is None or _run_quiet(namespace_argv) != 0:
                raise RuntimeError("namespace_cleanup_failed")
        veth_exists = _host_veth_exists(ip_binary, host_veth)
        if veth_exists is None:
            raise RuntimeError("veth_probe_failed")
        if veth_exists:
            veth_argv = build_ip_argv(
                NetworkCommand(NetworkOperation.VETH_DELETE, (host_veth,)),
                ip_binary=ip_binary,
            )
            if veth_argv is None or _run_quiet(veth_argv) != 0:
                raise RuntimeError("veth_cleanup_failed")
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 126
    return 0


def execute(command: NetworkCommand) -> int:
    if command.operation is NetworkOperation.SELF_TEST:
        print("root-helper-ok")
        return 0
    if command.operation is NetworkOperation.CONNECTION_PURGE:
        return _purge_connection(command)
    if not real_network_enabled():
        print("real_network_disabled", file=sys.stderr)
        return 78
    openvpn_operations = {
        NetworkOperation.OPENVPN_START,
        NetworkOperation.OPENVPN_STOP,
        NetworkOperation.OPENVPN_STATUS,
        NetworkOperation.OPENVPN_TUN_READY,
    }
    socks_operations = {
        NetworkOperation.SOCKS5_START,
        NetworkOperation.SOCKS5_STOP,
        NetworkOperation.SOCKS5_STATUS,
        NetworkOperation.SOCKS5_READY,
    }
    firewall_operations = {
        NetworkOperation.KILLSWITCH_APPLY,
        NetworkOperation.KILLSWITCH_REMOVE,
        NetworkOperation.KILLSWITCH_STATUS,
    }
    full_scan_operations = {NetworkOperation.NODE_EXIT_PROBE}
    unlock_operations = {NetworkOperation.SERVICE_UNLOCK_PROBE}
    if command.operation in openvpn_operations and not real_openvpn_enabled():
        print("real_openvpn_disabled", file=sys.stderr)
        return 78
    if command.operation in socks_operations and not real_socks5_enabled():
        print("real_socks5_disabled", file=sys.stderr)
        return 78
    if command.operation in firewall_operations and not real_firewall_enabled():
        print("real_firewall_disabled", file=sys.stderr)
        return 78
    if command.operation in full_scan_operations and not real_full_scans_enabled():
        print("real_full_scans_disabled", file=sys.stderr)
        return 78
    if command.operation in unlock_operations and not real_unlock_checks_enabled():
        print("real_unlock_checks_disabled", file=sys.stderr)
        return 78
    if command.operation is NetworkOperation.OPENVPN_STATUS:
        return _openvpn_status(command)
    if command.operation is NetworkOperation.OPENVPN_STOP:
        return _stop_openvpn(command)
    if command.operation is NetworkOperation.SOCKS5_STATUS:
        return _socks_status(command)
    if command.operation is NetworkOperation.SOCKS5_STOP:
        return _stop_socks(command)
    if command.operation is NetworkOperation.NAMESPACE_DNS_WRITE:
        return _write_namespace_dns(command)
    if command.operation is NetworkOperation.NAMESPACE_DNS_DELETE:
        return _delete_namespace_dns(command)
    if (
        command.operation is NetworkOperation.NAMESPACE_DELETE
        and not _namespace_exists(command.arguments[0])
    ):
        return 0
    try:
        ip_binary = _find_ip_binary()
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 126
    if command.operation is NetworkOperation.KILLSWITCH_APPLY:
        return _apply_killswitch(command, ip_binary)
    if command.operation is NetworkOperation.KILLSWITCH_STATUS:
        return _killswitch_status(command, ip_binary)
    if command.operation is NetworkOperation.KILLSWITCH_REMOVE:
        return _remove_killswitch(command, ip_binary)
    if command.operation is NetworkOperation.NODE_EXIT_PROBE:
        return _probe_namespace_exit(command, ip_binary)
    if command.operation is NetworkOperation.SERVICE_UNLOCK_PROBE:
        return _probe_namespace_unlock(command, ip_binary)
    if command.operation in {
        NetworkOperation.OPENVPN_START,
        NetworkOperation.SOCKS5_START,
    }:
        namespace = command.arguments[0]
        connection_id = command.arguments[1]
        try:
            protected = _killswitch_active(
                namespace,
                connection_id,
                ip_binary=ip_binary,
                node_id=(
                    command.arguments[2]
                    if command.operation is NetworkOperation.OPENVPN_START
                    else None
                ),
            )
        except RuntimeError as exc:
            print(str(exc), file=sys.stderr)
            return 126
        if not protected:
            print("killswitch_not_active", file=sys.stderr)
            return 3
    if command.operation is NetworkOperation.OPENVPN_START:
        return _start_openvpn(command, ip_binary)
    if command.operation is NetworkOperation.OPENVPN_TUN_READY:
        return _openvpn_tun_ready(command, ip_binary)
    if command.operation is NetworkOperation.SOCKS5_START:
        return _start_socks(command, ip_binary)
    if command.operation is NetworkOperation.SOCKS5_READY:
        return _socks_ready(command, ip_binary)
    if command.operation is NetworkOperation.VETH_DELETE:
        veth_exists = _host_veth_exists(ip_binary, command.arguments[0])
        if veth_exists is False:
            return 0
        if veth_exists is None:
            print("veth_probe_failed", file=sys.stderr)
            return 126
    argv = build_ip_argv(command, ip_binary=ip_binary)
    if argv is None:
        return 0
    try:
        completed = subprocess.run(
            argv,
            check=False,
            stdin=subprocess.DEVNULL,
            timeout=HELPER_TIMEOUT_SECONDS,
            close_fds=True,
            env=SAFE_ENVIRONMENT,
        )
    except subprocess.TimeoutExpired:
        print("operation_timeout", file=sys.stderr)
        return 124
    except OSError:
        print("operation_start_failed", file=sys.stderr)
        return 126
    return completed.returncode


def main() -> None:
    if os.geteuid() != 0:
        print("root_privileges_required", file=sys.stderr)
        raise SystemExit(77)
    try:
        command = parse_command(sys.argv[1:])
    except CommandValidationError as exc:
        print(exc.code, file=sys.stderr)
        raise SystemExit(64) from exc
    raise SystemExit(execute(command))


if __name__ == "__main__":
    main()
