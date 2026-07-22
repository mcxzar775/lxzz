import hashlib
import ipaddress
import re
import shlex
from collections.abc import Callable

from app.services.vpngate.types import OpenVPNConfigError, SanitizedOpenVPNConfig


MAX_CONFIG_BYTES = 512 * 1024
MAX_LINE_LENGTH = 4096
MAX_INLINE_BLOCK_BYTES = 384 * 1024

DANGEROUS_DIRECTIVES = frozenset(
    {
        "up",
        "down",
        "route-up",
        "ipchange",
        "client-connect",
        "client-disconnect",
        "learn-address",
        "plugin",
        "script-security",
        "auth-user-pass-verify",
        "tls-verify",
    }
)
INLINE_BLOCKS = frozenset({"ca", "cert", "key", "tls-auth", "tls-crypt"})
SAFE_TOKEN = re.compile(r"^[A-Za-z0-9_.:+-]{1,128}$")


def _require_args(args: list[str], expected: int) -> None:
    if len(args) != expected:
        raise OpenVPNConfigError("invalid_directive_arguments")


def _zero_args(args: list[str]) -> list[str]:
    _require_args(args, 0)
    return []


def _safe_token_args(args: list[str]) -> list[str]:
    _require_args(args, 1)
    if not SAFE_TOKEN.fullmatch(args[0]) or any(
        item.lower() in {"none", "null"} for item in args[0].split(":")
    ):
        raise OpenVPNConfigError("invalid_directive_arguments")
    return args


def _bounded_integer(value: str, minimum: int, maximum: int) -> str:
    try:
        number = int(value, 10)
    except ValueError as exc:
        raise OpenVPNConfigError("invalid_directive_arguments") from exc
    if number < minimum or number > maximum:
        raise OpenVPNConfigError("invalid_directive_arguments")
    return str(number)


def _one_integer(args: list[str], minimum: int, maximum: int) -> list[str]:
    _require_args(args, 1)
    return [_bounded_integer(args[0], minimum, maximum)]


def _validate_dev(args: list[str]) -> list[str]:
    _require_args(args, 1)
    if args[0].lower() != "tun":
        raise OpenVPNConfigError("unsupported_device")
    return ["tun"]


def _protocol_family(value: str) -> str:
    protocol = value.lower()
    if protocol in {"udp", "udp4", "udp6"}:
        return "udp"
    if protocol in {"tcp", "tcp4", "tcp6", "tcp-client"}:
        return "tcp"
    raise OpenVPNConfigError("unsupported_protocol")


def _validate_proto(args: list[str]) -> list[str]:
    _require_args(args, 1)
    _protocol_family(args[0])
    return [args[0].lower()]


def _validate_resolv_retry(args: list[str]) -> list[str]:
    _require_args(args, 1)
    if args[0].lower() == "infinite":
        return ["infinite"]
    return [_bounded_integer(args[0], 1, 3600)]


def _validate_remote_cert_tls(args: list[str]) -> list[str]:
    _require_args(args, 1)
    if args[0].lower() != "server":
        raise OpenVPNConfigError("invalid_directive_arguments")
    return ["server"]


def _validate_connect_retry(args: list[str]) -> list[str]:
    if len(args) not in {1, 2}:
        raise OpenVPNConfigError("invalid_directive_arguments")
    normalized = [_bounded_integer(args[0], 1, 3600)]
    if len(args) == 2:
        normalized.append(_bounded_integer(args[1], 1, 3600))
    return normalized


def _validate_key_direction(args: list[str]) -> list[str]:
    _require_args(args, 1)
    if args[0] not in {"0", "1"}:
        raise OpenVPNConfigError("invalid_directive_arguments")
    return args


def _validate_comp_lzo(args: list[str]) -> list[str]:
    _require_args(args, 1)
    if args[0].lower() != "no":
        raise OpenVPNConfigError("compression_not_allowed")
    return ["no"]


def _validate_compress(args: list[str]) -> list[str]:
    _require_args(args, 1)
    if args[0].lower() != "stub-v2":
        raise OpenVPNConfigError("compression_not_allowed")
    return ["stub-v2"]


def _validate_setenv(args: list[str]) -> list[str]:
    if [item.lower() for item in args] != ["opt", "block-outside-dns"]:
        raise OpenVPNConfigError("invalid_directive_arguments")
    return ["opt", "block-outside-dns"]


def _validate_auth_retry(args: list[str]) -> list[str]:
    _require_args(args, 1)
    if args[0].lower() != "nointeract":
        raise OpenVPNConfigError("invalid_directive_arguments")
    return ["nointeract"]


DirectiveValidator = Callable[[list[str]], list[str]]

DIRECTIVE_VALIDATORS: dict[str, DirectiveValidator] = {
    "client": _zero_args,
    "dev": _validate_dev,
    "proto": _validate_proto,
    "resolv-retry": _validate_resolv_retry,
    "nobind": _zero_args,
    "persist-key": _zero_args,
    "persist-tun": _zero_args,
    "remote-cert-tls": _validate_remote_cert_tls,
    "cipher": _safe_token_args,
    "data-ciphers": _safe_token_args,
    "data-ciphers-fallback": _safe_token_args,
    "auth": _safe_token_args,
    "auth-nocache": _zero_args,
    "verb": lambda args: _one_integer(args, 0, 4),
    "mute": lambda args: _one_integer(args, 0, 100),
    "connect-retry": _validate_connect_retry,
    "connect-timeout": lambda args: _one_integer(args, 1, 300),
    "ping": lambda args: _one_integer(args, 1, 3600),
    "ping-restart": lambda args: _one_integer(args, 1, 3600),
    "reneg-sec": lambda args: _one_integer(args, 0, 86400),
    "key-direction": _validate_key_direction,
    "comp-lzo": _validate_comp_lzo,
    "compress": _validate_compress,
    "setenv": _validate_setenv,
    "tls-client": _zero_args,
    "remote-random": _zero_args,
    "explicit-exit-notify": lambda args: _one_integer(args, 0, 5),
    "sndbuf": lambda args: _one_integer(args, 0, 16 * 1024 * 1024),
    "rcvbuf": lambda args: _one_integer(args, 0, 16 * 1024 * 1024),
    "fast-io": _zero_args,
    "auth-retry": _validate_auth_retry,
}


def _parse_remote(args: list[str], expected_ip: str) -> tuple[list[str], int, str | None]:
    if len(args) not in {2, 3}:
        raise OpenVPNConfigError("invalid_remote")
    try:
        remote_ip = ipaddress.ip_address(args[0])
        expected = ipaddress.ip_address(expected_ip)
    except ValueError as exc:
        raise OpenVPNConfigError("invalid_remote") from exc
    if not remote_ip.is_global or remote_ip != expected:
        raise OpenVPNConfigError("remote_address_mismatch")
    port = int(_bounded_integer(args[1], 1, 65535))
    normalized = [str(remote_ip), str(port)]
    remote_protocol: str | None = None
    if len(args) == 3:
        remote_protocol = _protocol_family(args[2])
        normalized.append(args[2].lower())
    return normalized, port, remote_protocol


def sanitize_openvpn_config(
    raw_config: bytes,
    *,
    expected_ip: str,
) -> SanitizedOpenVPNConfig:
    if not raw_config or len(raw_config) > MAX_CONFIG_BYTES or b"\x00" in raw_config:
        raise OpenVPNConfigError("invalid_config_size")
    try:
        text = raw_config.decode("utf-8-sig", errors="strict")
    except UnicodeDecodeError as exc:
        raise OpenVPNConfigError("invalid_config_encoding") from exc

    output: list[str] = []
    seen_directives: set[str] = set()
    inline_block: str | None = None
    inline_bytes = 0
    remote_port: int | None = None
    remote_protocol: str | None = None
    protocol: str | None = None

    for raw_line in text.splitlines():
        if len(raw_line) > MAX_LINE_LENGTH:
            raise OpenVPNConfigError("config_line_too_long")
        line = raw_line.strip()

        if inline_block is not None:
            if line.lower() == f"</{inline_block}>":
                output.append(f"</{inline_block}>")
                inline_block = None
                continue
            if line.startswith("<") and line.endswith(">"):
                raise OpenVPNConfigError("invalid_inline_block")
            inline_bytes += len(raw_line.encode("utf-8")) + 1
            if inline_bytes > MAX_INLINE_BLOCK_BYTES:
                raise OpenVPNConfigError("inline_block_too_large")
            output.append(raw_line.rstrip())
            continue

        if not line or line.startswith(("#", ";")):
            continue
        inline_match = re.fullmatch(r"<([A-Za-z0-9-]+)>", line)
        if inline_match:
            tag = inline_match.group(1).lower()
            if tag not in INLINE_BLOCKS or tag in seen_directives:
                raise OpenVPNConfigError("invalid_inline_block")
            seen_directives.add(tag)
            inline_block = tag
            inline_bytes = 0
            output.append(f"<{tag}>")
            continue

        try:
            tokens = shlex.split(line, comments=False, posix=True)
        except ValueError as exc:
            raise OpenVPNConfigError("invalid_directive_syntax") from exc
        if not tokens:
            continue
        directive = tokens[0].lstrip("-").lower()
        args = tokens[1:]
        if directive in DANGEROUS_DIRECTIVES:
            raise OpenVPNConfigError("dangerous_directive")
        if tokens[0].startswith("-") or (
            directive != "remote" and directive not in DIRECTIVE_VALIDATORS
        ):
            raise OpenVPNConfigError("unsupported_directive")
        if directive in seen_directives:
            raise OpenVPNConfigError("duplicate_directive")
        seen_directives.add(directive)

        if directive == "remote":
            normalized_args, remote_port, remote_protocol = _parse_remote(args, expected_ip)
        else:
            normalized_args = DIRECTIVE_VALIDATORS[directive](args)
            if directive == "proto":
                protocol = _protocol_family(normalized_args[0])
        output.append(" ".join([directive, *normalized_args]))

    if inline_block is not None:
        raise OpenVPNConfigError("unclosed_inline_block")
    if remote_port is None:
        raise OpenVPNConfigError("missing_remote")
    if protocol is None:
        raise OpenVPNConfigError("missing_protocol")
    if remote_protocol is not None and remote_protocol != protocol:
        raise OpenVPNConfigError("protocol_mismatch")
    if "client" not in seen_directives or "dev" not in seen_directives or "ca" not in seen_directives:
        raise OpenVPNConfigError("missing_required_directive")

    canonical = "\n".join(output) + "\n"
    config_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return SanitizedOpenVPNConfig(
        text=canonical,
        config_hash=config_hash,
        remote_ip=expected_ip,
        remote_port=remote_port,
        protocol=protocol,
    )


def validate_stored_openvpn_config(raw_config: bytes) -> SanitizedOpenVPNConfig:
    """Re-validate a canonical stored config before privileged execution."""
    if not raw_config or len(raw_config) > MAX_CONFIG_BYTES or b"\x00" in raw_config:
        raise OpenVPNConfigError("invalid_config_size")
    try:
        text = raw_config.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise OpenVPNConfigError("invalid_config_encoding") from exc

    inline_block: str | None = None
    remote_ip: str | None = None
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if inline_block is not None:
            if line.lower() == f"</{inline_block}>":
                inline_block = None
            continue
        inline_match = re.fullmatch(r"<([A-Za-z0-9-]+)>", line)
        if inline_match:
            inline_block = inline_match.group(1).lower()
            continue
        if not line or line.startswith(("#", ";")):
            continue
        try:
            tokens = shlex.split(line, comments=False, posix=True)
        except ValueError as exc:
            raise OpenVPNConfigError("invalid_directive_syntax") from exc
        if tokens and tokens[0].lower() == "remote" and len(tokens) >= 2:
            if remote_ip is not None:
                raise OpenVPNConfigError("duplicate_directive")
            remote_ip = tokens[1]
    if remote_ip is None:
        raise OpenVPNConfigError("missing_remote")

    sanitized = sanitize_openvpn_config(raw_config, expected_ip=remote_ip)
    if sanitized.text.encode("utf-8") != raw_config:
        raise OpenVPNConfigError("stored_config_not_canonical")
    return sanitized
