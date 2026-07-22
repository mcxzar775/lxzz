import base64
import binascii
import csv
import io
import ipaddress
import re
from collections import Counter

from app.services.vpngate.openvpn import MAX_CONFIG_BYTES, sanitize_openvpn_config
from app.services.vpngate.types import (
    OpenVPNConfigError,
    ParsedVPNGateNode,
    ParseReport,
    VPNGateFeedError,
)


REQUIRED_COLUMNS = frozenset(
    {
        "HostName",
        "IP",
        "Score",
        "Ping",
        "Speed",
        "CountryLong",
        "CountryShort",
        "NumVpnSessions",
        "Uptime",
        "TotalUsers",
        "TotalTraffic",
        "OpenVPN_ConfigData_Base64",
    }
)
COUNTRY_CODE = re.compile(r"^[A-Z]{2}$")


def _clean_text(value: str | None, *, maximum: int) -> str | None:
    if value is None:
        return None
    cleaned = value.strip()
    if not cleaned:
        return None
    if len(cleaned) > maximum or any(ord(char) < 32 for char in cleaned):
        raise VPNGateFeedError("invalid_text_field")
    return cleaned


def _optional_nonnegative_integer(value: str | None) -> int | None:
    if value is None or value.strip() in {"", "-"}:
        return None
    try:
        number = int(value.strip(), 10)
    except ValueError as exc:
        raise VPNGateFeedError("invalid_numeric_field") from exc
    if number < 0:
        raise VPNGateFeedError("invalid_numeric_field")
    return number


def _decode_config(encoded: str | None) -> bytes:
    if encoded is None:
        raise VPNGateFeedError("missing_config")
    compact = encoded.strip()
    if not compact or len(compact) > (MAX_CONFIG_BYTES * 4 // 3) + 16:
        raise VPNGateFeedError("invalid_config_size")
    try:
        decoded = base64.b64decode(compact, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise VPNGateFeedError("invalid_config_base64") from exc
    if not decoded or len(decoded) > MAX_CONFIG_BYTES:
        raise VPNGateFeedError("invalid_config_size")
    return decoded


def _parse_row(row: dict[str, str | None]) -> ParsedVPNGateNode:
    raw_ip = (row.get("IP") or "").strip()
    try:
        address = ipaddress.ip_address(raw_ip)
    except ValueError as exc:
        raise VPNGateFeedError("invalid_ip_address") from exc
    if not address.is_global:
        raise VPNGateFeedError("non_public_ip_address")
    ip_address = str(address)

    country_code = _clean_text(row.get("CountryShort"), maximum=8)
    if country_code is not None:
        country_code = country_code.upper()
        if not COUNTRY_CODE.fullmatch(country_code):
            raise VPNGateFeedError("invalid_country_code")

    raw_config = _decode_config(row.get("OpenVPN_ConfigData_Base64"))
    try:
        config = sanitize_openvpn_config(raw_config, expected_ip=ip_address)
    except OpenVPNConfigError:
        raise

    uptime_milliseconds = _optional_nonnegative_integer(row.get("Uptime"))
    uptime_seconds = (
        uptime_milliseconds // 1000 if uptime_milliseconds is not None else None
    )
    return ParsedVPNGateNode(
        config_hash=config.config_hash,
        host_name=_clean_text(row.get("HostName"), maximum=255),
        ip_address=ip_address,
        score=_optional_nonnegative_integer(row.get("Score")),
        ping_ms=_optional_nonnegative_integer(row.get("Ping")),
        speed_bps=_optional_nonnegative_integer(row.get("Speed")),
        country_long=_clean_text(row.get("CountryLong"), maximum=128),
        country_code=country_code,
        sessions=_optional_nonnegative_integer(row.get("NumVpnSessions")),
        uptime_seconds=uptime_seconds,
        total_users=_optional_nonnegative_integer(row.get("TotalUsers")),
        total_traffic_bytes=_optional_nonnegative_integer(row.get("TotalTraffic")),
        protocol=config.protocol,
        remote_port=config.remote_port,
        sanitized_config=config.text,
    )


def parse_vpngate_csv(payload: bytes, *, max_rows: int = 20_000) -> ParseReport:
    if not payload:
        raise VPNGateFeedError("empty_response")
    try:
        decoded = payload.decode("utf-8-sig", errors="strict")
    except UnicodeDecodeError as exc:
        raise VPNGateFeedError("invalid_csv_encoding") from exc

    lines = decoded.splitlines()
    header_index: int | None = None
    header_text = ""
    for index, line in enumerate(lines):
        candidate = line.strip()
        if candidate.startswith("#HostName,"):
            header_index = index
            header_text = candidate[1:]
            break
    if header_index is None:
        raise VPNGateFeedError("missing_csv_header")

    data_lines = [header_text]
    for line in lines[header_index + 1 :]:
        candidate = line.strip()
        if not candidate or candidate.startswith(("#", "*")):
            continue
        data_lines.append(line)
        if len(data_lines) - 1 > max_rows:
            raise VPNGateFeedError("row_limit_exceeded")

    reader = csv.DictReader(io.StringIO("\n".join(data_lines)), strict=True)
    fieldnames = set(reader.fieldnames or [])
    if not REQUIRED_COLUMNS.issubset(fieldnames):
        raise VPNGateFeedError("missing_required_columns")

    nodes: list[ParsedVPNGateNode] = []
    seen_hashes: set[str] = set()
    rejected = 0
    duplicates = 0
    rejection_reasons: Counter[str] = Counter()
    try:
        for row in reader:
            if None in row:
                rejected += 1
                rejection_reasons["invalid_csv_row"] += 1
                continue
            try:
                node = _parse_row(row)
            except (VPNGateFeedError, OpenVPNConfigError) as exc:
                rejected += 1
                rejection_reasons[exc.code] += 1
                continue
            if node.config_hash in seen_hashes:
                duplicates += 1
                continue
            seen_hashes.add(node.config_hash)
            nodes.append(node)
    except csv.Error as exc:
        raise VPNGateFeedError("invalid_csv_syntax") from exc

    if not nodes:
        raise VPNGateFeedError("no_valid_nodes")
    return ParseReport(
        nodes=nodes,
        rejected_rows=rejected,
        duplicate_rows=duplicates,
        rejection_reasons=dict(sorted(rejection_reasons.items())),
    )
