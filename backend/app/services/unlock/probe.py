import json
import os
from typing import Any

from app.services.network.commands import (
    MAX_NAMESPACE_RESOURCES,
    NetworkCommand,
    NetworkOperation,
    namespace_name,
)
from app.services.network.executor import NetworkExecutor, RealNetworkExecutor
from app.services.unlock.types import (
    ALLOWED_STATUSES,
    UnlockCheckResult,
    UnlockServiceName,
)


class MockUnlockProbe:
    """Deterministic probe that never opens a socket or changes host networking."""

    def check(
        self,
        connection_id: int,
        service_name: UnlockServiceName,
    ) -> UnlockCheckResult:
        if (
            isinstance(connection_id, bool)
            or not 1 <= connection_id <= MAX_NAMESPACE_RESOURCES
        ):
            raise ValueError("invalid_unlock_connection")
        return UnlockCheckResult(
            service_name=service_name,
            status="UNKNOWN",
            details={"mode": "simulation"},
            simulated=True,
        )


def _optional_text(value: object, *, limit: int) -> str | None:
    if value is None:
        return None
    if (
        not isinstance(value, str)
        or not value
        or len(value) > limit
        or not value.isascii()
    ):
        raise ValueError("invalid_unlock_probe_response")
    return value


def _optional_number(value: object, *, maximum: float) -> float | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("invalid_unlock_probe_response")
    parsed = float(value)
    if not 0 <= parsed <= maximum:
        raise ValueError("invalid_unlock_probe_response")
    return parsed


def _optional_bool(value: object) -> bool | None:
    if value is None or isinstance(value, bool):
        return value
    raise ValueError("invalid_unlock_probe_response")


def parse_unlock_probe_response(
    output: str,
    *,
    expected_service: UnlockServiceName,
) -> UnlockCheckResult:
    if not output or len(output.encode("utf-8")) > 4096:
        raise ValueError("invalid_unlock_probe_response")
    try:
        payload = json.loads(output)
    except json.JSONDecodeError as exc:
        raise ValueError("invalid_unlock_probe_response") from exc
    expected_keys = {
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
    if not isinstance(payload, dict) or set(payload) != expected_keys:
        raise ValueError("invalid_unlock_probe_response")
    data: dict[str, Any] = {str(key): value for key, value in payload.items()}
    if data["service_name"] != expected_service.value:
        raise ValueError("invalid_unlock_probe_response")
    status = _optional_text(data["status"], limit=64)
    if status is None or status not in ALLOWED_STATUSES[expected_service]:
        raise ValueError("invalid_unlock_probe_response")
    region = _optional_text(data["region"], limit=2)
    if region is not None and (len(region) != 2 or region != region.upper()):
        raise ValueError("invalid_unlock_probe_response")
    failure_reason = _optional_text(data["failure_reason"], limit=128)
    latency = _optional_number(data["latency_ms"], maximum=60_000)
    http_status = _optional_number(data["http_status"], maximum=599)
    secondary_status = _optional_number(
        data["secondary_http_status"], maximum=599
    )
    static_ok = _optional_bool(data["static_ok"])
    websocket_ok = _optional_bool(data["websocket_ok"])
    details: dict[str, Any] = {}
    if http_status is not None:
        details["http_status"] = int(http_status)
    if secondary_status is not None:
        details["secondary_http_status"] = int(secondary_status)
    if static_ok is not None:
        details["static_ok"] = static_ok
    if websocket_ok is not None:
        details["websocket_ok"] = websocket_ok
    return UnlockCheckResult(
        service_name=expected_service,
        status=status,
        region=region,
        latency_ms=latency,
        failure_reason=failure_reason,
        details=details,
        simulated=False,
    )


def _unknown_result(
    service_name: UnlockServiceName,
    reason: str,
) -> UnlockCheckResult:
    return UnlockCheckResult(
        service_name=service_name,
        status="UNKNOWN",
        failure_reason=reason,
        simulated=False,
    )


class NamespaceUnlockProbe:
    def __init__(
        self,
        executor: NetworkExecutor,
        *,
        allow_real_unlock_checks: bool,
        timeout_seconds: float = 30.0,
    ) -> None:
        if not allow_real_unlock_checks:
            raise ValueError("real_unlock_checks_not_allowed")
        if not 5 <= timeout_seconds <= 60:
            raise ValueError("invalid_unlock_timeout")
        if not isinstance(executor, RealNetworkExecutor):
            raise ValueError("real_unlock_checks_require_real_executor")
        self._executor = executor
        self._timeout_seconds = timeout_seconds

    def check(
        self,
        connection_id: int,
        service_name: UnlockServiceName,
    ) -> UnlockCheckResult:
        try:
            command = NetworkCommand(
                NetworkOperation.SERVICE_UNLOCK_PROBE,
                (
                    namespace_name(connection_id),
                    str(connection_id),
                    service_name.value,
                ),
            )
            result = self._executor.run(
                command,
                timeout_seconds=self._timeout_seconds,
            )
        except Exception:
            return _unknown_result(service_name, "unlock_probe_failed")
        if result.returncode != 0:
            return _unknown_result(service_name, "unlock_probe_failed")
        try:
            return parse_unlock_probe_response(
                result.stdout.strip(),
                expected_service=service_name,
            )
        except ValueError:
            return _unknown_result(service_name, "invalid_unlock_probe_response")


def build_unlock_probe(
    executor: NetworkExecutor,
    *,
    enable_real_unlock_checks: bool,
    timeout_seconds: float,
) -> MockUnlockProbe | NamespaceUnlockProbe:
    if not enable_real_unlock_checks:
        return MockUnlockProbe()
    if os.getenv("VPNGATE_ENABLE_REAL_UNLOCK_CHECKS") != "true":
        raise RuntimeError(
            "real unlock checks require VPNGATE_ENABLE_REAL_UNLOCK_CHECKS=true"
        )
    return NamespaceUnlockProbe(
        executor,
        allow_real_unlock_checks=True,
        timeout_seconds=timeout_seconds,
    )
