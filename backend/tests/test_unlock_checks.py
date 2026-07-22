import asyncio
import json

import pytest

from app.services.network import MockNetworkExecutor
from app.services.unlock import (
    ALL_UNLOCK_SERVICES,
    MockUnlockProbe,
    UnlockCheckCoordinator,
    UnlockServiceName,
    build_unlock_probe,
    parse_unlock_probe_response,
)


def test_mock_unlock_checks_are_explicit_and_network_free() -> None:
    probe = MockUnlockProbe()
    executor = MockNetworkExecutor()

    results = [probe.check(4, service) for service in ALL_UNLOCK_SERVICES]

    assert all(result.status == "UNKNOWN" for result in results)
    assert all(result.simulated is True for result in results)
    assert executor.commands == []


def test_coordinator_runs_selected_services_in_stable_order() -> None:
    coordinator = UnlockCheckCoordinator(MockUnlockProbe())

    results = asyncio.run(
        coordinator.check(
            3,
            (UnlockServiceName.YOUTUBE, UnlockServiceName.NETFLIX),
        )
    )

    assert [result.service_name for result in results] == [
        UnlockServiceName.YOUTUBE,
        UnlockServiceName.NETFLIX,
    ]


def test_namespace_probe_parser_accepts_only_bounded_canonical_result() -> None:
    output = json.dumps(
        {
            "failure_reason": None,
            "http_status": 401,
            "latency_ms": 12.5,
            "region": None,
            "secondary_http_status": None,
            "service_name": "openai_api",
            "static_ok": None,
            "status": "REACHABLE",
            "websocket_ok": None,
        }
    )

    result = parse_unlock_probe_response(
        output,
        expected_service=UnlockServiceName.OPENAI_API,
    )

    assert result.status == "REACHABLE"
    assert result.details == {"http_status": 401}
    assert result.simulated is False


@pytest.mark.parametrize(
    "payload",
    [
        "not-json",
        json.dumps({"service_name": "netflix"}),
        json.dumps(
            {
                "failure_reason": None,
                "http_status": 200,
                "latency_ms": 1,
                "region": None,
                "secondary_http_status": None,
                "service_name": "chatgpt",
                "static_ok": None,
                "status": "FULL",
                "websocket_ok": None,
            }
        ),
        json.dumps(
            {
                "failure_reason": None,
                "http_status": 200,
                "latency_ms": 1,
                "region": None,
                "secondary_http_status": None,
                "service_name": "youtube",
                "static_ok": None,
                "status": "REACHABLE",
                "websocket_ok": None,
            }
        ),
    ],
)
def test_namespace_probe_parser_rejects_mismatched_or_invalid_output(
    payload: str,
) -> None:
    with pytest.raises(ValueError):
        parse_unlock_probe_response(
            payload,
            expected_service=UnlockServiceName.CHATGPT,
        )


def test_real_unlock_builder_requires_exact_environment_gate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("VPNGATE_ENABLE_REAL_UNLOCK_CHECKS", raising=False)
    with pytest.raises(RuntimeError):
        build_unlock_probe(
            MockNetworkExecutor(),
            enable_real_unlock_checks=True,
            timeout_seconds=30,
        )


def test_disabled_unlock_builder_always_returns_mock(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("VPNGATE_ENABLE_REAL_UNLOCK_CHECKS", "true")
    probe = build_unlock_probe(
        MockNetworkExecutor(),
        enable_real_unlock_checks=False,
        timeout_seconds=30,
    )
    assert isinstance(probe, MockUnlockProbe)
