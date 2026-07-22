import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import RequestResponseEndpoint
from starlette.responses import Response

from app import __version__
from app.api.routes import api_router
from app.core.config import Settings, get_settings
from app.core.logging import configure_logging
from app.db.session import create_database_engine, create_session_factory
from app.models.enums import NetworkType
from app.services.admin_settings import apply_stored_runtime_settings
from app.services.auto_switch import (
    ConnectionHealthMonitor,
    ConnectionSwitchService,
    HealthPolicy,
    build_connection_runtime_driver,
)
from app.services.connections import (
    ConnectionLifecycleService,
    build_connection_lifecycle_driver,
    recover_interrupted_connections,
)
from app.services.network import build_network_executor
from app.services.ip_intelligence import build_ip_intelligence_service
from app.services.network.killswitch import KillSwitchManager
from app.services.network.namespace import NamespaceManager
from app.services.network.openvpn_manager import OpenVPNManager
from app.services.network.socks5 import (
    CredentialCipher,
    SecureSocksSpecStore,
    Socks5Manager,
    SocksEndpointService,
)
from app.services.scanning import (
    FullScanRunner,
    IsolatedFullScanRunner,
    NamespaceExitProbe,
    NodeScanCoordinator,
    SimulatedFullScanRunner,
    build_fast_scan_transport,
)
from app.services.unlock import (
    UnlockCheckCoordinator,
    UnlockServiceName,
    build_unlock_probe,
)
from app.services.vpngate.client import VPNGateClient
from app.services.vpngate.storage import SecureConfigStore


def create_app(settings: Settings | None = None) -> FastAPI:
    active_settings = settings or get_settings()
    engine = create_database_engine(active_settings.database_url)
    active_settings = apply_stored_runtime_settings(active_settings, engine)
    health_monitor: ConnectionHealthMonitor | None = None

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        stop_event: asyncio.Event | None = None
        monitor_task: asyncio.Task[None] | None = None
        await asyncio.to_thread(
            recover_interrupted_connections,
            session_factory,
            network_executor,
            enable_real_connections=active_settings.enable_real_connections,
        )
        if active_settings.enable_auto_switch and health_monitor is not None:
            stop_event = asyncio.Event()
            monitor_task = asyncio.create_task(health_monitor.run(stop_event))
        try:
            yield
        finally:
            if stop_event is not None:
                stop_event.set()
            if monitor_task is not None:
                await monitor_task
            engine.dispose()

    configure_logging()
    application = FastAPI(
        title=active_settings.app_name,
        version=__version__,
        docs_url="/api/docs" if active_settings.environment != "production" else None,
        redoc_url=None,
        lifespan=lifespan,
    )
    application.state.settings = active_settings
    application.state.engine = engine
    session_factory = create_session_factory(engine)
    application.state.session_factory = session_factory
    network_executor = build_network_executor(
        enable_real_network=active_settings.enable_real_network,
        sudo_path=active_settings.sudo_path,
        helper_path=active_settings.root_helper_path,
    )
    application.state.network_executor = network_executor
    namespace_manager = NamespaceManager(network_executor)
    application.state.namespace_manager = namespace_manager
    killswitch_manager = KillSwitchManager(
        network_executor,
        allow_real_firewall=active_settings.enable_real_firewall,
        default_backend=active_settings.firewall_backend,
    )
    application.state.killswitch_manager = killswitch_manager
    config_store = SecureConfigStore(active_settings.openvpn_config_directory)
    application.state.openvpn_config_store = config_store
    openvpn_manager = OpenVPNManager(
        network_executor,
        config_store,
        allow_real_openvpn=active_settings.enable_real_openvpn,
        tun_timeout_seconds=active_settings.openvpn_tun_timeout_seconds,
    )
    application.state.openvpn_manager = openvpn_manager
    credential_cipher = CredentialCipher.load_or_create(
        active_settings.credential_encryption_key_file
    )
    application.state.credential_cipher = credential_cipher
    socks_spec_store = SecureSocksSpecStore(active_settings.socks_config_directory)
    socks_spec_store.cleanup_stale()
    application.state.socks_spec_store = socks_spec_store
    socks_manager = Socks5Manager(
        network_executor,
        socks_spec_store,
        allow_real_socks5=active_settings.enable_real_socks5,
        ready_timeout_seconds=active_settings.socks_ready_timeout_seconds,
    )
    application.state.socks_manager = socks_manager
    application.state.socks_endpoint_service = SocksEndpointService(
        credential_cipher,
        socks_manager,
        port_start=active_settings.socks_port_start,
        port_end=active_settings.socks_port_end,
    )
    application.state.ip_intelligence_service = build_ip_intelligence_service(
        enable_real_ip_intelligence=active_settings.enable_real_ip_intelligence,
        api_token=active_settings.ipinfo_api_token,
        timeout_seconds=active_settings.ip_intelligence_timeout_seconds,
        max_response_bytes=active_settings.ip_intelligence_max_response_bytes,
    )
    unlock_probe = build_unlock_probe(
        network_executor,
        enable_real_unlock_checks=active_settings.enable_real_unlock_checks,
        timeout_seconds=active_settings.unlock_check_timeout_seconds,
    )
    application.state.unlock_probe = unlock_probe
    unlock_coordinator = UnlockCheckCoordinator(unlock_probe)
    application.state.unlock_check_coordinator = unlock_coordinator
    exit_probe = NamespaceExitProbe(
        network_executor,
        allow_real_full_scans=active_settings.enable_real_full_scans,
    )
    application.state.exit_probe = exit_probe
    auto_switch_policy = HealthPolicy(
        max_latency_ms=active_settings.auto_switch_max_latency_ms,
        min_download_bps=active_settings.auto_switch_min_download_bps,
        allowed_network_types=frozenset(
            NetworkType(value.strip())
            for value in active_settings.auto_switch_allowed_network_types.split(",")
            if value.strip()
        ),
        required_services=tuple(
            UnlockServiceName(value.strip())
            for value in active_settings.auto_switch_required_services.split(",")
            if value.strip()
        ),
    )
    application.state.auto_switch_policy = auto_switch_policy
    connection_runtime_driver = build_connection_runtime_driver(
        network_executor,
        enable_real_auto_switch=active_settings.enable_real_auto_switch,
        killswitch_manager=killswitch_manager,
        openvpn_manager=openvpn_manager,
        socks_service=application.state.socks_endpoint_service,
        exit_probe=exit_probe,
        intelligence_service=application.state.ip_intelligence_service,
        unlock_coordinator=unlock_coordinator,
    )
    application.state.connection_runtime_driver = connection_runtime_driver
    connection_switch_service = ConnectionSwitchService(
        connection_runtime_driver,
        failure_threshold=active_settings.health_failure_threshold,
        max_auto_switches_per_hour=active_settings.auto_switch_max_per_hour,
    )
    application.state.connection_switch_service = connection_switch_service
    health_monitor = ConnectionHealthMonitor(
        session_factory,
        connection_switch_service,
        auto_switch_policy,
        interval_seconds=active_settings.health_check_interval_seconds,
    )
    application.state.connection_health_monitor = health_monitor
    connection_lifecycle_driver = build_connection_lifecycle_driver(
        network_executor,
        enable_real_connections=active_settings.enable_real_connections,
        namespace_manager=namespace_manager,
        killswitch_manager=killswitch_manager,
        openvpn_manager=openvpn_manager,
        socks_service=application.state.socks_endpoint_service,
        exit_probe=exit_probe,
        intelligence_service=application.state.ip_intelligence_service,
        dns_servers=active_settings.namespace_dns_servers,
    )
    application.state.connection_lifecycle_driver = connection_lifecycle_driver
    application.state.connection_lifecycle_service = ConnectionLifecycleService(
        connection_lifecycle_driver
    )
    fast_scan_transport = build_fast_scan_transport(
        enable_real_scans=active_settings.enable_real_scans,
        connect_timeout_seconds=active_settings.scan_connect_timeout_seconds,
        total_timeout_seconds=active_settings.scan_total_timeout_seconds,
    )
    if active_settings.enable_real_full_scans:
        full_scan_runner: FullScanRunner = IsolatedFullScanRunner(
            namespace_manager,
            killswitch_manager,
            openvpn_manager,
            exit_probe,
            dns_servers=active_settings.namespace_dns_servers,
            unlock_probe=unlock_probe,
        )
    else:
        full_scan_runner = SimulatedFullScanRunner()
    application.state.node_scan_coordinator = NodeScanCoordinator(
        fast_scan_transport,
        full_scan_runner,
        concurrency=active_settings.scan_concurrency,
        fast_timeout_seconds=active_settings.scan_total_timeout_seconds,
        full_timeout_seconds=active_settings.full_scan_timeout_seconds,
    )
    application.state.vpngate_fetcher = VPNGateClient(
        url=active_settings.vpngate_api_url,
        timeout_seconds=active_settings.vpngate_request_timeout_seconds,
        max_response_bytes=active_settings.vpngate_max_response_bytes,
    )

    @application.middleware("http")
    async def security_headers(
        request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "same-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        return response

    @application.get("/healthz", include_in_schema=False)
    def health() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    application.include_router(api_router, prefix=active_settings.api_prefix)

    frontend_dist = Path(__file__).resolve().parents[2] / "frontend" / "dist"
    if frontend_dist.is_dir():
        assets = frontend_dist / "assets"
        if assets.is_dir():
            application.mount("/assets", StaticFiles(directory=assets), name="assets")

        @application.get("/{path:path}", include_in_schema=False)
        def spa(path: str) -> FileResponse:
            requested = (frontend_dist / path).resolve()
            if requested.is_file() and frontend_dist.resolve() in requested.parents:
                return FileResponse(requested)
            return FileResponse(frontend_dist / "index.html")

    return application


app = create_app()
