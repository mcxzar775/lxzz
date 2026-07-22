from functools import lru_cache
import ipaddress
from typing import Literal

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="VPNGATE_",
        case_sensitive=False,
        extra="ignore",
    )

    app_name: str = "VPNGate Multi-Exit Manager"
    environment: Literal["development", "test", "production"] = "development"
    api_prefix: str = "/api/v1"
    database_url: str = "sqlite:///./data/vpngate.db"

    session_cookie_name: str = "vpngate_session"
    csrf_cookie_name: str = "vpngate_csrf"
    cookie_secure: bool = False
    session_minutes: int = Field(default=720, ge=5, le=1440)
    remember_session_days: int = Field(default=30, ge=1, le=90)
    login_max_attempts: int = Field(default=5, ge=2, le=20)
    login_lock_minutes: int = Field(default=15, ge=1, le=1440)

    vpngate_api_url: str = "https://www.vpngate.net/api/iphone/"
    vpngate_request_timeout_seconds: float = Field(default=30.0, ge=1.0, le=120.0)
    vpngate_max_response_bytes: int = Field(
        default=10 * 1024 * 1024, ge=1024, le=50 * 1024 * 1024
    )
    vpngate_max_rows: int = Field(default=20_000, ge=1, le=100_000)
    openvpn_config_directory: str = "./data/openvpn-configs"
    socks_config_directory: str = "./data/socks-configs"
    credential_encryption_key_file: str = "./data/credential.key"

    enable_real_network: bool = False
    enable_real_openvpn: bool = False
    enable_real_socks5: bool = False
    enable_real_firewall: bool = False
    enable_real_scans: bool = False
    enable_real_full_scans: bool = False
    enable_real_ip_intelligence: bool = False
    enable_real_unlock_checks: bool = False
    enable_real_connections: bool = False
    enable_auto_switch: bool = False
    enable_real_auto_switch: bool = False
    firewall_backend: Literal["auto", "nftables", "iptables"] = "auto"
    sudo_path: str = "/usr/bin/sudo"
    root_helper_path: str = "/usr/local/libexec/vpngate-manager-helper"
    namespace_dns_servers: tuple[str, ...] = ("1.1.1.1", "8.8.8.8")
    openvpn_tun_timeout_seconds: float = Field(default=30.0, ge=5.0, le=120.0)
    socks_port_start: int = Field(default=21000, ge=1024, le=65535)
    socks_port_end: int = Field(default=21999, ge=1024, le=65535)
    socks_ready_timeout_seconds: float = Field(default=15.0, ge=5.0, le=120.0)
    scan_concurrency: int = Field(default=3, ge=1, le=10)
    scan_connect_timeout_seconds: float = Field(default=15.0, ge=1.0, le=60.0)
    scan_total_timeout_seconds: float = Field(default=30.0, ge=2.0, le=120.0)
    full_scan_timeout_seconds: float = Field(default=90.0, ge=10.0, le=300.0)
    ipinfo_api_token: SecretStr | None = None
    ip_intelligence_timeout_seconds: float = Field(default=10.0, ge=1.0, le=30.0)
    ip_intelligence_max_response_bytes: int = Field(
        default=64 * 1024, ge=1024, le=1024 * 1024
    )
    unlock_check_timeout_seconds: float = Field(default=30.0, ge=5.0, le=60.0)
    health_check_interval_seconds: float = Field(default=60.0, ge=10.0, le=3600.0)
    health_failure_threshold: int = Field(default=3, ge=1, le=20)
    auto_switch_max_per_hour: int = Field(default=5, ge=1, le=20)
    auto_switch_max_latency_ms: float | None = Field(default=None, ge=1, le=120_000)
    auto_switch_min_download_bps: int | None = Field(
        default=None,
        ge=0,
        le=100_000_000_000,
    )
    auto_switch_allowed_network_types: str = ""
    auto_switch_required_services: str = ""

    @model_validator(mode="after")
    def require_secure_production_cookie(self) -> "Settings":
        if self.environment == "production" and not self.cookie_secure:
            raise ValueError("VPNGATE_COOKIE_SECURE must be true in production")
        if not self.vpngate_api_url.startswith("https://"):
            raise ValueError("VPNGATE_VPNGATE_API_URL must use HTTPS")
        if not self.sudo_path.startswith("/") or not self.root_helper_path.startswith("/"):
            raise ValueError("network helper executable paths must be absolute")
        if not 1 <= len(self.namespace_dns_servers) <= 3:
            raise ValueError("VPNGATE_NAMESPACE_DNS_SERVERS requires one to three addresses")
        normalized_dns: list[str] = []
        for value in self.namespace_dns_servers:
            try:
                address = ipaddress.ip_address(value)
            except ValueError as exc:
                raise ValueError("namespace DNS servers must be IP addresses") from exc
            if not address.is_global or str(address) != value:
                raise ValueError("namespace DNS servers must be canonical public IP addresses")
            normalized_dns.append(value)
        if len(set(normalized_dns)) != len(normalized_dns):
            raise ValueError("namespace DNS servers must be unique")
        if self.enable_real_openvpn and not self.enable_real_network:
            raise ValueError(
                "VPNGATE_ENABLE_REAL_OPENVPN requires VPNGATE_ENABLE_REAL_NETWORK=true"
            )
        if self.enable_real_socks5 and not self.enable_real_openvpn:
            raise ValueError(
                "VPNGATE_ENABLE_REAL_SOCKS5 requires VPNGATE_ENABLE_REAL_OPENVPN=true"
            )
        if self.enable_real_firewall and not self.enable_real_network:
            raise ValueError(
                "VPNGATE_ENABLE_REAL_FIREWALL requires VPNGATE_ENABLE_REAL_NETWORK=true"
            )
        if self.enable_real_openvpn and not self.enable_real_firewall:
            raise ValueError(
                "VPNGATE_ENABLE_REAL_OPENVPN requires VPNGATE_ENABLE_REAL_FIREWALL=true"
            )
        if self.enable_real_full_scans and not (
            self.enable_real_network
            and self.enable_real_firewall
            and self.enable_real_openvpn
        ):
            raise ValueError(
                "VPNGATE_ENABLE_REAL_FULL_SCANS requires real network, firewall, and OpenVPN"
            )
        if self.enable_real_ip_intelligence and (
            self.ipinfo_api_token is None
            or not self.ipinfo_api_token.get_secret_value()
        ):
            raise ValueError(
                "VPNGATE_ENABLE_REAL_IP_INTELLIGENCE requires VPNGATE_IPINFO_API_TOKEN"
            )
        if self.enable_real_unlock_checks and not (
            self.enable_real_network
            and self.enable_real_firewall
            and self.enable_real_openvpn
        ):
            raise ValueError(
                "VPNGATE_ENABLE_REAL_UNLOCK_CHECKS requires real network, firewall, and OpenVPN"
            )
        if self.enable_real_auto_switch and not (
            self.enable_real_network
            and self.enable_real_firewall
            and self.enable_real_openvpn
            and self.enable_real_socks5
            and self.enable_real_full_scans
            and self.enable_real_unlock_checks
        ):
            raise ValueError(
                "VPNGATE_ENABLE_REAL_AUTO_SWITCH requires real network, firewall, "
                "OpenVPN, SOCKS5, full scans, and unlock checks"
            )
        if self.enable_real_connections and not (
            self.enable_real_network
            and self.enable_real_firewall
            and self.enable_real_openvpn
            and self.enable_real_socks5
            and self.enable_real_full_scans
        ):
            raise ValueError(
                "VPNGATE_ENABLE_REAL_CONNECTIONS requires real network, firewall, "
                "OpenVPN, SOCKS5, and full scans"
            )
        allowed_network_types = [
            item.strip()
            for item in self.auto_switch_allowed_network_types.split(",")
            if item.strip()
        ]
        valid_network_types = {
            "RESIDENTIAL_LIKELY",
            "DATACENTER",
            "MOBILE",
            "BUSINESS_ISP",
            "PUBLIC_VPN",
            "PROXY",
            "UNKNOWN",
        }
        if (
            len(set(allowed_network_types)) != len(allowed_network_types)
            or any(item not in valid_network_types for item in allowed_network_types)
        ):
            raise ValueError("VPNGATE_AUTO_SWITCH_ALLOWED_NETWORK_TYPES is invalid")
        required_services = [
            item.strip()
            for item in self.auto_switch_required_services.split(",")
            if item.strip()
        ]
        if (
            len(set(required_services)) != len(required_services)
            or any(
                item not in {"netflix", "chatgpt", "openai_api", "youtube"}
                for item in required_services
            )
        ):
            raise ValueError("VPNGATE_AUTO_SWITCH_REQUIRED_SERVICES is invalid")
        if self.scan_total_timeout_seconds < self.scan_connect_timeout_seconds:
            raise ValueError(
                "VPNGATE_SCAN_TOTAL_TIMEOUT_SECONDS must not be below connect timeout"
            )
        if self.socks_port_end < self.socks_port_start:
            raise ValueError("VPNGATE_SOCKS_PORT_END must not be below port start")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
