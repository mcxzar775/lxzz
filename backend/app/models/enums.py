from enum import Enum


class UserRole(str, Enum):
    SUPER_ADMIN = "SUPER_ADMIN"
    ADMIN = "ADMIN"
    VIEWER = "VIEWER"


class ConnectionStatus(str, Enum):
    PENDING = "PENDING"
    STARTING = "STARTING"
    RUNNING = "RUNNING"
    STOPPING = "STOPPING"
    STOPPED = "STOPPED"
    FAILED = "FAILED"


class ScanStatus(str, Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    TIMEOUT = "TIMEOUT"


class NetworkType(str, Enum):
    RESIDENTIAL_LIKELY = "RESIDENTIAL_LIKELY"
    DATACENTER = "DATACENTER"
    MOBILE = "MOBILE"
    BUSINESS_ISP = "BUSINESS_ISP"
    PUBLIC_VPN = "PUBLIC_VPN"
    PROXY = "PROXY"
    UNKNOWN = "UNKNOWN"


class TaskStatus(str, Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
