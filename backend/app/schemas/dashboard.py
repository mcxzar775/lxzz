from pydantic import BaseModel


class DashboardCounts(BaseModel):
    total_nodes: int
    available_nodes: int
    online_vpns: int
    online_socks: int
    anomalies: int
    residential_likely: int
    netflix_full: int
    chatgpt_available: int


class SystemMetrics(BaseModel):
    cpu_percent: float
    memory_percent: float
    disk_percent: float
    network_bytes_sent: int
    network_bytes_received: int


class DashboardResponse(BaseModel):
    counts: DashboardCounts
    system: SystemMetrics
    network_executor: str

