export type UserRole = 'SUPER_ADMIN' | 'ADMIN' | 'VIEWER'

export interface User {
  id: number
  username: string
  role: UserRole
  is_active: boolean
  totp_enabled: boolean
  created_at: string
  last_login_at: string | null
}

export interface AuthResponse {
  user: User
  permissions: string[]
}

export interface DashboardCounts {
  total_nodes: number
  available_nodes: number
  online_vpns: number
  online_socks: number
  anomalies: number
  residential_likely: number
  netflix_full: number
  chatgpt_available: number
}

export interface SystemMetrics {
  cpu_percent: number
  memory_percent: number
  disk_percent: number
  network_bytes_sent: number
  network_bytes_received: number
}

export interface DashboardResponse {
  counts: DashboardCounts
  system: SystemMetrics
  network_executor: string
}

export type NetworkType =
  | 'RESIDENTIAL_LIKELY'
  | 'DATACENTER'
  | 'MOBILE'
  | 'BUSINESS_ISP'
  | 'PUBLIC_VPN'
  | 'PROXY'
  | 'UNKNOWN'

export interface VPNGateNode {
  id: number
  config_hash: string
  host_name: string | null
  ip_address: string
  score: number | null
  ping_ms: number | null
  speed_bps: number | null
  country_long: string | null
  country_code: string | null
  protocol: 'udp' | 'tcp'
  remote_port: number
  is_available: boolean
  is_blocked: boolean
  asn: number | null
  asn_organization: string | null
  isp: string | null
  ptr: string | null
  classified_exit_ip: string | null
  exit_country_code: string | null
  exit_country_name: string | null
  exit_city: string | null
  intelligence_source: string | null
  intelligence_checked_at: string | null
  network_classification_reasons: string[]
  network_type: NetworkType
  network_confidence: number | null
  last_seen_at: string
  last_success_at: string | null
}

export interface NodeListResponse {
  items: VPNGateNode[]
  total: number
  limit: number
  offset: number
}

export interface NodeRefreshResponse {
  fetched_bytes: number
  valid_nodes: number
  inserted: number
  updated: number
  rejected_rows: number
  duplicate_rows: number
  rejection_reasons: Record<string, number>
}

export interface NodeScanResponse {
  id: number
  node_id: number
  scan_type: 'fast' | 'full'
  status: 'RUNNING' | 'SUCCEEDED' | 'FAILED' | 'TIMEOUT'
  latency_ms: number | null
  exit_ip: string | null
  error_code: string | null
  details: Record<string, unknown>
  simulated: boolean
  created_at: string
  completed_at: string | null
}

export interface NodeBlockResponse {
  node_id: number
  blocked: boolean
  reason: string | null
}

export type ConnectionStatus =
  | 'PENDING'
  | 'STARTING'
  | 'RUNNING'
  | 'STOPPING'
  | 'STOPPED'
  | 'FAILED'

export type UnlockServiceName = 'netflix' | 'chatgpt' | 'openai_api' | 'youtube'

export interface VPNConnection {
  id: number
  name: string
  node_id: number | null
  node_ip: string | null
  node_country_code: string | null
  node_speed_bps: number | null
  namespace: string
  tun_device: string
  status: ConnectionStatus
  exit_ip: string | null
  started_at: string | null
  stopped_at: string | null
  last_health_at: string | null
  consecutive_failures: number
  auto_switch_count: number
  last_error: string | null
  socks_port: number | null
  socks_username: string | null
  socks_active: boolean
  socks_bytes_up: number
  socks_bytes_down: number
  created_at: string
  updated_at: string
}

export interface ConnectionListResponse {
  items: VPNConnection[]
  total: number
  limit: number
  offset: number
}

export interface ServiceCheck {
  id: number
  connection_id: number
  service_name: UnlockServiceName
  status: string
  region: string | null
  latency_ms: number | null
  failure_reason: string | null
  details: Record<string, unknown>
  checked_at: string
}

export interface ServiceCheckListResponse {
  items: ServiceCheck[]
  total: number
  limit: number
  offset: number
}

export interface UnlockCheckResponse {
  items: ServiceCheck[]
}

export interface ConnectionCreateResponse {
  connection: VPNConnection
  one_time_socks_password: string | null
}

export interface ConnectionLifecycleResult {
  action: string
  status: ConnectionStatus
  exit_ip: string | null
  network_type: NetworkType
  socks_active: boolean
  steps: string[]
  simulated: boolean
  failure_code: string | null
}

export interface ConnectionLifecycleResponse {
  connection: VPNConnection
  result: ConnectionLifecycleResult
}

export interface SocksPasswordRotateResponse {
  connection_id: number
  username: string
  one_time_socks_password: string
}

export interface HealthCheckResponse {
  connection_id: number
  healthy: boolean
  trigger: string | null
  exit_ip: string | null
  latency_ms: number | null
  download_bps: number | null
  network_type: NetworkType
  failure_code: string | null
  simulated: boolean
  consecutive_failures: number
}

export interface ConnectionSwitchResponse {
  connection_id: number
  previous_node_id: number
  candidate_node_id: number
  status: 'SUCCEEDED' | 'FAILED'
  exit_ip: string | null
  simulated: boolean
  failure_code: string | null
}

export interface ConnectionEvent {
  id: number
  connection_id: number | null
  event_type: string
  status: string
  message: string | null
  details: Record<string, unknown>
  created_at: string
}

export interface ConnectionEventListResponse {
  items: ConnectionEvent[]
  total: number
  limit: number
  offset: number
}

export type LogSource = 'audit' | 'login' | 'connection' | 'scan'

export interface AdminLogEntry {
  id: string
  source: LogSource
  category: string
  level: 'INFO' | 'WARN' | 'ERROR'
  message: string
  actor: string | null
  target: string | null
  details: Record<string, unknown>
  created_at: string
}

export interface AdminLogListResponse {
  items: AdminLogEntry[]
  total: number
  limit: number
  offset: number
}

export interface AdminSettings {
  node_refresh_minutes: number
  scan_concurrency: number
  socks_port_start: number
  socks_port_end: number
  namespace_dns_servers: string[]
  log_retention_days: number
  health_check_interval_seconds: number
  auto_switch_max_per_hour: number
  ipinfo_api_token_configured: boolean
  requires_restart: boolean
}

export interface UserListResponse {
  items: User[]
  total: number
}
