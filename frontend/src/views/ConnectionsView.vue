<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { useRoute, useRouter } from 'vue-router'

import { apiRequest } from '../api/http'
import AppSidebar from '../components/AppSidebar.vue'
import { useAuthStore } from '../stores/auth'
import type {
  ConnectionCreateResponse,
  ConnectionEvent,
  ConnectionEventListResponse,
  ConnectionLifecycleResponse,
  ConnectionListResponse,
  ConnectionSwitchResponse,
  HealthCheckResponse,
  NodeListResponse,
  SocksPasswordRotateResponse,
  UserRole,
  VPNConnection,
  VPNGateNode,
} from '../types/api'

const auth = useAuthStore()
const router = useRouter()
const route = useRoute()
const connections = ref<VPNConnection[]>([])
const nodes = ref<VPNGateNode[]>([])
const events = ref<ConnectionEvent[]>([])
const loading = ref(false)
const actionId = ref<number | null>(null)
const createVisible = ref(false)
const eventsVisible = ref(false)
const credentialVisible = ref(false)
const oneTimeCredential = ref({ username: '', password: '', port: 0 })
const createForm = reactive({
  name: '',
  node_id: null as number | null,
  create_socks: true,
  socks_username: '',
  socks_port: undefined as number | undefined,
  allowlist: '',
})

const roleLabels: Record<UserRole, string> = {
  SUPER_ADMIN: '超级管理员',
  ADMIN: '管理员',
  VIEWER: '只读用户',
}
const roleLabel = computed(() => (auth.user ? roleLabels[auth.user.role] : ''))
const canManage = computed(() => auth.permissions.includes('network:manage'))
const availableNodes = computed(() => nodes.value.filter((node) => node.is_available && !node.is_blocked))

const statusLabels: Record<string, string> = {
  PENDING: '待处理',
  STARTING: '启动中',
  RUNNING: '运行中',
  STOPPING: '停止中',
  STOPPED: '已停止',
  FAILED: '异常',
}

function statusType(status: string): 'success' | 'warning' | 'danger' | 'info' {
  if (status === 'RUNNING') return 'success'
  if (status === 'FAILED') return 'danger'
  if (status === 'STARTING' || status === 'STOPPING') return 'warning'
  return 'info'
}

function formatBytes(value: number | null): string {
  if (value === null) return '—'
  const units = ['B', 'KB', 'MB', 'GB']
  let amount = value
  let unit = 0
  while (amount >= 1024 && unit < units.length - 1) {
    amount /= 1024
    unit += 1
  }
  return `${amount.toFixed(unit === 0 ? 0 : 1)} ${units[unit]}`
}

function formatTime(value: string | null): string {
  return value ? new Date(value).toLocaleString('zh-CN', { hour12: false }) : '—'
}

function uptime(value: string | null): string {
  if (!value) return '—'
  const seconds = Math.max(0, Math.floor((Date.now() - new Date(value).getTime()) / 1000))
  const hours = Math.floor(seconds / 3600)
  const minutes = Math.floor((seconds % 3600) / 60)
  return `${hours}h ${minutes}m`
}

function replaceConnection(updated: VPNConnection): void {
  const index = connections.value.findIndex((item) => item.id === updated.id)
  if (index >= 0) connections.value.splice(index, 1, updated)
  else connections.value.unshift(updated)
}

async function loadData(): Promise<void> {
  loading.value = true
  try {
    const [connectionResult, nodeResult] = await Promise.all([
      apiRequest<ConnectionListResponse>('/api/v1/connections?limit=200'),
      apiRequest<NodeListResponse>('/api/v1/nodes?available=true&limit=200&sort_by=score&sort_order=desc'),
    ])
    connections.value = connectionResult.items
    nodes.value = nodeResult.items
    const requestedNode = Number(route.query.node_id)
    if (Number.isInteger(requestedNode) && requestedNode > 0 && canManage.value) {
      createForm.node_id = requestedNode
      createVisible.value = true
    }
  } catch {
    ElMessage.error('连接数据加载失败')
  } finally {
    loading.value = false
  }
}

async function createConnection(): Promise<void> {
  if (!createForm.node_id || !createForm.name.trim()) return
  loading.value = true
  try {
    const result = await apiRequest<ConnectionCreateResponse>('/api/v1/connections', {
      method: 'POST',
      body: JSON.stringify({
        name: createForm.name.trim(),
        node_id: createForm.node_id,
        create_socks: createForm.create_socks,
        socks_username: createForm.socks_username.trim() || null,
        socks_port: createForm.socks_port ?? null,
        client_ip_allowlist: createForm.allowlist
          .split(/[,\n]/)
          .map((item) => item.trim())
          .filter(Boolean),
      }),
    })
    replaceConnection(result.connection)
    createVisible.value = false
    if (result.one_time_socks_password && result.connection.socks_username && result.connection.socks_port) {
      oneTimeCredential.value = {
        username: result.connection.socks_username,
        password: result.one_time_socks_password,
        port: result.connection.socks_port,
      }
      credentialVisible.value = true
    }
    Object.assign(createForm, { name: '', node_id: null, create_socks: true, socks_username: '', socks_port: undefined, allowlist: '' })
    ElMessage.success('连接已创建')
  } catch {
    ElMessage.error('连接创建失败，请检查节点状态和输入')
  } finally {
    loading.value = false
  }
}

async function lifecycle(connection: VPNConnection, action: 'start' | 'stop' | 'restart'): Promise<void> {
  actionId.value = connection.id
  try {
    const result = await apiRequest<ConnectionLifecycleResponse>(
      `/api/v1/connections/${connection.id}/${action}`,
      { method: 'POST' },
    )
    replaceConnection(result.connection)
    if (result.result.failure_code) ElMessage.error(`操作失败：${result.result.failure_code}`)
    else ElMessage.success(`${statusLabels[result.connection.status] ?? result.connection.status} · ${result.result.simulated ? '模拟执行' : '真实执行'}`)
  } catch {
    ElMessage.error('连接状态不允许执行该操作')
  } finally {
    actionId.value = null
  }
}

async function switchConnection(connection: VPNConnection): Promise<void> {
  actionId.value = connection.id
  try {
    const result = await apiRequest<ConnectionSwitchResponse>(`/api/v1/connections/${connection.id}/switch`, {
      method: 'POST',
      body: JSON.stringify({}),
    })
    await loadData()
    ElMessage[result.status === 'SUCCEEDED' ? 'success' : 'error'](
      result.status === 'SUCCEEDED' ? `已切换到节点 #${result.candidate_node_id}` : `切换失败：${result.failure_code}`,
    )
  } catch {
    ElMessage.error('没有符合条件的候选节点或连接状态不允许切换')
  } finally {
    actionId.value = null
  }
}

async function checkHealth(connection: VPNConnection): Promise<void> {
  actionId.value = connection.id
  try {
    const result = await apiRequest<HealthCheckResponse>(`/api/v1/connections/${connection.id}/health-check`, {
      method: 'POST',
      body: JSON.stringify({}),
    })
    await loadData()
    ElMessage[result.healthy ? 'success' : 'warning'](
      result.healthy ? `健康检查通过（${result.simulated ? '模拟' : '真实'}）` : `健康检查失败：${result.failure_code}`,
    )
  } catch {
    ElMessage.error('健康检查要求连接处于运行状态')
  } finally {
    actionId.value = null
  }
}

async function rotatePassword(connection: VPNConnection): Promise<void> {
  try {
    await ElMessageBox.confirm('旧 SOCKS5 密码将立即失效，是否继续？', '轮换密码', { type: 'warning' })
    const result = await apiRequest<SocksPasswordRotateResponse>(
      `/api/v1/connections/${connection.id}/rotate-password`,
      { method: 'POST' },
    )
    oneTimeCredential.value = {
      username: result.username,
      password: result.one_time_socks_password,
      port: connection.socks_port ?? 0,
    }
    credentialVisible.value = true
  } catch {
    // Cancellation and active-endpoint conflicts need no sensitive detail.
  }
}

async function deleteConnection(connection: VPNConnection): Promise<void> {
  try {
    await ElMessageBox.confirm('仅已停止的连接可删除。该操作会删除关联检测历史。', '删除连接', { type: 'warning' })
    await apiRequest<void>(`/api/v1/connections/${connection.id}`, { method: 'DELETE' })
    connections.value = connections.value.filter((item) => item.id !== connection.id)
    ElMessage.success('连接已删除')
  } catch {
    // Cancellation and state conflicts are intentionally handled alike.
  }
}

async function showEvents(connection: VPNConnection): Promise<void> {
  try {
    const result = await apiRequest<ConnectionEventListResponse>(
      `/api/v1/connections/${connection.id}/events?limit=100`,
    )
    events.value = result.items
    eventsVisible.value = true
  } catch {
    ElMessage.error('事件历史加载失败')
  }
}

async function runCommand(command: string, connection: VPNConnection): Promise<void> {
  if (command === 'start' || command === 'stop' || command === 'restart') await lifecycle(connection, command)
  else if (command === 'switch') await switchConnection(connection)
  else if (command === 'health') await checkHealth(connection)
  else if (command === 'password') await rotatePassword(connection)
  else if (command === 'events') await showEvents(connection)
  else if (command === 'delete') await deleteConnection(connection)
}

async function logout(): Promise<void> {
  await auth.logout()
  await router.replace('/login')
}

onMounted(loadData)
</script>

<template>
  <main class="dashboard-shell">
    <AppSidebar safety-title="连接执行默认模拟" safety-text="真实生命周期需全部显式开关" />
    <section class="dashboard-main">
      <header class="topbar">
        <div><p class="eyebrow">CONTROL PLANE / CONNECTIONS</p><h1>连接管理</h1></div>
        <div class="user-menu">
          <div class="user-avatar">{{ auth.user?.username.slice(0, 1).toUpperCase() }}</div>
          <div><strong>{{ auth.user?.username }}</strong><small>{{ roleLabel }}</small></div>
          <el-button text @click="logout">退出</el-button>
        </div>
      </header>

      <div class="dashboard-content management-content">
        <section class="management-toolbar panel">
          <div><span class="live-indicator"><i></i> FAIL-CLOSED LIFECYCLE</span><h2>隔离连接与独立 SOCKS5 出口</h2><p>启动和切换只有在出口、网络类型与规则验证通过后才会开放代理。</p></div>
          <div class="toolbar-actions">
            <el-button @click="loadData">刷新</el-button>
            <el-button v-if="canManage" type="primary" @click="createVisible = true">创建连接</el-button>
          </div>
        </section>

        <section class="panel node-table-panel">
          <el-table v-loading="loading" :data="connections" empty-text="暂无连接，请从可用节点创建">
            <el-table-column label="连接 / Namespace" min-width="180">
              <template #default="{ row }: { row: VPNConnection }"><div class="cell-stack"><strong>{{ row.name }}</strong><span class="mono">{{ row.namespace }}</span></div></template>
            </el-table-column>
            <el-table-column label="节点 / 出口" min-width="180">
              <template #default="{ row }: { row: VPNConnection }"><div class="cell-stack"><strong class="mono">{{ row.node_ip ?? `#${row.node_id}` }}</strong><span class="mono">{{ row.exit_ip ?? '无活动出口' }}</span></div></template>
            </el-table-column>
            <el-table-column label="SOCKS5" min-width="170">
              <template #default="{ row }: { row: VPNConnection }"><div class="cell-stack"><strong>{{ row.socks_port ? `0.0.0.0:${row.socks_port}` : '未配置' }}</strong><span>{{ row.socks_username ?? '—' }} · {{ row.socks_active ? '在线' : '离线' }}</span></div></template>
            </el-table-column>
            <el-table-column label="状态" width="110"><template #default="{ row }: { row: VPNConnection }"><el-tag :type="statusType(row.status)" effect="dark">{{ statusLabels[row.status] }}</el-tag></template></el-table-column>
            <el-table-column label="速度 / 流量" min-width="150"><template #default="{ row }: { row: VPNConnection }"><div class="cell-stack"><strong>{{ formatBytes(row.node_speed_bps) }}/s</strong><span>↑ {{ formatBytes(row.socks_bytes_up) }} · ↓ {{ formatBytes(row.socks_bytes_down) }}</span></div></template></el-table-column>
            <el-table-column label="运行时间" min-width="145"><template #default="{ row }: { row: VPNConnection }"><div class="cell-stack"><strong>{{ row.status === 'RUNNING' ? uptime(row.started_at) : '—' }}</strong><span>{{ formatTime(row.last_health_at) }}</span></div></template></el-table-column>
            <el-table-column label="操作" width="130" fixed="right">
              <template #default="{ row }: { row: VPNConnection }">
                <el-dropdown trigger="click" :disabled="actionId === row.id" @command="(command: string) => runCommand(command, row)">
                  <el-button :loading="actionId === row.id">操作</el-button>
                  <template #dropdown><el-dropdown-menu>
                    <el-dropdown-item v-if="canManage" command="start" :disabled="row.status === 'RUNNING'">启动</el-dropdown-item>
                    <el-dropdown-item v-if="canManage" command="stop" :disabled="row.status === 'STOPPED'">停止</el-dropdown-item>
                    <el-dropdown-item v-if="canManage" command="restart" :disabled="row.status !== 'RUNNING'">重启</el-dropdown-item>
                    <el-dropdown-item v-if="canManage" command="switch" :disabled="row.status !== 'RUNNING'">切换节点</el-dropdown-item>
                    <el-dropdown-item v-if="canManage" command="health" :disabled="row.status !== 'RUNNING'">健康检测</el-dropdown-item>
                    <el-dropdown-item v-if="canManage && row.socks_port" command="password" :disabled="row.socks_active">改 SOCKS 密码</el-dropdown-item>
                    <el-dropdown-item command="events">事件历史</el-dropdown-item>
                    <el-dropdown-item v-if="canManage" command="delete" divided :disabled="row.status !== 'STOPPED'">删除</el-dropdown-item>
                  </el-dropdown-menu></template>
                </el-dropdown>
              </template>
            </el-table-column>
          </el-table>
        </section>
      </div>
    </section>

    <el-dialog v-model="createVisible" title="创建隔离连接" width="min(36rem, 92vw)">
      <el-form label-position="top">
        <el-form-item label="连接名称"><el-input v-model="createForm.name" maxlength="96" placeholder="例如 us-primary" /></el-form-item>
        <el-form-item label="VPNGate 节点"><el-select v-model="createForm.node_id" filterable placeholder="选择可用且未拉黑的节点"><el-option v-for="node in availableNodes" :key="node.id" :value="node.id" :label="`${node.country_code ?? '—'} · ${node.ip_address} · ${node.ping_ms ?? '—'} ms`" /></el-select></el-form-item>
        <el-switch v-model="createForm.create_socks" active-text="同时创建 SOCKS5 端点" />
        <template v-if="createForm.create_socks">
          <div class="dialog-grid"><el-form-item label="用户名（留空自动生成）"><el-input v-model="createForm.socks_username" /></el-form-item><el-form-item label="端口（留空自动分配）"><el-input-number v-model="createForm.socks_port" :min="1024" :max="65535" controls-position="right" /></el-form-item></div>
          <el-form-item label="客户端 IP/CIDR 白名单"><el-input v-model="createForm.allowlist" type="textarea" :rows="3" placeholder="每行或逗号分隔；留空表示由防火墙策略决定" /></el-form-item>
        </template>
      </el-form>
      <template #footer><el-button @click="createVisible = false">取消</el-button><el-button type="primary" :disabled="!createForm.name.trim() || !createForm.node_id" @click="createConnection">创建</el-button></template>
    </el-dialog>

    <el-dialog v-model="credentialVisible" title="一次性 SOCKS5 凭据" width="min(34rem, 92vw)" :close-on-click-modal="false">
      <el-alert type="warning" :closable="false" title="密码只在本次响应中显示，请立即保存到安全的密码管理器。" />
      <dl class="credential-grid"><dt>端口</dt><dd class="mono">{{ oneTimeCredential.port }}</dd><dt>用户名</dt><dd class="mono">{{ oneTimeCredential.username }}</dd><dt>密码</dt><dd class="mono sensitive-value">{{ oneTimeCredential.password }}</dd></dl>
      <template #footer><el-button type="primary" @click="credentialVisible = false">我已安全保存</el-button></template>
    </el-dialog>

    <el-drawer v-model="eventsVisible" title="连接事件" size="min(46rem, 92vw)">
      <el-timeline><el-timeline-item v-for="event in events" :key="event.id" :timestamp="formatTime(event.created_at)" placement="top"><strong>{{ event.event_type }}</strong><p>{{ event.message ?? event.status }} · <span class="mono">{{ event.status }}</span></p></el-timeline-item></el-timeline>
    </el-drawer>
  </main>
</template>
