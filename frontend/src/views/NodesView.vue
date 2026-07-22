<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { useRouter } from 'vue-router'

import { apiRequest } from '../api/http'
import AppSidebar from '../components/AppSidebar.vue'
import { useAuthStore } from '../stores/auth'
import type {
  NetworkType,
  NodeBlockResponse,
  NodeListResponse,
  NodeRefreshResponse,
  NodeScanResponse,
  UserRole,
  VPNGateNode,
} from '../types/api'

const auth = useAuthStore()
const router = useRouter()
const loading = ref(false)
const refreshing = ref(false)
const classifyingId = ref<number | null>(null)
const actionId = ref<number | null>(null)
const batchScanning = ref(false)
const nodes = ref<VPNGateNode[]>([])
const selection = ref<VPNGateNode[]>([])
const total = ref(0)
const page = ref(1)
const pageSize = 50
const search = ref('')
const country = ref('')
const protocol = ref<'' | 'udp' | 'tcp'>('')
const availability = ref<'' | 'true' | 'false'>('')
const networkType = ref<NetworkType | ''>('')

const roleLabels: Record<UserRole, string> = {
  SUPER_ADMIN: '超级管理员',
  ADMIN: '管理员',
  VIEWER: '只读用户',
}
const roleLabel = computed(() => (auth.user ? roleLabels[auth.user.role] : ''))
const canManage = computed(() => auth.permissions.includes('network:manage'))

const typeLabels: Record<NetworkType, string> = {
  RESIDENTIAL_LIKELY: '疑似住宅',
  DATACENTER: '数据中心',
  MOBILE: '移动网络',
  BUSINESS_ISP: '企业网络',
  PUBLIC_VPN: '公共 VPN',
  PROXY: '代理网络',
  UNKNOWN: '待识别',
}

const reasonLabels: Record<string, string> = {
  provider_proxy_flag: '供应商代理标记',
  provider_vpn_flag: '供应商 VPN 标记',
  provider_anonymous_flag: '匿名网络标记',
  provider_hosting_flag: '托管网络标记',
  provider_mobile_flag: '移动网络标记',
  hosting_asn_type: '托管 ASN 类型',
  business_asn_type: '企业 ASN 类型',
  institutional_asn_type: '机构 ASN 类型',
  proxy_keyword: '代理关键词',
  vpn_keyword: 'VPN 关键词',
  datacenter_keyword: '机房关键词',
  mobile_keyword: '移动网络关键词',
  consumer_access_keyword: '消费者接入特征',
  business_keyword: '企业网络关键词',
  conflicting_signals: '存在冲突信号',
  insufficient_evidence: '证据不足',
}

function typeTag(type: NetworkType): 'success' | 'warning' | 'danger' | 'info' | 'primary' {
  if (type === 'RESIDENTIAL_LIKELY') return 'success'
  if (type === 'DATACENTER' || type === 'PUBLIC_VPN') return 'warning'
  if (type === 'PROXY') return 'danger'
  if (type === 'UNKNOWN') return 'info'
  return 'primary'
}

function confidence(value: number | null): string {
  return value === null ? '—' : `${Math.round(value * 100)}%`
}

function checkedAt(value: string | null): string {
  return value ? new Date(value).toLocaleString('zh-CN', { hour12: false }) : '尚未分类'
}

function reasons(node: VPNGateNode): string {
  if (node.network_classification_reasons.length === 0) return '尚无分类依据'
  return node.network_classification_reasons.map((reason) => reasonLabels[reason] ?? reason).join('；')
}

function formatSpeed(value: number | null): string {
  if (value === null) return '—'
  return `${(value / 1_000_000).toFixed(1)} Mbps`
}

async function loadNodes(resetPage = false): Promise<void> {
  if (resetPage) page.value = 1
  const params = new URLSearchParams({
    limit: String(pageSize),
    offset: String((page.value - 1) * pageSize),
    sort_by: 'score',
    sort_order: 'desc',
  })
  if (search.value.trim()) params.set('search', search.value.trim())
  if (/^[a-zA-Z]{2}$/.test(country.value.trim())) params.set('country_code', country.value.trim().toUpperCase())
  if (protocol.value) params.set('protocol', protocol.value)
  if (availability.value) params.set('available', availability.value)
  if (networkType.value) params.set('network_type', networkType.value)
  loading.value = true
  try {
    const result = await apiRequest<NodeListResponse>(`/api/v1/nodes?${params.toString()}`)
    nodes.value = result.items
    total.value = result.total
    selection.value = []
  } catch {
    ElMessage.error('节点数据加载失败')
  } finally {
    loading.value = false
  }
}

async function refreshNodes(): Promise<void> {
  refreshing.value = true
  try {
    const result = await apiRequest<NodeRefreshResponse>('/api/v1/nodes/refresh', { method: 'POST' })
    ElMessage.success(`刷新完成：新增 ${result.inserted}，更新 ${result.updated}，有效 ${result.valid_nodes}`)
    await loadNodes(true)
  } catch {
    ElMessage.error('VPNGate 数据源暂时不可用')
  } finally {
    refreshing.value = false
  }
}

async function scanOne(node: VPNGateNode, scanType: 'fast' | 'full'): Promise<NodeScanResponse | null> {
  actionId.value = node.id
  try {
    const result = await apiRequest<NodeScanResponse>(`/api/v1/nodes/${node.id}/scan?scan_type=${scanType}`, { method: 'POST' })
    const mode = result.simulated ? '模拟' : '真实'
    if (result.status === 'SUCCEEDED') ElMessage.success(`#${node.id} ${scanType} 检测完成（${mode}）`)
    else ElMessage.warning(`#${node.id} 检测未通过：${result.error_code ?? result.status}`)
    return result
  } catch {
    ElMessage.error(scanType === 'full' ? '真实 full 检测未开启或执行失败' : '节点检测失败')
    return null
  } finally {
    actionId.value = null
  }
}

async function batchScan(scanType: 'fast' | 'full'): Promise<void> {
  if (selection.value.length === 0) return
  batchScanning.value = true
  try {
    const results = await Promise.all(selection.value.map((node) => scanOne(node, scanType)))
    const succeeded = results.filter((result) => result?.status === 'SUCCEEDED').length
    ElMessage.info(`批量检测完成：${succeeded}/${results.length} 成功`)
    await loadNodes()
  } finally {
    batchScanning.value = false
  }
}

async function classify(node: VPNGateNode): Promise<void> {
  classifyingId.value = node.id
  try {
    const updated = await apiRequest<VPNGateNode>(`/api/v1/nodes/${node.id}/classify`, { method: 'POST' })
    nodes.value = nodes.value.map((item) => (item.id === updated.id ? { ...updated, is_blocked: item.is_blocked } : item))
    ElMessage.success('出口 IP 分类已更新')
  } catch {
    ElMessage.warning('需要先完成一次成功的真实 full 检测')
  } finally {
    classifyingId.value = null
  }
}

async function toggleBlock(node: VPNGateNode): Promise<void> {
  try {
    if (node.is_blocked) {
      await ElMessageBox.confirm('从黑名单移除该节点？', '解除拉黑', { type: 'warning' })
      await apiRequest<NodeBlockResponse>(`/api/v1/nodes/${node.id}/block`, { method: 'DELETE' })
    } else {
      const prompt = await ElMessageBox.prompt('可填写拉黑原因；该节点不能再用于创建或切换连接。', '拉黑节点', {
        inputPlaceholder: '例如：出口不稳定',
        inputValidator: (value: string) => value.length <= 255 || '原因最多 255 个字符',
      })
      await apiRequest<NodeBlockResponse>(`/api/v1/nodes/${node.id}/block`, {
        method: 'POST',
        body: JSON.stringify({ reason: prompt.value.trim() || null }),
      })
    }
    nodes.value = nodes.value.map((item) => (item.id === node.id ? { ...item, is_blocked: !node.is_blocked } : item))
    ElMessage.success(node.is_blocked ? '已解除拉黑' : '节点已拉黑')
  } catch {
    // Cancellation and request failures do not reveal operational details.
  }
}

async function createConnection(node: VPNGateNode): Promise<void> {
  await router.push({ path: '/connections', query: { node_id: String(node.id) } })
}

async function logout(): Promise<void> {
  await auth.logout()
  await router.replace('/login')
}

onMounted(() => loadNodes())
</script>

<template>
  <main class="dashboard-shell">
    <AppSidebar safety-title="默认模拟检测" safety-text="真实 full 检测需显式开启" />
    <section class="dashboard-main">
      <header class="topbar">
        <div><p class="eyebrow">CONTROL PLANE / NODES</p><h1>节点管理</h1></div>
        <div class="user-menu">
          <div class="user-avatar">{{ auth.user?.username.slice(0, 1).toUpperCase() }}</div>
          <div><strong>{{ auth.user?.username }}</strong><small>{{ roleLabel }}</small></div>
          <el-button text @click="logout">退出</el-button>
        </div>
      </header>

      <div class="dashboard-content nodes-content">
        <section class="node-toolbar">
          <div><span class="live-indicator"><i></i> FILTER · SCAN · CLASSIFY</span><h2>VPNGate 节点与实际出口情报</h2><p>默认 fast/full 检测均使用模拟执行器；真实 namespace、OpenVPN 与防火墙检测必须由环境开关共同授权。</p></div>
          <div v-if="canManage" class="toolbar-actions"><el-button :loading="refreshing" @click="refreshNodes">刷新节点源</el-button><el-button type="primary" :disabled="selection.length === 0" :loading="batchScanning" @click="batchScan('fast')">批量 Fast</el-button><el-button type="warning" plain :disabled="selection.length === 0" :loading="batchScanning" @click="batchScan('full')">批量 Full</el-button></div>
        </section>

        <section class="panel node-filter-panel">
          <div class="node-filters expanded-filters">
            <el-input v-model="search" clearable placeholder="IP、组织、ISP、PTR 或城市" @keyup.enter="loadNodes(true)" />
            <el-input v-model="country" clearable maxlength="2" placeholder="国家代码，如 US" @keyup.enter="loadNodes(true)" />
            <el-select v-model="protocol" clearable placeholder="全部协议"><el-option label="UDP" value="udp" /><el-option label="TCP" value="tcp" /></el-select>
            <el-select v-model="availability" clearable placeholder="全部可用状态"><el-option label="可用" value="true" /><el-option label="不可用" value="false" /></el-select>
            <el-select v-model="networkType" clearable placeholder="全部网络类型"><el-option v-for="(label, value) in typeLabels" :key="value" :label="label" :value="value" /></el-select>
            <el-button type="primary" @click="loadNodes(true)">查询</el-button>
          </div>
        </section>

        <section class="panel node-table-panel">
          <el-table v-loading="loading" :data="nodes" empty-text="暂无节点数据" @selection-change="(rows: VPNGateNode[]) => selection = rows">
            <el-table-column v-if="canManage" type="selection" width="48" />
            <el-table-column label="VPNGate 节点" min-width="190"><template #default="{ row }: { row: VPNGateNode }"><div class="cell-stack"><strong class="mono">{{ row.ip_address }}</strong><span>{{ row.country_code ?? '—' }} · {{ row.protocol.toUpperCase() }}:{{ row.remote_port }}</span></div></template></el-table-column>
            <el-table-column label="质量" min-width="125"><template #default="{ row }: { row: VPNGateNode }"><div class="cell-stack"><strong>{{ row.ping_ms ?? '—' }} ms</strong><span>{{ formatSpeed(row.speed_bps) }}</span></div></template></el-table-column>
            <el-table-column label="实际出口" min-width="190"><template #default="{ row }: { row: VPNGateNode }"><div class="cell-stack"><strong class="mono">{{ row.classified_exit_ip ?? '未扫描' }}</strong><span>{{ [row.exit_city, row.exit_country_name].filter(Boolean).join(' · ') || '位置未知' }}</span></div></template></el-table-column>
            <el-table-column label="ASN / ISP" min-width="230"><template #default="{ row }: { row: VPNGateNode }"><div class="cell-stack"><strong>{{ row.asn ? `AS${row.asn}` : 'ASN 未知' }} · {{ row.asn_organization ?? '组织未知' }}</strong><span>{{ row.isp ?? row.ptr ?? 'ISP / PTR 未知' }}</span></div></template></el-table-column>
            <el-table-column label="网络类型" min-width="150"><template #default="{ row }: { row: VPNGateNode }"><el-tooltip :content="reasons(row)" placement="top"><div class="classification-cell"><el-tag :type="typeTag(row.network_type)" effect="dark">{{ typeLabels[row.network_type] }}</el-tag><strong>{{ confidence(row.network_confidence) }}</strong></div></el-tooltip></template></el-table-column>
            <el-table-column label="状态" min-width="145"><template #default="{ row }: { row: VPNGateNode }"><div class="cell-stack"><strong><el-tag :type="row.is_blocked ? 'danger' : row.is_available ? 'success' : 'info'">{{ row.is_blocked ? '已拉黑' : row.is_available ? '可用' : '不可用' }}</el-tag></strong><span>{{ checkedAt(row.intelligence_checked_at) }}</span></div></template></el-table-column>
            <el-table-column v-if="canManage" label="操作" width="135" fixed="right">
              <template #default="{ row }: { row: VPNGateNode }"><el-dropdown trigger="click" @command="(command: string) => command === 'fast' ? scanOne(row, 'fast') : command === 'full' ? scanOne(row, 'full') : command === 'classify' ? classify(row) : command === 'block' ? toggleBlock(row) : createConnection(row)"><el-button :loading="actionId === row.id || classifyingId === row.id">操作</el-button><template #dropdown><el-dropdown-menu><el-dropdown-item command="create" :disabled="!row.is_available || row.is_blocked">创建连接</el-dropdown-item><el-dropdown-item command="fast">Fast 检测</el-dropdown-item><el-dropdown-item command="full">Full 检测</el-dropdown-item><el-dropdown-item command="classify" :disabled="!row.classified_exit_ip">重分类</el-dropdown-item><el-dropdown-item command="block" divided>{{ row.is_blocked ? '解除拉黑' : '拉黑节点' }}</el-dropdown-item></el-dropdown-menu></template></el-dropdown></template>
            </el-table-column>
          </el-table>
          <div class="node-pagination"><span>共 {{ total }} 个节点<span v-if="selection.length"> · 已选 {{ selection.length }}</span></span><el-pagination v-model:current-page="page" background layout="prev, pager, next" :page-size="pageSize" :total="total" @current-change="loadNodes()" /></div>
        </section>
      </div>
    </section>
  </main>
</template>
