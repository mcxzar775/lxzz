<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import { ElMessage } from 'element-plus'
import { useRouter } from 'vue-router'

import { apiRequest } from '../api/http'
import AppSidebar from '../components/AppSidebar.vue'
import { useAuthStore } from '../stores/auth'
import type {
  ConnectionListResponse,
  ServiceCheck,
  ServiceCheckListResponse,
  UnlockCheckResponse,
  UnlockServiceName,
  UserRole,
  VPNConnection,
} from '../types/api'

const auth = useAuthStore()
const router = useRouter()
const connections = ref<VPNConnection[]>([])
const selectedConnectionId = ref<number | null>(null)
const selectedServices = ref<UnlockServiceName[]>([
  'netflix',
  'chatgpt',
  'openai_api',
  'youtube',
])
const checks = ref<ServiceCheck[]>([])
const loading = ref(false)
const checking = ref(false)

const roleLabels: Record<UserRole, string> = {
  SUPER_ADMIN: '超级管理员',
  ADMIN: '管理员',
  VIEWER: '只读用户',
}
const roleLabel = computed(() => (auth.user ? roleLabels[auth.user.role] : ''))
const canManage = computed(() => auth.permissions.includes('network:manage'))
const selectedConnection = computed(
  () => connections.value.find((item) => item.id === selectedConnectionId.value) ?? null,
)

const serviceLabels: Record<UnlockServiceName, string> = {
  netflix: 'Netflix',
  chatgpt: 'ChatGPT',
  openai_api: 'OpenAI API',
  youtube: 'YouTube',
}

const statusLabels: Record<string, string> = {
  FULL: '完整解锁',
  ORIGINALS_ONLY: '仅自制内容',
  BLOCKED: '已阻断',
  REACHABLE: '网络可达',
  UNLOCKED: '可用',
  SUPPORTED_REGION: '支持地区',
  UNSUPPORTED_REGION: '不支持地区',
  PARTIAL: '部分可达',
  CHALLENGE: '挑战页面',
  HTTP_BLOCKED: 'HTTP 阻断',
  DNS_FAILED: 'DNS 失败',
  TLS_FAILED: 'TLS 失败',
  TIMEOUT: '超时',
  REGION_DETECTED: '已识别地区',
  UNKNOWN: '未知',
}

function statusType(status: string): 'success' | 'warning' | 'danger' | 'info' | 'primary' {
  if (['FULL', 'UNLOCKED', 'SUPPORTED_REGION', 'REACHABLE', 'REGION_DETECTED'].includes(status)) {
    return 'success'
  }
  if (['BLOCKED', 'HTTP_BLOCKED', 'DNS_FAILED', 'TLS_FAILED'].includes(status)) {
    return 'danger'
  }
  if (['ORIGINALS_ONLY', 'PARTIAL', 'CHALLENGE', 'TIMEOUT'].includes(status)) {
    return 'warning'
  }
  return 'info'
}

function isSimulated(check: ServiceCheck): boolean {
  return check.details.simulated === true
}

function checkedAt(value: string): string {
  return new Date(value).toLocaleString('zh-CN', { hour12: false })
}

async function loadConnections(): Promise<void> {
  loading.value = true
  try {
    const result = await apiRequest<ConnectionListResponse>('/api/v1/connections?limit=200')
    connections.value = result.items
    if (selectedConnectionId.value === null && result.items.length > 0) {
      selectedConnectionId.value = result.items[0]?.id ?? null
    }
  } catch {
    ElMessage.error('连接列表加载失败')
  } finally {
    loading.value = false
  }
}

async function loadChecks(): Promise<void> {
  if (selectedConnectionId.value === null) {
    checks.value = []
    return
  }
  loading.value = true
  try {
    const result = await apiRequest<ServiceCheckListResponse>(
      `/api/v1/connections/${selectedConnectionId.value}/checks?limit=200`,
    )
    checks.value = result.items
  } catch {
    ElMessage.error('检测历史加载失败')
  } finally {
    loading.value = false
  }
}

async function runChecks(): Promise<void> {
  if (selectedConnectionId.value === null || selectedServices.value.length === 0) return
  checking.value = true
  try {
    const result = await apiRequest<UnlockCheckResponse>(
      `/api/v1/connections/${selectedConnectionId.value}/check-unlock`,
      {
        method: 'POST',
        body: JSON.stringify({ services: selectedServices.value }),
      },
    )
    checks.value = [...result.items, ...checks.value]
    ElMessage.success('解锁检测已完成')
  } catch {
    ElMessage.warning('检测要求连接处于 RUNNING 状态')
  } finally {
    checking.value = false
  }
}

async function logout(): Promise<void> {
  await auth.logout()
  await router.replace('/login')
}

watch(selectedConnectionId, loadChecks)
onMounted(loadConnections)
</script>

<template>
  <main class="dashboard-shell">
    <AppSidebar safety-title="Namespace 强制隔离" safety-text="默认检测为模拟模式" />

    <section class="dashboard-main">
      <header class="topbar">
        <div>
          <p class="eyebrow">CONTROL PLANE / UNLOCK CHECKS</p>
          <h1>解锁检测</h1>
        </div>
        <div class="user-menu">
          <div class="user-avatar">{{ auth.user?.username.slice(0, 1).toUpperCase() }}</div>
          <div><strong>{{ auth.user?.username }}</strong><small>{{ roleLabel }}</small></div>
          <el-button text @click="logout">退出</el-button>
        </div>
      </header>

      <div class="dashboard-content unlock-content">
        <section class="unlock-control panel">
          <div class="panel-heading">
            <div><span>NAMESPACE-BOUND PROBES</span><h3>选择连接与服务</h3></div>
            <el-tag :type="selectedConnection?.status === 'RUNNING' ? 'success' : 'info'" effect="dark">
              {{ selectedConnection?.status ?? 'NO CONNECTION' }}
            </el-tag>
          </div>
          <div class="unlock-form">
            <el-select v-model="selectedConnectionId" placeholder="选择 VPN 连接" :loading="loading">
              <el-option
                v-for="connection in connections"
                :key="connection.id"
                :label="`${connection.name} · ${connection.namespace} · ${connection.status}`"
                :value="connection.id"
              />
            </el-select>
            <el-checkbox-group v-model="selectedServices">
              <el-checkbox-button value="netflix">Netflix</el-checkbox-button>
              <el-checkbox-button value="chatgpt">ChatGPT</el-checkbox-button>
              <el-checkbox-button value="openai_api">OpenAI API</el-checkbox-button>
              <el-checkbox-button value="youtube">YouTube</el-checkbox-button>
            </el-checkbox-group>
            <el-button
              type="primary"
              :loading="checking"
              :disabled="!canManage || selectedConnection?.status !== 'RUNNING' || selectedServices.length === 0"
              @click="runChecks"
            >开始检测</el-button>
          </div>
          <p v-if="connections.length === 0" class="empty-hint">当前没有连接记录；请先在连接管理中创建并启动连接。</p>
          <p v-else class="unlock-note">真实模式下，检测只在所选连接的 Namespace 内运行；未显式开启时结果标记为模拟。</p>
        </section>

        <section class="unlock-summary-grid">
          <article v-for="service in selectedServices" :key="service" class="panel unlock-service-card">
            <span>{{ serviceLabels[service] }}</span>
            <strong>{{ statusLabels[checks.find((item) => item.service_name === service)?.status ?? 'UNKNOWN'] ?? '未知' }}</strong>
            <small>{{ checks.find((item) => item.service_name === service)?.region ?? '无地区信息' }}</small>
          </article>
        </section>

        <section class="panel node-table-panel">
          <el-table v-loading="loading" :data="checks" empty-text="暂无检测历史">
            <el-table-column label="服务" min-width="150">
              <template #default="{ row }: { row: ServiceCheck }"><strong>{{ serviceLabels[row.service_name] }}</strong></template>
            </el-table-column>
            <el-table-column label="状态" min-width="160">
              <template #default="{ row }: { row: ServiceCheck }">
                <el-tag :type="statusType(row.status)" effect="dark">{{ statusLabels[row.status] ?? row.status }}</el-tag>
              </template>
            </el-table-column>
            <el-table-column label="地区" width="100">
              <template #default="{ row }: { row: ServiceCheck }">{{ row.region ?? '—' }}</template>
            </el-table-column>
            <el-table-column label="延迟" width="120">
              <template #default="{ row }: { row: ServiceCheck }">{{ row.latency_ms === null ? '—' : `${row.latency_ms.toFixed(1)} ms` }}</template>
            </el-table-column>
            <el-table-column label="执行模式" width="120">
              <template #default="{ row }: { row: ServiceCheck }">
                <el-tag :type="isSimulated(row) ? 'info' : 'success'" effect="plain">{{ isSimulated(row) ? '模拟' : 'Namespace' }}</el-tag>
              </template>
            </el-table-column>
            <el-table-column label="失败原因" min-width="150">
              <template #default="{ row }: { row: ServiceCheck }"><span class="mono">{{ row.failure_reason ?? '—' }}</span></template>
            </el-table-column>
            <el-table-column label="检测时间" min-width="180">
              <template #default="{ row }: { row: ServiceCheck }">{{ checkedAt(row.checked_at) }}</template>
            </el-table-column>
          </el-table>
        </section>
      </div>
    </section>
  </main>
</template>
