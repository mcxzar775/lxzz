<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { useRouter } from 'vue-router'

import { apiRequest } from '../api/http'
import AppSidebar from '../components/AppSidebar.vue'
import { useAuthStore } from '../stores/auth'
import type { AdminLogEntry, AdminLogListResponse, LogSource, UserRole } from '../types/api'

const auth = useAuthStore()
const router = useRouter()
const loading = ref(false)
const logs = ref<AdminLogEntry[]>([])
const total = ref(0)
const source = ref<LogSource | ''>('')
const page = ref(1)
const pageSize = 50

const roleLabels: Record<UserRole, string> = {
  SUPER_ADMIN: '超级管理员',
  ADMIN: '管理员',
  VIEWER: '只读用户',
}
const roleLabel = computed(() => (auth.user ? roleLabels[auth.user.role] : ''))
const sourceLabels: Record<LogSource, string> = {
  audit: '审计',
  login: '登录',
  connection: '连接',
  scan: '检测',
}

function formatTime(value: string): string {
  return new Date(value).toLocaleString('zh-CN', { hour12: false })
}

function levelType(level: AdminLogEntry['level']): 'success' | 'warning' | 'danger' {
  if (level === 'ERROR') return 'danger'
  if (level === 'WARN') return 'warning'
  return 'success'
}

function safeDetails(details: Record<string, unknown>): string {
  const entries = Object.entries(details).filter(([, value]) => value !== null && value !== undefined)
  return entries.length ? JSON.stringify(Object.fromEntries(entries)) : '—'
}

function exportLogs(): void {
  if (!logs.value.length) {
    ElMessage.warning('当前页面没有可导出的日志')
    return
  }
  const payload = {
    exported_at: new Date().toISOString(),
    source: source.value || 'all',
    page: page.value,
    items: logs.value,
  }
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json;charset=utf-8' })
  const url = URL.createObjectURL(blob)
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = `vpngate-logs-${new Date().toISOString().slice(0, 10)}.json`
  anchor.click()
  URL.revokeObjectURL(url)
  ElMessage.success(`已导出当前页面 ${logs.value.length} 条脱敏日志`)
}

async function loadLogs(resetPage = false): Promise<void> {
  if (resetPage) page.value = 1
  const params = new URLSearchParams({
    limit: String(pageSize),
    offset: String((page.value - 1) * pageSize),
  })
  if (source.value) params.set('source', source.value)
  loading.value = true
  try {
    const result = await apiRequest<AdminLogListResponse>(`/api/v1/logs?${params.toString()}`)
    logs.value = result.items
    total.value = result.total
  } catch {
    ElMessage.error('日志加载失败或当前账号无审计权限')
  } finally {
    loading.value = false
  }
}

async function logout(): Promise<void> {
  await auth.logout()
  await router.replace('/login')
}

onMounted(() => loadLogs())
</script>

<template>
  <main class="dashboard-shell">
    <AppSidebar safety-title="日志已结构化脱敏" safety-text="凭据与密钥不会出现在响应中" />
    <section class="dashboard-main">
      <header class="topbar">
        <div><p class="eyebrow">CONTROL PLANE / AUDIT</p><h1>日志中心</h1></div>
        <div class="user-menu">
          <div class="user-avatar">{{ auth.user?.username.slice(0, 1).toUpperCase() }}</div>
          <div><strong>{{ auth.user?.username }}</strong><small>{{ roleLabel }}</small></div>
          <el-button text @click="logout">退出</el-button>
        </div>
      </header>

      <div class="dashboard-content management-content">
        <section class="management-toolbar panel">
          <div><span class="live-indicator"><i></i> NORMALIZED EVENT STREAM</span><h2>审计、登录、连接与检测日志</h2><p>统一时间线仅展示结构化安全字段，不返回密码、Cookie、Token 或 API Key。</p></div>
          <div class="toolbar-actions">
            <el-select v-model="source" clearable placeholder="全部来源" @change="loadLogs(true)">
              <el-option label="审计" value="audit" />
              <el-option label="登录" value="login" />
              <el-option label="连接" value="connection" />
              <el-option label="检测" value="scan" />
            </el-select>
            <el-button :disabled="!logs.length" @click="exportLogs">导出当前页</el-button>
            <el-button @click="loadLogs()">刷新</el-button>
          </div>
        </section>

        <section class="panel node-table-panel">
          <el-table v-loading="loading" :data="logs" empty-text="暂无日志">
            <el-table-column label="时间" width="178"><template #default="{ row }: { row: AdminLogEntry }"><span class="mono table-time">{{ formatTime(row.created_at) }}</span></template></el-table-column>
            <el-table-column label="来源 / 分类" width="140"><template #default="{ row }: { row: AdminLogEntry }"><div class="cell-stack"><strong>{{ sourceLabels[row.source] }}</strong><span>{{ row.category }}</span></div></template></el-table-column>
            <el-table-column label="级别" width="90"><template #default="{ row }: { row: AdminLogEntry }"><el-tag :type="levelType(row.level)" effect="dark">{{ row.level }}</el-tag></template></el-table-column>
            <el-table-column label="事件" min-width="210"><template #default="{ row }: { row: AdminLogEntry }"><strong>{{ row.message }}</strong></template></el-table-column>
            <el-table-column label="操作者 / 目标" min-width="190"><template #default="{ row }: { row: AdminLogEntry }"><div class="cell-stack"><strong>{{ row.actor ?? '系统' }}</strong><span>{{ row.target ?? '—' }}</span></div></template></el-table-column>
            <el-table-column label="安全详情" min-width="260"><template #default="{ row }: { row: AdminLogEntry }"><el-tooltip :content="safeDetails(row.details)" placement="top"><span class="mono detail-preview">{{ safeDetails(row.details) }}</span></el-tooltip></template></el-table-column>
          </el-table>
          <div class="node-pagination"><span>共 {{ total }} 条记录</span><el-pagination v-model:current-page="page" background layout="prev, pager, next" :page-size="pageSize" :total="total" @current-change="loadLogs()" /></div>
        </section>
      </div>
    </section>
  </main>
</template>
