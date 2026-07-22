<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'

import { apiRequest } from '../api/http'
import AppSidebar from '../components/AppSidebar.vue'
import MetricCard from '../components/MetricCard.vue'
import { useAuthStore } from '../stores/auth'
import type { DashboardResponse, UserRole } from '../types/api'

const auth = useAuthStore()
const router = useRouter()
const dashboard = ref<DashboardResponse | null>(null)
const loading = ref(true)

const roleLabels: Record<UserRole, string> = {
  SUPER_ADMIN: '超级管理员',
  ADMIN: '管理员',
  VIEWER: '只读用户',
}
const roleLabel = computed(() => (auth.user ? roleLabels[auth.user.role] : ''))

function formatBytes(bytes: number): string {
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  let value = bytes
  let unit = 0
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024
    unit += 1
  }
  return `${value.toFixed(unit === 0 ? 0 : 1)} ${units[unit]}`
}

async function loadDashboard(): Promise<void> {
  loading.value = true
  try {
    dashboard.value = await apiRequest<DashboardResponse>('/api/v1/dashboard')
  } catch {
    ElMessage.error('仪表盘加载失败，请稍后重试')
  } finally {
    loading.value = false
  }
}

async function logout(): Promise<void> {
  await auth.logout()
  await router.replace('/login')
}

onMounted(loadDashboard)
</script>

<template>
  <main class="dashboard-shell">
    <AppSidebar />

    <section class="dashboard-main" id="overview">
      <header class="topbar">
        <div>
          <p class="eyebrow">CONTROL PLANE / OVERVIEW</p>
          <h1>运行仪表盘</h1>
        </div>
        <div class="user-menu">
          <div class="user-avatar">{{ auth.user?.username.slice(0, 1).toUpperCase() }}</div>
          <div><strong>{{ auth.user?.username }}</strong><small>{{ roleLabel }}</small></div>
          <el-button text @click="logout">退出</el-button>
        </div>
      </header>

      <div v-loading="loading" class="dashboard-content">
        <section class="status-banner">
          <div>
            <span class="live-indicator"><i></i> SYSTEM READY</span>
            <h2>控制面已就绪，网络执行保持隔离。</h2>
            <p>已启用节点、连接、解锁检测、日志与权限管理；真实网络功能仍需显式授权。</p>
          </div>
          <div class="executor-badge">
            <span>NETWORK EXECUTOR</span>
            <strong>{{ dashboard?.network_executor ?? '—' }}</strong>
          </div>
        </section>

        <section class="metrics-grid" aria-label="业务指标">
          <MetricCard label="节点总数" :value="dashboard?.counts.total_nodes ?? 0" />
          <MetricCard label="可用节点" :value="dashboard?.counts.available_nodes ?? 0" tone="green" />
          <MetricCard label="在线 VPN" :value="dashboard?.counts.online_vpns ?? 0" tone="green" />
          <MetricCard label="在线 SOCKS5" :value="dashboard?.counts.online_socks ?? 0" tone="blue" />
          <MetricCard label="异常数量" :value="dashboard?.counts.anomalies ?? 0" tone="red" />
          <MetricCard label="疑似住宅" :value="dashboard?.counts.residential_likely ?? 0" tone="amber" />
          <MetricCard label="Netflix 完整解锁" :value="dashboard?.counts.netflix_full ?? 0" />
          <MetricCard label="ChatGPT 可用" :value="dashboard?.counts.chatgpt_available ?? 0" />
        </section>

        <section class="lower-grid">
          <article class="panel system-panel">
            <div class="panel-heading">
              <div><span>HOST TELEMETRY</span><h3>宿主机资源</h3></div>
              <button type="button" @click="loadDashboard">刷新</button>
            </div>
            <div class="resource-row">
              <label>CPU <strong>{{ dashboard?.system.cpu_percent.toFixed(1) ?? '0.0' }}%</strong></label>
              <el-progress :percentage="dashboard?.system.cpu_percent ?? 0" :show-text="false" />
            </div>
            <div class="resource-row">
              <label>内存 <strong>{{ dashboard?.system.memory_percent.toFixed(1) ?? '0.0' }}%</strong></label>
              <el-progress :percentage="dashboard?.system.memory_percent ?? 0" :show-text="false" />
            </div>
            <div class="resource-row">
              <label>磁盘 <strong>{{ dashboard?.system.disk_percent.toFixed(1) ?? '0.0' }}%</strong></label>
              <el-progress :percentage="dashboard?.system.disk_percent ?? 0" :show-text="false" />
            </div>
            <div class="network-totals">
              <div><span>累计发送</span><strong>{{ formatBytes(dashboard?.system.network_bytes_sent ?? 0) }}</strong></div>
              <div><span>累计接收</span><strong>{{ formatBytes(dashboard?.system.network_bytes_received ?? 0) }}</strong></div>
            </div>
          </article>

          <article class="panel stage-panel">
            <div class="panel-heading"><div><span>ADMIN CONSOLE / STAGE 12</span><h3>已启用能力</h3></div></div>
            <ul class="capability-list">
              <li><i>✓</i><div><strong>网页登录认证</strong><span>HttpOnly Session + CSRF</span></div></li>
              <li><i>✓</i><div><strong>角色权限</strong><span>SUPER_ADMIN / ADMIN / VIEWER</span></div></li>
              <li><i>✓</i><div><strong>安全审计</strong><span>登录与用户操作可追踪</span></div></li>
              <li><i>✓</i><div><strong>模拟执行器</strong><span>默认不操作路由与防火墙</span></div></li>
              <li><i>✓</i><div><strong>连接生命周期</strong><span>创建、启停、切换、SOCKS5 凭据轮换</span></div></li>
              <li><i>✓</i><div><strong>运营管理</strong><span>节点、解锁、日志、用户与设置</span></div></li>
            </ul>
          </article>
        </section>
      </div>
    </section>
  </main>
</template>
