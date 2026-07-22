<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { useRouter } from 'vue-router'

import { apiRequest } from '../api/http'
import AppSidebar from '../components/AppSidebar.vue'
import { useAuthStore } from '../stores/auth'
import type { AdminSettings, User, UserListResponse, UserRole } from '../types/api'

const auth = useAuthStore()
const router = useRouter()
const activeTab = ref('users')
const loading = ref(false)
const saving = ref(false)
const users = ref<User[]>([])
const createVisible = ref(false)
const passwordVisible = ref(false)
const passwordTarget = ref<User | null>(null)
const replacementPassword = ref('')
const createForm = reactive({ username: '', password: '', role: 'VIEWER' as UserRole })
const settings = reactive<AdminSettings>({
  node_refresh_minutes: 30,
  scan_concurrency: 3,
  socks_port_start: 10800,
  socks_port_end: 10999,
  namespace_dns_servers: ['1.1.1.1', '8.8.8.8'],
  log_retention_days: 30,
  health_check_interval_seconds: 60,
  auto_switch_max_per_hour: 3,
  ipinfo_api_token_configured: false,
  requires_restart: false,
})
const dnsInput = ref('1.1.1.1, 8.8.8.8')

const roleLabels: Record<UserRole, string> = {
  SUPER_ADMIN: '超级管理员',
  ADMIN: '管理员',
  VIEWER: '只读用户',
}
const roleLabel = computed(() => (auth.user ? roleLabels[auth.user.role] : ''))

function formatTime(value: string | null): string {
  return value ? new Date(value).toLocaleString('zh-CN', { hour12: false }) : '从未登录'
}

async function loadUsers(): Promise<void> {
  const result = await apiRequest<UserListResponse>('/api/v1/users?limit=200')
  users.value = result.items
}

async function loadSettings(): Promise<void> {
  const result = await apiRequest<AdminSettings>('/api/v1/settings')
  Object.assign(settings, result)
  dnsInput.value = result.namespace_dns_servers.join(', ')
}

async function loadData(): Promise<void> {
  loading.value = true
  try {
    await Promise.all([loadUsers(), loadSettings()])
  } catch {
    ElMessage.error('管理数据加载失败')
  } finally {
    loading.value = false
  }
}

async function createUser(): Promise<void> {
  if (!createForm.username.trim() || createForm.password.length < 12) return
  saving.value = true
  try {
    const user = await apiRequest<User>('/api/v1/users', {
      method: 'POST',
      body: JSON.stringify(createForm),
    })
    users.value.push(user)
    Object.assign(createForm, { username: '', password: '', role: 'VIEWER' })
    createVisible.value = false
    ElMessage.success('用户已创建，密码不会再次显示')
  } catch {
    ElMessage.error('创建失败：请确认用户名唯一且密码满足安全要求')
  } finally {
    saving.value = false
  }
}

async function updateUser(user: User, changes: { role?: UserRole; is_active?: boolean }): Promise<void> {
  saving.value = true
  try {
    const updated = await apiRequest<User>(`/api/v1/users/${user.id}`, {
      method: 'PATCH',
      body: JSON.stringify(changes),
    })
    users.value = users.value.map((item) => (item.id === updated.id ? updated : item))
    ElMessage.success('用户状态已更新')
  } catch {
    await loadUsers()
    ElMessage.error('更新失败；最后一个有效超级管理员受保护')
  } finally {
    saving.value = false
  }
}

async function deactivate(user: User): Promise<void> {
  try {
    await ElMessageBox.confirm(`停用用户 ${user.username} 并撤销其活动会话？`, '停用用户', { type: 'warning' })
    await apiRequest<void>(`/api/v1/users/${user.id}`, { method: 'DELETE' })
    users.value = users.value.map((item) => (item.id === user.id ? { ...item, is_active: false } : item))
    ElMessage.success('用户已停用')
  } catch {
    // User cancellation and protected-account conflicts require no extra detail.
  }
}

function openPasswordReset(user: User): void {
  passwordTarget.value = user
  replacementPassword.value = ''
  passwordVisible.value = true
}

async function resetPassword(): Promise<void> {
  if (!passwordTarget.value || replacementPassword.value.length < 12) return
  saving.value = true
  try {
    await apiRequest<void>(`/api/v1/users/${passwordTarget.value.id}/password`, {
      method: 'POST',
      body: JSON.stringify({ new_password: replacementPassword.value }),
    })
    replacementPassword.value = ''
    passwordVisible.value = false
    ElMessage.success('密码已重置，该用户的所有活动会话已撤销')
  } catch {
    ElMessage.error('密码重置失败，请检查密码安全要求')
  } finally {
    saving.value = false
  }
}

async function saveSettings(): Promise<void> {
  const dns = dnsInput.value.split(/[ ,\n]+/).map((item) => item.trim()).filter(Boolean)
  saving.value = true
  try {
    const result = await apiRequest<AdminSettings>('/api/v1/settings', {
      method: 'PUT',
      body: JSON.stringify({
        node_refresh_minutes: settings.node_refresh_minutes,
        scan_concurrency: settings.scan_concurrency,
        socks_port_start: settings.socks_port_start,
        socks_port_end: settings.socks_port_end,
        namespace_dns_servers: dns,
        log_retention_days: settings.log_retention_days,
        health_check_interval_seconds: settings.health_check_interval_seconds,
        auto_switch_max_per_hour: settings.auto_switch_max_per_hour,
      }),
    })
    Object.assign(settings, result)
    dnsInput.value = result.namespace_dns_servers.join(', ')
    ElMessage.warning('设置已保存；运行参数将在服务重启后生效')
  } catch {
    ElMessage.error('设置校验失败，请检查端口范围与公共 DNS IP')
  } finally {
    saving.value = false
  }
}

async function logout(): Promise<void> {
  await auth.logout()
  await router.replace('/login')
}

onMounted(loadData)
</script>

<template>
  <main class="dashboard-shell">
    <AppSidebar safety-title="敏感设置不经 Web 写入" safety-text="API Token 仅从 root 环境配置" />
    <section class="dashboard-main">
      <header class="topbar">
        <div><p class="eyebrow">CONTROL PLANE / ADMINISTRATION</p><h1>用户与设置</h1></div>
        <div class="user-menu">
          <div class="user-avatar">{{ auth.user?.username.slice(0, 1).toUpperCase() }}</div>
          <div><strong>{{ auth.user?.username }}</strong><small>{{ roleLabel }}</small></div>
          <el-button text @click="logout">退出</el-button>
        </div>
      </header>

      <div v-loading="loading" class="dashboard-content management-content">
        <section class="management-toolbar panel">
          <div><span class="live-indicator"><i></i> LEAST PRIVILEGE</span><h2>角色权限与非敏感运行参数</h2><p>账号变更会写入审计日志；密码、Token 与 API Key 永不回显。</p></div>
        </section>

        <section class="panel administration-panel">
          <el-tabs v-model="activeTab">
            <el-tab-pane label="用户管理" name="users">
              <div class="tab-toolbar"><p>超级管理员管理用户；最后一个有效超级管理员不可停用或降级。</p><el-button type="primary" @click="createVisible = true">创建用户</el-button></div>
              <el-table :data="users" empty-text="暂无用户">
                <el-table-column label="用户" min-width="170"><template #default="{ row }: { row: User }"><div class="cell-stack"><strong>{{ row.username }}</strong><span>#{{ row.id }} · {{ formatTime(row.last_login_at) }}</span></div></template></el-table-column>
                <el-table-column label="角色" min-width="180"><template #default="{ row }: { row: User }"><el-select :model-value="row.role" :disabled="saving" @change="(role: UserRole) => updateUser(row, { role })"><el-option label="超级管理员" value="SUPER_ADMIN" /><el-option label="管理员" value="ADMIN" /><el-option label="只读用户" value="VIEWER" /></el-select></template></el-table-column>
                <el-table-column label="状态" width="150"><template #default="{ row }: { row: User }"><el-switch :model-value="row.is_active" :disabled="saving" active-text="有效" inactive-text="停用" @change="(active: boolean) => updateUser(row, { is_active: active })" /></template></el-table-column>
                <el-table-column label="双因素认证" min-width="190"><template #default="{ row }: { row: User }"><el-tag :type="row.totp_enabled ? 'success' : 'info'">{{ row.totp_enabled ? '已启用' : '未启用' }}</el-tag><small class="inline-note">认证层暂未开放 Web 配置</small></template></el-table-column>
                <el-table-column label="操作" width="170" fixed="right"><template #default="{ row }: { row: User }"><el-button text type="primary" @click="openPasswordReset(row)">重置密码</el-button><el-button text type="danger" :disabled="!row.is_active" @click="deactivate(row)">停用</el-button></template></el-table-column>
              </el-table>
            </el-tab-pane>

            <el-tab-pane label="系统设置" name="settings">
              <el-alert type="info" :closable="false" title="执行器参数保存到数据库并在服务重启后生效；刷新与保留周期作为运维策略保存。敏感环境开关和 API Token 不允许通过 Web 修改。" />
              <el-form class="settings-form" label-position="top">
                <div class="settings-grid">
                  <el-form-item label="节点刷新间隔（分钟）"><el-input-number v-model="settings.node_refresh_minutes" :min="5" :max="1440" /></el-form-item>
                  <el-form-item label="扫描并发数"><el-input-number v-model="settings.scan_concurrency" :min="1" :max="10" /></el-form-item>
                  <el-form-item label="SOCKS 端口起始"><el-input-number v-model="settings.socks_port_start" :min="1024" :max="65535" /></el-form-item>
                  <el-form-item label="SOCKS 端口结束"><el-input-number v-model="settings.socks_port_end" :min="1024" :max="65535" /></el-form-item>
                  <el-form-item label="日志保留天数"><el-input-number v-model="settings.log_retention_days" :min="1" :max="3650" /></el-form-item>
                  <el-form-item label="健康检测间隔（秒）"><el-input-number v-model="settings.health_check_interval_seconds" :min="10" :max="3600" /></el-form-item>
                  <el-form-item label="每小时自动切换上限"><el-input-number v-model="settings.auto_switch_max_per_hour" :min="1" :max="20" /></el-form-item>
                  <el-form-item label="IPinfo API Token"><el-tag :type="settings.ipinfo_api_token_configured ? 'success' : 'info'">{{ settings.ipinfo_api_token_configured ? 'root 环境已配置' : '未配置' }}</el-tag></el-form-item>
                </div>
                <el-form-item label="Namespace DNS（1–3 个规范公共 IP）"><el-input v-model="dnsInput" placeholder="1.1.1.1, 8.8.8.8" /></el-form-item>
                <el-button type="primary" :loading="saving" @click="saveSettings">保存设置</el-button>
              </el-form>
            </el-tab-pane>
          </el-tabs>
        </section>
      </div>
    </section>

    <el-dialog v-model="createVisible" title="创建用户" width="min(32rem, 92vw)" :close-on-click-modal="false">
      <el-alert type="warning" :closable="false" title="密码只用于本次提交，不会在页面、日志或 API 响应中显示。" />
      <el-form label-position="top" class="dialog-form">
        <el-form-item label="用户名"><el-input v-model="createForm.username" minlength="3" maxlength="64" autocomplete="off" /></el-form-item>
        <el-form-item label="初始密码（至少 12 位）"><el-input v-model="createForm.password" type="password" minlength="12" show-password autocomplete="new-password" /></el-form-item>
        <el-form-item label="角色"><el-select v-model="createForm.role"><el-option label="超级管理员" value="SUPER_ADMIN" /><el-option label="管理员" value="ADMIN" /><el-option label="只读用户" value="VIEWER" /></el-select></el-form-item>
      </el-form>
      <template #footer><el-button @click="createVisible = false">取消</el-button><el-button type="primary" :loading="saving" :disabled="!createForm.username.trim() || createForm.password.length < 12" @click="createUser">创建</el-button></template>
    </el-dialog>

    <el-dialog v-model="passwordVisible" title="重置用户密码" width="min(32rem, 92vw)" :close-on-click-modal="false" @closed="replacementPassword = ''">
      <el-alert type="warning" :closable="false" :title="`重置 ${passwordTarget?.username ?? ''} 的密码会立即撤销其全部活动会话；密码不会被回显或写入日志。`" />
      <el-form label-position="top" class="dialog-form"><el-form-item label="新密码（至少 12 位）"><el-input v-model="replacementPassword" type="password" minlength="12" show-password autocomplete="new-password" /></el-form-item></el-form>
      <template #footer><el-button @click="passwordVisible = false">取消</el-button><el-button type="primary" :loading="saving" :disabled="replacementPassword.length < 12" @click="resetPassword">确认重置</el-button></template>
    </el-dialog>
  </main>
</template>
