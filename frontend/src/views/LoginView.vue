<script setup lang="ts">
import { reactive, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ElMessage, type FormInstance, type FormRules } from 'element-plus'

import { ApiError } from '../api/http'
import { useAuthStore } from '../stores/auth'

interface LoginForm {
  username: string
  password: string
  rememberMe: boolean
}

const formRef = ref<FormInstance>()
const loading = ref(false)
const form = reactive<LoginForm>({ username: '', password: '', rememberMe: false })
const rules: FormRules<LoginForm> = {
  username: [{ required: true, message: '请输入用户名', trigger: 'blur' }],
  password: [{ required: true, message: '请输入密码', trigger: 'blur' }],
}
const auth = useAuthStore()
const route = useRoute()
const router = useRouter()

async function submit(): Promise<void> {
  if (!(await formRef.value?.validate().catch(() => false))) return
  loading.value = true
  try {
    await auth.login(form.username, form.password, form.rememberMe)
    const redirect = typeof route.query.redirect === 'string' ? route.query.redirect : '/'
    await router.replace(redirect)
  } catch (error) {
    if (error instanceof ApiError && error.status === 429) {
      ElMessage.error('登录尝试过多，请稍后再试')
    } else {
      ElMessage.error('用户名或密码错误')
    }
  } finally {
    loading.value = false
  }
}
</script>

<template>
  <main class="login-shell">
    <section class="login-intro" aria-label="系统介绍">
      <div class="brand-mark" aria-hidden="true"><span></span><span></span><span></span></div>
      <p class="eyebrow">VPNGate MULTI-EXIT MANAGER</p>
      <h1>每一条隧道，<br /><em>都是独立边界。</em></h1>
      <p class="intro-copy">
        在统一控制面中管理隔离的 OpenVPN 出口、SOCKS5 端点与健康状态。
        开发环境默认使用模拟网络执行器。
      </p>
      <div class="boundary-map" aria-hidden="true">
        <span>CONTROL</span><i></i><span>NAMESPACE</span><i></i><span>EXIT</span>
      </div>
    </section>

    <section class="login-panel" aria-label="登录">
      <div class="login-card">
        <div class="card-kicker">安全控制台</div>
        <h2>欢迎回来</h2>
        <p>使用管理员分配的账户登录。</p>

        <el-form
          ref="formRef"
          :model="form"
          :rules="rules"
          label-position="top"
          size="large"
          @keyup.enter="submit"
        >
          <el-form-item label="用户名" prop="username">
            <el-input
              v-model="form.username"
              autocomplete="username"
              placeholder="输入用户名"
              autofocus
            />
          </el-form-item>
          <el-form-item label="密码" prop="password">
            <el-input
              v-model="form.password"
              type="password"
              autocomplete="current-password"
              placeholder="输入密码"
              show-password
            />
          </el-form-item>
          <div class="form-options">
            <el-checkbox v-model="form.rememberMe">记住登录状态</el-checkbox>
            <span>会话受 CSRF 保护</span>
          </div>
          <el-button class="login-button" type="primary" :loading="loading" @click="submit">
            进入管理后台
          </el-button>
        </el-form>
        <div class="security-note">
          <span class="status-dot"></span>
          账户密码采用 Argon2id 哈希，凭据不会写入日志
        </div>
      </div>
    </section>
  </main>
</template>

