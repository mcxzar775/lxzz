<script setup lang="ts">
import { computed } from 'vue'

import { useAuthStore } from '../stores/auth'

withDefaults(
  defineProps<{
    safetyTitle?: string
    safetyText?: string
  }>(),
  {
    safetyTitle: '安全开发模式',
    safetyText: '宿主机网络未被修改',
  },
)

const auth = useAuthStore()
const canAudit = computed(() => auth.permissions.includes('audit:read'))
const canAdminister = computed(
  () => auth.permissions.includes('users:manage') || auth.permissions.includes('settings:manage'),
)
</script>

<template>
  <aside class="sidebar">
    <div class="sidebar-brand">
      <div class="brand-mark compact" aria-hidden="true"><span></span><span></span><span></span></div>
      <div><strong>VPNGate</strong><small>Multi-Exit Manager</small></div>
    </div>
    <nav aria-label="主导航">
      <router-link class="nav-item" active-class="active" exact-active-class="active" to="/"><span>01</span>运行概览</router-link>
      <router-link class="nav-item" active-class="active" to="/nodes"><span>02</span>节点管理</router-link>
      <router-link class="nav-item" active-class="active" to="/connections"><span>03</span>连接管理</router-link>
      <router-link class="nav-item" active-class="active" to="/unlock"><span>04</span>解锁检测</router-link>
      <router-link v-if="canAudit" class="nav-item" active-class="active" to="/logs"><span>05</span>日志中心</router-link>
      <router-link v-if="canAdminister" class="nav-item" active-class="active" to="/administration"><span>06</span>用户与设置</router-link>
    </nav>
    <div class="sidebar-safety">
      <span class="status-dot"></span>
      <div><strong>{{ safetyTitle }}</strong><small>{{ safetyText }}</small></div>
    </div>
  </aside>
</template>
