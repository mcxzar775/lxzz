import { computed, ref } from 'vue'
import { defineStore } from 'pinia'

import { apiRequest } from '../api/http'
import type { AuthResponse, User } from '../types/api'

export const useAuthStore = defineStore('auth', () => {
  const user = ref<User | null>(null)
  const permissions = ref<string[]>([])
  const initialized = ref(false)
  const isAuthenticated = computed(() => user.value !== null)

  function applyAuth(auth: AuthResponse): void {
    user.value = auth.user
    permissions.value = auth.permissions
    initialized.value = true
  }

  async function login(username: string, password: string, rememberMe: boolean): Promise<void> {
    const auth = await apiRequest<AuthResponse>('/api/v1/auth/login', {
      method: 'POST',
      body: JSON.stringify({ username, password, remember_me: rememberMe }),
    })
    applyAuth(auth)
  }

  async function fetchMe(): Promise<boolean> {
    try {
      applyAuth(await apiRequest<AuthResponse>('/api/v1/auth/me'))
      return true
    } catch {
      user.value = null
      permissions.value = []
      initialized.value = true
      return false
    }
  }

  async function logout(): Promise<void> {
    try {
      await apiRequest<void>('/api/v1/auth/logout', { method: 'POST' })
    } finally {
      user.value = null
      permissions.value = []
      initialized.value = true
    }
  }

  return { user, permissions, initialized, isAuthenticated, login, fetchMe, logout }
})

