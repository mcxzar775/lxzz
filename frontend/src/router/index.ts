import { createRouter, createWebHistory } from 'vue-router'

import { useAuthStore } from '../stores/auth'
import DashboardView from '../views/DashboardView.vue'
import AdministrationView from '../views/AdministrationView.vue'
import ConnectionsView from '../views/ConnectionsView.vue'
import LoginView from '../views/LoginView.vue'
import LogsView from '../views/LogsView.vue'
import NodesView from '../views/NodesView.vue'
import UnlockView from '../views/UnlockView.vue'

const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/login', name: 'login', component: LoginView, meta: { guest: true } },
    { path: '/', name: 'dashboard', component: DashboardView, meta: { auth: true } },
    { path: '/nodes', name: 'nodes', component: NodesView, meta: { auth: true } },
    { path: '/connections', name: 'connections', component: ConnectionsView, meta: { auth: true } },
    { path: '/unlock', name: 'unlock', component: UnlockView, meta: { auth: true } },
    { path: '/logs', name: 'logs', component: LogsView, meta: { auth: true, permission: 'audit:read' } },
    { path: '/administration', name: 'administration', component: AdministrationView, meta: { auth: true, permission: 'settings:manage' } },
    { path: '/:pathMatch(.*)*', redirect: '/' },
  ],
})

router.beforeEach(async (to) => {
  const auth = useAuthStore()
  if (!auth.initialized) {
    await auth.fetchMe()
  }
  if (to.meta.auth && !auth.isAuthenticated) {
    return { name: 'login', query: { redirect: to.fullPath } }
  }
  if (to.meta.guest && auth.isAuthenticated) {
    return { name: 'dashboard' }
  }
  if (
    typeof to.meta.permission === 'string'
    && !auth.permissions.includes(to.meta.permission)
  ) {
    return { name: 'dashboard' }
  }
  return true
})

export default router
