<script setup>
import { computed, onBeforeUnmount, onMounted, provide, reactive, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import zhCn from 'element-plus/es/locale/lang/zh-cn'

import api from './api/client'
import { errorText } from './lib/http-error'

const route = useRoute()
const router = useRouter()
const isEntry = computed(() => route.name === 'home')
const authVisible = ref(false)
const authMode = ref('login')
const authLoading = ref(false)
const authError = ref('')
const auth = reactive({ user: null })
const authForm = reactive({
  login: '',
  username: '',
  email: '',
  password: '',
  confirm_password: '',
  remember: true,
})

provide('auth', auth)
provide('openAuth', (mode = 'login') => {
  authMode.value = mode
  authError.value = ''
  authVisible.value = true
})

const userInitial = computed(() => {
  const name = auth.user?.display_name || auth.user?.username || 'U'
  return name.slice(0, 1).toUpperCase()
})

// 后端健康状态：'checking' | 'online' | 'offline'，由轮询 /health 真实反映。
const serverStatus = ref('checking')
const statusText = computed(() => ({ online: '服务在线', offline: '服务离线', checking: '检测中' }[serverStatus.value]))
const apiHost = computed(() => (api.defaults.baseURL || '').replace(/^https?:\/\//, '') || '本地服务')

let healthTimer = null
const checkHealth = async () => {
  try {
    await api.get('/health', { timeout: 5000 })
    serverStatus.value = 'online'
  } catch {
    serverStatus.value = 'offline'
  }
}

const loadMe = async () => {
  if (!localStorage.getItem('rss_token')) return
  try {
    const { data } = await api.get('/api/auth/me')
    auth.user = data.user
  } catch {
    localStorage.removeItem('rss_token')
    auth.user = null
  }
}

const validateAuth = () => {
  if (authMode.value === 'login') {
    if (!authForm.login.trim()) return '请输入用户名或邮箱。'
    if (!authForm.password) return '请输入密码。'
    return ''
  }
  if (!authForm.username.trim()) return '请输入用户名。'
  if (!/^[\u4e00-\u9fa5A-Za-z0-9_-]{2,32}$/.test(authForm.username.trim())) return '用户名支持中英文、数字、下划线和短横线，长度 2-32。'
  if (!authForm.email.trim()) return '请输入邮箱。'
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(authForm.email.trim())) return '邮箱格式不正确。'
  if (authForm.password.length < 8) return '密码至少 8 位。'
  if (!/[A-Za-z]/.test(authForm.password) || !/\d/.test(authForm.password)) return '密码需要同时包含字母和数字。'
  if (authForm.password !== authForm.confirm_password) return '两次输入的密码不一致。'
  return ''
}

const submitAuth = async () => {
  authError.value = ''
  const validation = validateAuth()
  if (validation) {
    authError.value = validation
    return
  }
  authLoading.value = true
  try {
    const endpoint = authMode.value === 'login' ? '/api/auth/login' : '/api/auth/register'
    const payload = authMode.value === 'login'
      ? { login: authForm.login, password: authForm.password, remember: authForm.remember }
      : {
          username: authForm.username,
          email: authForm.email,
          password: authForm.password,
          confirm_password: authForm.confirm_password,
        }
    const { data } = await api.post(endpoint, payload)
    localStorage.setItem('rss_token', data.token)
    auth.user = data.user
    authVisible.value = false
    ElMessage.success(authMode.value === 'login' ? '已登录' : '注册完成')
  } catch (error) {
    authError.value = errorText(error)
  } finally {
    authLoading.value = false
  }
}

const logout = async () => {
  try {
    await api.post('/api/auth/logout')
  } finally {
    localStorage.removeItem('rss_token')
    auth.user = null
    if (route.meta.requiresAuth) router.push('/side-channel')
  }
}

onMounted(() => {
  loadMe()
  checkHealth()
  healthTimer = setInterval(checkHealth, 20000)
})

onBeforeUnmount(() => {
  if (healthTimer) clearInterval(healthTimer)
})
</script>

<template>
  <el-config-provider :locale="zhCn">
  <RouterView v-if="isEntry" />

  <div v-else class="workbench-shell">
    <aside class="console-sidebar">
      <RouterLink class="sidebar-brand" to="/">
        <span class="brand-mark">R</span>
        <span>
          <strong>机器人安全审计</strong>
          <small>Robot Security System</small>
        </span>
      </RouterLink>

      <nav class="sidebar-nav">
        <RouterLink to="/side-channel">侧信道分析</RouterLink>
        <RouterLink to="/payload">载荷检测</RouterLink>
        <RouterLink to="/motion">动作序列</RouterLink>
        <RouterLink to="/papb">PAPB 校验</RouterLink>
        <RouterLink to="/history">审计历史</RouterLink>
        <RouterLink to="/profile">账户设置</RouterLink>
      </nav>
    </aside>

    <main class="workbench-main">
      <div class="page-heading">
        <div>
          <h1>{{ route.meta.title || '机器人网络安全审计' }}</h1>
        </div>

        <div class="page-actions">
          <div class="sidebar-status" :class="`is-${serverStatus}`">
            {{ statusText }} · <strong>{{ apiHost }}</strong>
          </div>

          <el-dropdown v-if="auth.user" trigger="click">
            <button class="account-button" type="button">
              <span class="avatar">{{ userInitial }}</span>
              <span>{{ auth.user.display_name || auth.user.username }}</span>
            </button>
            <template #dropdown>
              <el-dropdown-menu>
                <el-dropdown-item @click="router.push('/profile')">账户设置</el-dropdown-item>
                <el-dropdown-item @click="router.push('/history')">审计历史</el-dropdown-item>
                <el-dropdown-item divided @click="logout">退出登录</el-dropdown-item>
              </el-dropdown-menu>
            </template>
          </el-dropdown>

          <div v-else class="topbar-auth">
            <button type="button" class="text-login" @click="authMode = 'login'; authVisible = true">登录</button>
            <el-button type="primary" @click="authMode = 'register'; authVisible = true">注册</el-button>
          </div>
        </div>
      </div>

      <RouterView />
    </main>
  </div>

  <el-dialog v-model="authVisible" width="420px" class="auth-dialog" :show-close="false">
    <div class="auth-head">
      <div>
        <h2>{{ authMode === 'login' ? '登录' : '注册' }}</h2>
        <p>{{ authMode === 'login' ? '进入本地审计控制台' : '创建一个审计账户' }}</p>
      </div>
      <button type="button" aria-label="关闭" @click="authVisible = false">×</button>
    </div>

    <div class="auth-tabs">
      <button :class="{ active: authMode === 'login' }" type="button" @click="authMode = 'login'">登录</button>
      <button :class="{ active: authMode === 'register' }" type="button" @click="authMode = 'register'">注册</button>
    </div>

    <div v-if="authMode === 'login'" class="auth-form">
      <label class="auth-field">
        <span>用户名或邮箱</span>
        <el-input v-model="authForm.login" placeholder="name@example.com" />
      </label>
      <label class="auth-field">
        <span>密码</span>
        <el-input v-model="authForm.password" placeholder="请输入密码" type="password" show-password />
      </label>
      <div class="auth-options">
        <el-checkbox v-model="authForm.remember">保持登录</el-checkbox>
      </div>
      <p v-if="authError" class="auth-error">{{ authError }}</p>
      <el-button type="primary" :loading="authLoading" class="full-button" @click="submitAuth">登录</el-button>
    </div>

    <div v-else class="auth-form">
      <label class="auth-field">
        <span>用户名</span>
        <el-input v-model="authForm.username" placeholder="2-32 位，中英文或数字" />
      </label>
      <label class="auth-field">
        <span>邮箱</span>
        <el-input v-model="authForm.email" placeholder="name@example.com" />
      </label>
      <label class="auth-field">
        <span>密码</span>
        <el-input v-model="authForm.password" placeholder="至少 8 位，包含字母和数字" type="password" show-password />
      </label>
      <label class="auth-field">
        <span>确认密码</span>
        <el-input v-model="authForm.confirm_password" placeholder="再次输入密码" type="password" show-password />
      </label>
      <p v-if="authError" class="auth-error">{{ authError }}</p>
      <el-button type="primary" :loading="authLoading" class="full-button" @click="submitAuth">注册</el-button>
    </div>
  </el-dialog>
  </el-config-provider>
</template>
