<script setup>
import { computed, onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'

import api from '../api/client'
import { formatTime } from '../lib/format'

const router = useRouter()
const loading = ref(false)
const saving = ref(false)
const emailNotice = ref(true)
const profile = ref({
  username: '',
  email: '',
  display_name: '',
  role: '',
  organization: '',
  bio: '',
  created_at: '',
  task_counts: {},
  total_tasks: 0,
  exported_reports: 0,
  high_alerts: 0,
})
const recentTasks = ref([])

const initials = computed(() => (profile.value.display_name || profile.value.username || 'U').slice(0, 1).toUpperCase())

const loadProfile = async () => {
  loading.value = true
  try {
    const [{ data: profileData }, { data: taskData }] = await Promise.all([
      api.get('/api/profile'),
      api.get('/api/tasks'),
    ])
    profile.value = profileData
    recentTasks.value = (taskData.tasks || []).slice(0, 5)
  } catch {
    ElMessage.error('个人主页加载失败，请确认已登录。')
  } finally {
    loading.value = false
  }
}

const saveProfile = async () => {
  saving.value = true
  try {
    const { data } = await api.put('/api/profile', {
      display_name: profile.value.display_name,
      role: profile.value.role,
      organization: profile.value.organization,
      bio: profile.value.bio,
    })
    profile.value = data
    ElMessage.success('个人资料已保存。')
  } catch {
    ElMessage.error('保存失败。')
  } finally {
    saving.value = false
  }
}

onMounted(loadProfile)
</script>

<template>
  <section class="profile-layout fade-in">
    <aside class="profile-identity panel">
      <button class="profile-avatar" type="button">{{ initials }}</button>
      <h2>{{ profile.display_name || profile.username }}</h2>
      <p>{{ profile.email }}</p>
      <span>注册于 {{ formatTime(profile.created_at) }}</span>
      <div class="profile-mini-stats">
        <div><strong>{{ profile.total_tasks || 0 }}</strong><span>分析</span></div>
        <div><strong>{{ profile.task_counts?.payload || 0 }}</strong><span>载荷</span></div>
        <div><strong>{{ profile.task_counts?.motion || 0 }}</strong><span>时序</span></div>
      </div>
    </aside>

    <section class="panel profile-editor">
      <div class="section-header">
        <div>
          <h2 class="section-title">资料设置</h2>
          <p class="panel-sub">用于报告归属、演示身份和历史记录筛选。</p>
        </div>
        <el-button type="primary" :loading="saving" @click="saveProfile">保存资料</el-button>
      </div>

      <div class="profile-form-grid">
        <label>
          <span>显示名称</span>
          <el-input v-model="profile.display_name" :disabled="loading" />
        </label>
        <label>
          <span>角色</span>
          <el-input v-model="profile.role" :disabled="loading" />
        </label>
        <label>
          <span>组织 / 队伍</span>
          <el-input v-model="profile.organization" :disabled="loading" />
        </label>
        <label>
          <span>用户名</span>
          <el-input v-model="profile.username" disabled />
        </label>
      </div>

      <label class="profile-bio">
        <span>个人说明</span>
        <el-input v-model="profile.bio" type="textarea" :rows="4" :disabled="loading" />
      </label>
    </section>
  </section>

  <section class="profile-lower-grid fade-in">
    <section class="panel">
      <div class="section-header">
        <h2 class="section-title">最近活动</h2>
        <el-button text @click="router.push('/history')">查看全部</el-button>
      </div>
      <div class="activity-list compact">
        <div v-for="task in recentTasks" :key="task.id" class="activity-row">
          <span>{{ formatTime(task.created_at) }}</span>
          <strong>{{ task.title }}</strong>
          <em>{{ task.module }}</em>
        </div>
        <div v-if="!recentTasks.length" class="empty-state">暂无活动记录。</div>
      </div>
    </section>

    <section class="panel">
      <h2 class="section-title">账户设置</h2>
      <div class="settings-list refined">
        <div class="setting-row">
          <span>告警邮件通知</span>
          <el-switch v-model="emailNotice" />
        </div>
      </div>
    </section>
  </section>
</template>
