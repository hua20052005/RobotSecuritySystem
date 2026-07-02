<script setup>
import { useRoute } from 'vue-router'
import {
  Clock,
  Compass,
  Connection,
  DataAnalysis,
  DocumentChecked,
  HomeFilled,
  Lock,
  SetUp,
  User,
} from '@element-plus/icons-vue'

import PageHeader from './PageHeader.vue'

defineProps({
  serverStatus: { type: String, default: 'checking' },
  statusText: { type: String, default: '检测中' },
  apiHost: { type: String, default: '本地服务' },
})

const route = useRoute()
const analysisItems = [
  { to: '/unified-analysis', label: '三维统一分析', icon: Compass },
  { to: '/side-channel', label: '侧信道分析', icon: DataAnalysis },
  { to: '/payload', label: '加密表征检测', icon: Lock },
  { to: '/motion', label: '动作序列分析', icon: Connection },
]
const defenseItems = [
  { to: '/defense', label: '系统集成防御', icon: SetUp },
]
const accountItems = [
  { to: '/history', label: '检测记录', icon: Clock },
  { to: '/profile', label: '账户设置', icon: User },
]
</script>

<template>
  <div class="workbench-shell">
    <aside class="console-sidebar">
      <RouterLink class="sidebar-brand" to="/">
        <img class="brand-mark" src="/roboguard-mark.svg" alt="" />
        <span><strong>RoboGuard</strong><small>具身智能链路防御</small></span>
      </RouterLink>

      <nav class="sidebar-nav">
        <span class="sidebar-label">系统</span>
        <RouterLink to="/"><el-icon><HomeFilled /></el-icon><span>系统总览</span></RouterLink>
        <span class="sidebar-label">分析工作台</span>
        <RouterLink v-for="item in analysisItems" :key="item.to" :to="item.to">
          <el-icon><component :is="item.icon" /></el-icon><span>{{ item.label }}</span>
        </RouterLink>
        <span class="sidebar-label sidebar-label-spaced">主动防御</span>
        <RouterLink v-for="item in defenseItems" :key="item.to" :to="item.to">
          <el-icon><component :is="item.icon" /></el-icon><span>{{ item.label }}</span>
        </RouterLink>
        <span class="sidebar-label sidebar-label-spaced">记录与账户</span>
        <RouterLink v-for="item in accountItems" :key="item.to" :to="item.to">
          <el-icon><component :is="item.icon" /></el-icon><span>{{ item.label }}</span>
        </RouterLink>
      </nav>

      <div class="sidebar-foot">
        <DocumentChecked />
        <span><strong>本地分析模式</strong><small>检测证据保存在当前设备</small></span>
      </div>
    </aside>

    <main class="workbench-main">
      <PageHeader
        v-if="route.name !== 'defense'"
        :title="route.meta.title || 'RoboGuard 控制链路安全防御'"
        :description="route.meta.description || ''"
        :server-status="serverStatus"
        :status-text="statusText"
        :api-host="apiHost"
      >
        <template #account><slot name="account" /></template>
      </PageHeader>
      <slot />
    </main>
  </div>
</template>
