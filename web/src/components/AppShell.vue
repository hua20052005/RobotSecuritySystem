<script setup>
import { useRoute } from 'vue-router'
import {
  Clock,
  Connection,
  Cpu,
  DataAnalysis,
  DocumentChecked,
  HomeFilled,
  Lock,
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
  { to: '/side-channel', label: '侧信道分析', icon: DataAnalysis },
  { to: '/payload', label: '载荷检测', icon: Lock },
  { to: '/motion', label: '动作序列分析', icon: Connection },
]
const accountItems = [
  { to: '/history', label: '审计历史', icon: Clock },
  { to: '/profile', label: '账户设置', icon: User },
]
</script>

<template>
  <div class="workbench-shell">
    <aside class="console-sidebar">
      <RouterLink class="sidebar-brand" to="/">
        <span class="brand-mark"><el-icon><Cpu /></el-icon></span>
        <span><strong>RobotSec</strong><small>机器人安全审计</small></span>
      </RouterLink>

      <nav class="sidebar-nav">
        <span class="sidebar-label">系统</span>
        <RouterLink to="/"><el-icon><HomeFilled /></el-icon><span>系统总览</span></RouterLink>
        <span class="sidebar-label">分析工作台</span>
        <RouterLink v-for="item in analysisItems" :key="item.to" :to="item.to">
          <el-icon><component :is="item.icon" /></el-icon><span>{{ item.label }}</span>
        </RouterLink>
        <span class="sidebar-label sidebar-label-spaced">审计与账户</span>
        <RouterLink v-for="item in accountItems" :key="item.to" :to="item.to">
          <el-icon><component :is="item.icon" /></el-icon><span>{{ item.label }}</span>
        </RouterLink>
      </nav>

      <div class="sidebar-foot">
        <DocumentChecked />
        <span><strong>本地审计模式</strong><small>证据仅保存在当前设备</small></span>
      </div>
    </aside>

    <main class="workbench-main">
      <PageHeader
        :title="route.meta.title || '机器人网络安全审计'"
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
