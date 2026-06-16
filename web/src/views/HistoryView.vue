<script setup>
import { computed, onMounted, ref } from 'vue'
import { ElMessage } from 'element-plus'

import api from '../api/client'
import MarkdownReport from '../components/MarkdownReport.vue'

const tasks = ref([])
const selected = ref(null)
const loading = ref(false)
const detailVisible = ref(false)
const moduleFilter = ref('')
const dateFilter = ref('all')
const keyword = ref('')
const page = ref(1)
const pageSize = 8

const moduleName = {
  'side-channel': '侧信道',
  payload: '载荷检测',
  motion: '运动建模',
  papb: 'PAPB流程',
}

const filteredTasks = computed(() => {
  const now = Date.now()
  return tasks.value.filter((item) => {
    if (moduleFilter.value && item.module !== moduleFilter.value) return false
    const text = `${item.title} ${item.module}`.toLowerCase()
    if (keyword.value && !text.includes(keyword.value.toLowerCase())) return false
    if (dateFilter.value !== 'all') {
      const days = Number(dateFilter.value)
      const created = new Date(item.created_at).getTime()
      if (now - created > days * 86400000) return false
    }
    return true
  })
})

const pageTasks = computed(() => {
  const start = (page.value - 1) * pageSize
  return filteredTasks.value.slice(start, start + pageSize)
})

const formatTime = (value) => value ? new Date(value).toLocaleString() : '-'

const riskLevel = (task) => {
  const s = task.summary || {}
  if (task.module === 'papb') {
    if (s.status === 'ANOMALY') return '高风险'
    if (s.status === 'UNKNOWN_VALIDITY') return '待确认'
    return '正常'
  }
  const ratio = Number(s.high_or_critical_ratio ?? s.ratio ?? 0)
  const invalid = Number(s.invalid_transition_count || 0)
  if (ratio >= 0.15 || invalid > 0) return '高风险'
  if (ratio >= 0.05 || Number(s.abnormal || 0) > 0) return '待确认'
  return '正常'
}

const taskMetricText = (task) => {
  const s = task.summary || {}
  if (task.module === 'papb') {
    return `${s.action_count ?? '-'} 个动作 · ${s.status || 'UNKNOWN'}`
  }
  const count = s.total ?? s.processed_packets ?? s.transition_count ?? '-'
  return `${count} 条记录`
}

const loadTasks = async () => {
  loading.value = true
  try {
    const { data } = await api.get('/api/tasks')
    tasks.value = data.tasks || []
  } catch {
    ElMessage.error('历史记录加载失败')
  } finally {
    loading.value = false
  }
}

const openTask = async (task) => {
  try {
    const { data } = await api.get(`/api/tasks/${task.id}`)
    selected.value = data
    detailVisible.value = true
  } catch {
    ElMessage.error('任务详情加载失败')
  }
}

const exportJson = (task) => {
  const blob = new Blob([JSON.stringify(task, null, 2)], { type: 'application/json;charset=utf-8' })
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = `${task.id}_task.json`
  link.click()
  URL.revokeObjectURL(url)
}

const exportAll = () => exportJson({ exported_at: new Date().toISOString(), tasks: filteredTasks.value })

onMounted(loadTasks)
</script>

<template>
  <section class="panel fade-in">
    <div class="history-toolbar">
      <el-tabs v-model="moduleFilter" class="history-tabs">
        <el-tab-pane label="全部" name="" />
        <el-tab-pane label="侧信道" name="side-channel" />
        <el-tab-pane label="载荷检测" name="payload" />
        <el-tab-pane label="运动建模" name="motion" />
        <el-tab-pane label="PAPB流程" name="papb" />
      </el-tabs>
      <div class="history-filters">
        <el-select v-model="dateFilter" style="width: 132px;">
          <el-option label="全部时间" value="all" />
          <el-option label="最近一天" value="1" />
          <el-option label="最近7天" value="7" />
          <el-option label="最近30天" value="30" />
        </el-select>
        <el-input v-model="keyword" placeholder="搜索任务或模块" clearable style="width: 220px;" />
        <el-button @click="exportAll">导出全部</el-button>
      </div>
    </div>

    <div class="history-list" v-loading="loading">
      <div
        v-for="task in pageTasks"
        :key="task.id"
        class="history-row"
        :class="{ danger: riskLevel(task) === '高风险' }"
      >
        <span class="module-chip" :class="task.module">{{ moduleName[task.module] || task.module }}</span>
        <div class="history-main">
          <strong>{{ task.title }}</strong>
          <span>{{ formatTime(task.created_at) }} · {{ taskMetricText(task) }}</span>
        </div>
        <span class="risk-badge" :class="riskLevel(task)">{{ riskLevel(task) }}</span>
        <div class="history-actions">
          <el-button size="small" @click="openTask(task)">查看详情</el-button>
          <el-button size="small" @click="exportJson(task)">导出</el-button>
        </div>
      </div>
      <div v-if="!pageTasks.length" class="empty-state">暂无符合条件的任务记录</div>
    </div>

    <div class="history-pagination">
      <span>共 {{ filteredTasks.length }} 条</span>
      <el-pagination
        v-model:current-page="page"
        layout="prev, pager, next"
        :page-size="pageSize"
        :total="filteredTasks.length"
      />
    </div>
  </section>

  <el-dialog v-model="detailVisible" title="任务详情" width="860px">
    <template v-if="selected">
      <div class="task-detail-grid">
        <div><strong>任务编号</strong><span>{{ selected.id }}</span></div>
        <div><strong>模块</strong><span>{{ moduleName[selected.module] || selected.module }}</span></div>
        <div><strong>创建时间</strong><span>{{ formatTime(selected.created_at) }}</span></div>
      </div>
      <h3 class="detail-title">摘要</h3>
      <pre class="json-preview">{{ JSON.stringify(selected.summary, null, 2) }}</pre>
      <h3 class="detail-title">完整结果</h3>
      <pre class="json-preview">{{ JSON.stringify(selected.result, null, 2) }}</pre>
      <h3 class="detail-title">AI 报告</h3>
      <MarkdownReport v-if="selected.ai_report" :content="selected.ai_report" />
      <div v-else class="empty-state">该任务还没有生成 AI 报告</div>
    </template>
    <template #footer>
      <el-button @click="detailVisible = false">关闭</el-button>
      <el-button v-if="selected" type="primary" @click="exportJson(selected)">导出任务 JSON</el-button>
    </template>
  </el-dialog>
</template>
