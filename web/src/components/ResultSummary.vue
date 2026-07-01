<script setup>
import { CopyDocument } from '@element-plus/icons-vue'

import RiskBadge from './RiskBadge.vue'

defineProps({
  status: { type: String, default: 'PENDING' },
  title: { type: String, required: true },
  description: { type: String, default: '' },
  advice: { type: String, default: '' },
  taskId: { type: [String, Number], default: '' },
  duration: { type: [String, Number], default: '' },
})

const copyTaskId = async (taskId) => {
  try {
    await navigator.clipboard.writeText(String(taskId))
    ElMessage.success('任务编号已复制')
  } catch {
    ElMessage.warning('无法自动复制，请手动选择任务编号')
  }
}
</script>

<template>
  <section class="result-summary-bar" :data-status="String(status).toLowerCase()">
    <div class="result-summary-status"><RiskBadge :status="status" size="large" /></div>
    <div class="result-summary-copy">
      <strong>{{ title }}</strong>
      <p>{{ description }}</p>
      <span v-if="advice">下一步：{{ advice }}</span>
    </div>
    <div v-if="taskId || duration" class="result-summary-meta">
      <span v-if="duration"><small>检测耗时</small><strong>{{ duration }}</strong></span>
      <span v-if="taskId">
        <small>任务编号</small>
        <strong class="task-id-value">{{ taskId }}<el-button text :icon="CopyDocument" aria-label="复制任务编号" @click="copyTaskId(taskId)" /></strong>
      </span>
    </div>
    <div v-if="$slots.actions" class="result-summary-actions"><slot name="actions" /></div>
  </section>
</template>
