<script setup>
import { computed, ref } from 'vue'
import { ElMessage } from 'element-plus'

import api from '../api/client'
import MarkdownReport from '../components/MarkdownReport.vue'
import MetricCard from '../components/MetricCard.vue'

const windowMs = ref(100)
const clusters = ref(8)
const maxTemplates = ref(2)
const minSupport = ref(2)
const diversity = ref(0.85)
const taskSequences = ref('task_sequences_example.json')
const includePorts = ref('')
const excludePorts = ref('22')
const loading = ref(false)
const reportLoading = ref(false)
const result = ref(null)
const aiReport = ref('')
const reportDialogVisible = ref(false)

const joinUrl = (base, path) => {
  const cleanBase = base?.replace(/\/$/, '') || ''
  return `${cleanBase}${path}`
}

const downloadImage = computed(() => {
  if (!result.value?.download_image_url) return ''
  return joinUrl(api.defaults.baseURL, result.value.download_image_url)
})

const downloadMarkdown = computed(() => {
  if (!result.value?.download_markdown_url) return ''
  return joinUrl(api.defaults.baseURL, result.value.download_markdown_url)
})

const downloadTransitions = computed(() => {
  if (!result.value?.download_transitions_url) return ''
  return joinUrl(api.defaults.baseURL, result.value.download_transitions_url)
})

const consistencyRows = computed(() => {
  const scores = result.value?.temporal_consistency_score || {}
  return Object.entries(scores).map(([label, score]) => ({
    label,
    score: Number(score),
  }))
})

const downloadText = (filename, text) => {
  const blob = new Blob([text], { type: 'text/markdown;charset=utf-8' })
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = filename
  link.click()
  URL.revokeObjectURL(url)
}

const runAnalysis = async () => {
  loading.value = true
  result.value = null
  aiReport.value = ''

  const formData = new FormData()
  formData.append('window_ms', windowMs.value.toString())
  formData.append('clusters', clusters.value.toString())
  formData.append('max_templates_per_action', maxTemplates.value.toString())
  formData.append('min_template_support', minSupport.value.toString())
  formData.append('template_diversity_threshold', diversity.value.toString())
  formData.append('task_sequences', taskSequences.value.trim())
  formData.append('include_ports', includePorts.value.trim())
  formData.append('exclude_ports', excludePorts.value.trim())

  try {
    const { data } = await api.post('/api/motion/analyze', formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
    })
    result.value = data
  } catch (error) {
    ElMessage.error(error.response?.data?.detail?.message || error.response?.data?.detail || '运动时序建模失败，请检查后端日志。')
  } finally {
    loading.value = false
  }
}

const buildEvidence = () => {
  if (!result.value) return {}
  return {
    scene: 'motion_temporal_modeling',
    parameters: {
      window_ms: windowMs.value,
      clusters: clusters.value,
      max_templates_per_action: maxTemplates.value,
      min_template_support: minSupport.value,
      template_diversity_threshold: diversity.value,
      task_sequences: taskSequences.value || null,
      include_ports: includePorts.value || null,
      exclude_ports: excludePorts.value || null,
    },
    summary: result.value.summary,
    temporal_consistency_score: result.value.temporal_consistency_score,
    template_summary: result.value.template_summary,
    transition_preview: result.value.transition_preview?.slice(0, 20) || [],
  }
}

const generateReport = async () => {
  if (!result.value) return
  reportLoading.value = true
  try {
    const { data } = await api.post('/api/reports/generate', {
      scene: '运动时序建模',
      task_id: result.value.run_id || '',
      evidence: buildEvidence(),
    })
    aiReport.value = data.report || ''
    reportDialogVisible.value = true
  } catch (error) {
    ElMessage.error(error.response?.data?.detail || 'AI 报告生成失败，请检查后端配置。')
  } finally {
    reportLoading.value = false
  }
}
</script>

<template>
  <section class="panel fade-in">
    <div class="section-header">
      <div>
        <h2 class="section-title">运动时序建模</h2>
        <p class="panel-sub">基于动作 PCAP 样本构建符号序列模板，评估动作一致性、可分性与任务转移异常。</p>
      </div>
      <div class="pill-badge">Temporal Model</div>
    </div>

    <div class="grid-3" style="margin-top: 20px;">
      <div>
        <p class="panel-sub">时间窗口 ms</p>
        <el-input-number v-model="windowMs" :min="20" :max="5000" :step="20" />
      </div>
      <div>
        <p class="panel-sub">符号聚类数</p>
        <el-input-number v-model="clusters" :min="2" :max="26" :step="1" />
      </div>
      <div>
        <p class="panel-sub">每动作模板数</p>
        <el-input-number v-model="maxTemplates" :min="1" :max="8" :step="1" />
      </div>
      <div>
        <p class="panel-sub">最小模板支持</p>
        <el-input-number v-model="minSupport" :min="1" :max="20" :step="1" />
      </div>
      <div>
        <p class="panel-sub">模板多样性阈值</p>
        <el-slider v-model="diversity" :min="0.5" :max="0.99" :step="0.01" />
      </div>
      <div>
        <p class="panel-sub">任务序列文件</p>
        <el-input v-model="taskSequences" placeholder="task_sequences_example.json" />
      </div>
    </div>

    <div class="grid-2" style="margin-top: 18px;">
      <div>
        <p class="panel-sub">保留端口（可选）</p>
        <el-input v-model="includePorts" placeholder="例如 1883,8883" />
      </div>
      <div>
        <p class="panel-sub">排除端口</p>
        <el-input v-model="excludePorts" placeholder="默认 22" />
      </div>
    </div>

    <div class="action-row" style="margin-top: 20px;">
      <el-button type="primary" :loading="loading" @click="runAnalysis">开始时序建模</el-button>
      <span class="pill-badge">默认读取 motion/motion 下的动作样本</span>
    </div>
  </section>

  <section v-if="result" class="panel fade-in">
    <div class="section-header">
      <h2 class="section-title">模型指标</h2>
      <el-button :loading="reportLoading" @click="generateReport">生成 AI 报告</el-button>
    </div>
    <div class="grid-3" style="margin-top: 18px;">
      <MetricCard
        title="动作数量"
        :value="String(result.summary.action_count || 0)"
        subtitle="参与建模的动作类别"
      />
      <MetricCard
        title="最近邻准确率"
        :value="(Number(result.summary.nearest_neighbor_accuracy || 0) * 100).toFixed(2) + '%'"
        subtitle="动作序列可识别性"
      />
      <MetricCard
        title="模板留一准确率"
        :value="(Number(result.summary.leave_one_out_template_accuracy || 0) * 100).toFixed(2) + '%'"
        subtitle="模板泛化表现"
      />
      <MetricCard
        title="类内相似度"
        :value="Number(result.summary.mean_within_action_similarity || 0).toFixed(4)"
        subtitle="同动作稳定性"
      />
      <MetricCard
        title="类间相似度"
        :value="Number(result.summary.mean_between_action_similarity || 0).toFixed(4)"
        subtitle="不同动作混淆度"
      />
      <MetricCard
        title="可分性"
        :value="Number(result.summary.separability_score || 0).toFixed(4)"
        subtitle="类内减类间"
      />
    </div>
  </section>

  <section v-if="result" class="grid-2 fade-in">
    <div class="chart-card">
      <div class="chart-title">符号动作序列</div>
      <img v-if="downloadImage" :src="downloadImage" class="motion-image" alt="symbol sequences" />
    </div>
    <div class="chart-card">
      <div class="chart-title">动作一致性</div>
      <div class="data-table">
        <el-table :data="consistencyRows" height="260" stripe>
          <el-table-column prop="label" label="动作" />
          <el-table-column prop="score" label="一致性分数">
            <template #default="{ row }">{{ row.score.toFixed(4) }}</template>
          </el-table-column>
        </el-table>
      </div>
    </div>
  </section>

  <section v-if="result" class="panel fade-in">
    <div class="section-header">
      <h2 class="section-title">模板风险摘要</h2>
      <div class="action-row">
        <el-button v-if="downloadMarkdown" tag="a" :href="downloadMarkdown" target="_blank">下载建模报告</el-button>
        <el-button v-if="downloadTransitions" tag="a" :href="downloadTransitions" target="_blank">下载转移分数</el-button>
      </div>
    </div>
    <div class="data-table" style="margin-top: 16px;">
      <el-table :data="result.template_summary" height="300" stripe>
        <el-table-column prop="label" label="动作" min-width="120" />
        <el-table-column prop="mean_anomaly_score" label="平均异常分" min-width="140" />
        <el-table-column prop="max_anomaly_score" label="最高异常分" min-width="140" />
        <el-table-column prop="mean_margin_vs_other" label="类间边际" min-width="140" />
        <el-table-column prop="template_accuracy" label="模板准确率" min-width="140" />
      </el-table>
    </div>
  </section>

  <section v-if="result" class="panel fade-in">
    <div class="section-header">
      <h2 class="section-title">任务转移预览</h2>
      <span class="pill-badge">异常转移 {{ result.summary.invalid_transition_count || 0 }} 条</span>
    </div>
    <div class="data-table" style="margin-top: 16px;">
      <el-table :data="result.transition_preview" height="320" stripe>
        <el-table-column
          v-for="col in Object.keys(result.transition_preview?.[0] || {})"
          :key="col"
          :prop="col"
          :label="col"
          min-width="150"
          show-overflow-tooltip
        />
      </el-table>
    </div>
  </section>

  <section v-else-if="!result" class="empty-state fade-in">
    点击开始时序建模后展示动作模板、转移分数和异常摘要。
  </section>

  <el-dialog v-model="reportDialogVisible" title="AI 检测报告" width="760px">
    <MarkdownReport :content="aiReport" />
    <template #footer>
      <div class="action-row">
        <el-button @click="reportDialogVisible = false">关闭</el-button>
        <el-button type="primary" @click="downloadText('motion_ai_report.md', aiReport)">
          下载报告
        </el-button>
      </div>
    </template>
  </el-dialog>
</template>
