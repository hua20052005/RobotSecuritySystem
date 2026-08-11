<script setup>
import { computed, nextTick, reactive, ref } from 'vue'
import { useRouter } from 'vue-router'
import { Connection, DataAnalysis, Lock } from '@element-plus/icons-vue'

import api from '../api/client'
import JsonViewer from '../components/JsonViewer.vue'
import MetricCard from '../components/MetricCard.vue'
import ModuleHero from '../components/ModuleHero.vue'
import ResultSummary from '../components/ResultSummary.vue'
import RiskBadge from '../components/RiskBadge.vue'
import SectionBlock from '../components/SectionBlock.vue'
import UploadPanel from '../components/UploadPanel.vue'
import { useSingleUpload } from '../composables/useSingleUpload'

const router = useRouter()
const { fileList, selectedFile, handleChange, handleRemove } = useSingleUpload()
const payloadMode = ref('packet')
const scenario = ref('general')
const running = ref(false)
const resultReady = ref(false)
const activeTab = ref('overview')
const resultRef = ref(null)
const elapsedMs = ref(0)
const taskId = ref('')

const enabled = reactive({ side: true, payload: true, motion: true })
const states = reactive({
  side: { state: 'PENDING', result: null, error: '', technicalError: '', elapsed: 0 },
  payload: { state: 'PENDING', result: null, error: '', technicalError: '', elapsed: 0 },
  motion: { state: 'PENDING', result: null, error: '', technicalError: '', elapsed: 0 },
})

const dimensions = [
  { key: 'side', label: '侧信道', description: '连接与元数据', icon: DataAnalysis },
  { key: 'payload', label: '加密表征检测', description: '内容模式与语义表征', icon: Lock },
  { key: 'motion', label: '动作时序', description: '行为与流程', icon: Connection },
]

const selectedCount = computed(() => Object.values(enabled).filter(Boolean).length)
const errorCount = computed(() => dimensions.filter((item) => states[item.key].state === 'ERROR').length)
const completedCount = computed(() =>
  dimensions.filter((item) => ['DONE', 'ERROR'].includes(states[item.key].state)).length,
)

const sideStatus = computed(() => {
  const ratio = Number(states.side.result?.summary?.ratio || 0)
  if (ratio >= 0.15) return 'ANOMALY'
  if (ratio >= 0.05) return 'TOLERATED'
  if (ratio > 0) return 'UNKNOWN'
  return 'NORMAL'
})

const payloadStatus = computed(() => {
  const ratio = Number(states.payload.result?.abnormal_ratio || 0)
  if (ratio > 20) return 'ANOMALY'
  if (ratio > 5) return 'TOLERATED'
  if (ratio > 0) return 'UNKNOWN'
  return 'NORMAL'
})

const motionStatus = computed(() => states.motion.result?.summary?.flow_status || 'UNKNOWN')

const dimensionStatus = (key) => {
  if (!enabled[key]) return 'PENDING'
  if (states[key].state === 'RUNNING' || states[key].state === 'ERROR') return states[key].state
  return { side: sideStatus.value, payload: payloadStatus.value, motion: motionStatus.value }[key]
}

const overallStatus = computed(() => {
  if (running.value) return 'RUNNING'
  if (!resultReady.value) return 'PENDING'
  const statuses = dimensions.filter((item) => enabled[item.key]).map((item) => dimensionStatus(item.key))
  if (statuses.every((status) => status === 'ERROR')) return 'ERROR'
  if (statuses.some((status) => status === 'ANOMALY')) return 'ANOMALY'
  if (statuses.some((status) => status === 'ERROR')) return 'UNKNOWN'
  if (statuses.some((status) => ['UNKNOWN', 'UNKNOWN_VALIDITY'].includes(status))) return 'UNKNOWN'
  if (statuses.some((status) => ['TOLERATED', 'NORMAL_WITH_TOLERANCE'].includes(status))) return 'TOLERATED'
  return 'NORMAL'
})

const overallMeta = computed(() => ({
  PENDING: ['等待统一分析', '上传 PCAP 后，系统将并行完成三类检测并汇总风险结论。'],
  RUNNING: ['统一分析进行中', `正在完成 ${completedCount.value}/${selectedCount.value} 个检测维度。`],
  NORMAL: ['综合结论正常', '当前三类证据未发现明显异常，可继续查看分维证据。'],
  TOLERATED: ['存在轻微偏离', '部分检测结果出现可容忍偏离，建议结合场景复核。'],
  UNKNOWN: errorCount.value
    ? ['综合结论待确认', `${errorCount.value} 个检测维度未完成，已完成维度的结果仍会保留。`]
    : ['综合结论待确认', '检测结果存在不确定性，建议进入分维证据查看原始输出。'],
  ANOMALY: ['发现异常风险', '至少一个检测维度给出异常结论，建议进入防御控制台或查看分维证据。'],
  ERROR: ['统一分析失败', '所有检测维度均未完成，请检查后端服务、模型状态或输入文件。'],
})[overallStatus.value])

const dimensionSummary = computed(() => ({
  side: {
    primary: `${(Number(states.side.result?.summary?.ratio || 0) * 100).toFixed(2)}%`,
    secondary: `${states.side.result?.summary?.abnormal || 0} 个可疑流量片段`,
  },
  payload: {
    primary: `${Number(states.payload.result?.abnormal_ratio || 0).toFixed(2)}%`,
    secondary: `${states.payload.result?.low_confidence_count || 0} 个低置信度结果`,
  },
  motion: {
    primary: states.motion.result?.summary?.flow_status || '-',
    secondary: `${states.motion.result?.actions?.length || 0} 个动作片段`,
  },
}))

const unifiedJson = computed(() => ({
  task_id: taskId.value,
  generated_at: new Date().toISOString(),
  file: selectedFile.value ? { name: selectedFile.value.name, size: selectedFile.value.size } : null,
  overall_status: overallStatus.value,
  configuration: { enabled: { ...enabled }, payload_mode: payloadMode.value, scenario: scenario.value },
  dimensions: {
    side_channel: { status: dimensionStatus('side'), error: states.side.error || null, technical_error: states.side.technicalError || null, result: states.side.result },
    payload: { status: dimensionStatus('payload'), error: states.payload.error || null, technical_error: states.payload.technicalError || null, result: states.payload.result },
    motion: { status: dimensionStatus('motion'), error: states.motion.error || null, technical_error: states.motion.technicalError || null, result: states.motion.result },
  },
}))

const freshForm = () => {
  const data = new FormData()
  data.append('file', selectedFile.value)
  return data
}

const requestDimension = async (key) => {
  states[key].state = 'RUNNING'
  states[key].result = null
  states[key].error = ''
  states[key].technicalError = ''
  const startedAt = performance.now()
  try {
    let response
    if (key === 'side') {
      const data = freshForm()
      data.append('features', JSON.stringify(['size', 'interval', 'port']))
      data.append('contamination', '0.06')
      response = await api.post('/api/side-channel/analyze', data, { timeout: 600000 })
    } else if (key === 'payload') {
      const health = await api.get('/health', { timeout: 5000 })
      const payloadReady = health.data?.payload_available
        ?? health.data?.etbert_models?.[payloadMode.value]
        ?? health.data?.etbert_available
      if (!payloadReady) {
        throw new Error('加密表征检测模型或服务尚未就绪')
      }
      const data = freshForm()
      data.append('max_packets', '500')
      response = await api.post(`/api/etbert/detect/${payloadMode.value}`, data, { timeout: 600000 })
    } else {
      const data = freshForm()
      data.append('mode', 'sequence')
      data.append('method', 'command')
      data.append('validate_flow', 'true')
      data.append('scenario', scenario.value)
      data.append('min_segment_s', '0.25')
      data.append('step_s', '0.5')
      data.append('segment_penalty', '0.02')
      response = await api.post('/api/motion-recognition/recognize', data, { timeout: 600000 })
    }
    states[key].result = response.data
    states[key].state = 'DONE'
  } catch (error) {
    states[key].state = 'ERROR'
    const detail = error.response?.data?.detail || error.message || '检测失败'
    states[key].technicalError = typeof detail === 'string' ? detail : JSON.stringify(detail)
    states[key].error = key === 'payload'
      ? '加密表征检测暂不可用，已保留其他维度结果。'
      : `${dimensions.find((item) => item.key === key)?.label || '检测'}未完成`
  } finally {
    states[key].elapsed = Math.round(performance.now() - startedAt)
  }
}

const runUnified = async () => {
  if (!selectedFile.value) {
    ElMessage.warning('请先上传 PCAP 文件')
    return
  }
  if (!selectedCount.value) {
    ElMessage.warning('请至少选择一个检测维度')
    return
  }
  running.value = true
  resultReady.value = false
  activeTab.value = 'overview'
  taskId.value = `UA-${Date.now().toString(36).toUpperCase()}`
  dimensions.forEach(({ key }) => {
    states[key].state = 'PENDING'
    states[key].result = null
    states[key].error = ''
    states[key].technicalError = ''
    states[key].elapsed = 0
  })
  const startedAt = performance.now()
  await Promise.all(dimensions.filter((item) => enabled[item.key]).map((item) => requestDimension(item.key)))
  elapsedMs.value = Math.round(performance.now() - startedAt)
  running.value = false
  resultReady.value = true
  await nextTick()
  resultRef.value?.scrollIntoView({ behavior: 'smooth', block: 'start' })
  if (overallStatus.value === 'ANOMALY') ElMessage.error('统一分析发现异常风险')
  else if (overallStatus.value === 'UNKNOWN') ElMessage.warning('统一分析结果待确认')
  else ElMessage.success('统一分析完成')
}

const resetFile = () => {
  handleRemove()
  resultReady.value = false
}

const toggleDimension = (key) => {
  if (running.value) return
  enabled[key] = !enabled[key]
}
</script>

<template>
  <ModuleHero
    objective="从连接侧信道、加密流量表征和动作流程三个维度形成统一风险结论"
    input="一份机器人控制链路 PCAP"
    output="统一状态、分维指标与完整证据 JSON"
    scenario="比赛演示、现场排查与综合分析"
  />

  <SectionBlock title="统一检测入口" description="上传一次抓包，选择检测维度并并行运行。" class="fade-in">
    <div class="unified-entry-grid">
      <div>
        <UploadPanel
          :file-list="fileList"
          :selected-file="selectedFile"
          :disabled="running"
          @change="handleChange"
          @remove="resetFile"
        />
        <div class="unified-options">
          <label class="control-field">
            <span>加密表征检测粒度</span>
            <el-segmented v-model="payloadMode" :options="[{ label: '包级', value: 'packet' }, { label: '流级', value: 'flow' }]" />
          </label>
          <label class="control-field">
            <span>动作任务场景</span>
            <el-select v-model="scenario">
              <el-option label="自由操控 / 通用演示" value="general" />
              <el-option label="巡检任务" value="patrol" />
              <el-option label="人机交互" value="interaction" />
              <el-option label="性能展示" value="performance" />
            </el-select>
          </label>
        </div>
      </div>

      <div class="wheel-column">
        <div class="analysis-wheel" :class="{ 'is-running': running }">
          <button
            v-for="(item, index) in dimensions"
            :key="item.key"
            type="button"
            class="wheel-node"
            :class="[`node-${index + 1}`, { 'is-enabled': enabled[item.key], 'is-disabled': !enabled[item.key] }]"
            :disabled="running"
            @click="toggleDimension(item.key)"
          >
            <el-icon><component :is="item.icon" /></el-icon>
            <strong>{{ item.label }}</strong>
            <small>{{ item.description }}</small>
            <RiskBadge :status="states[item.key].state === 'DONE' ? dimensionStatus(item.key) : states[item.key].state" />
          </button>
          <div class="wheel-center">
            <strong>{{ running ? `${completedCount}/${selectedCount}` : selectedCount }}</strong>
            <span>{{ running ? '检测中' : '检测维度' }}</span>
          </div>
        </div>
        <el-button type="primary" size="large" :loading="running" :disabled="!selectedFile || !selectedCount || running" @click="runUnified">
          {{ running ? '统一分析中...' : '开始三维统一分析' }}
        </el-button>
      </div>
    </div>
  </SectionBlock>

  <div v-if="!resultReady && !running" class="result-placeholder">
    三个维度会并行运行；某一维失败时，已完成维度的结果仍会正常保留。
  </div>

  <template v-if="resultReady || running">
    <div ref="resultRef">
      <ResultSummary
        :status="overallStatus"
        :title="overallMeta[0]"
        :description="overallMeta[1]"
        :advice="errorCount ? '部分维度未完成，请结合分维证据复核。' : overallStatus === 'ANOMALY' ? '建议进入防御控制台或查看异常维度原始证据。' : '可进入单项模块查看更详细的检测证据。'"
        :task-id="taskId"
        :duration="running ? '运行中' : `${(elapsedMs / 1000).toFixed(2)} s`"
      />
    </div>

    <div class="grid-3 unified-metrics">
      <MetricCard
        v-for="item in dimensions"
        :key="item.key"
        :title="item.label"
        :value="enabled[item.key] ? dimensionSummary[item.key].primary : '未启用'"
        :subtitle="states[item.key].error || dimensionSummary[item.key].secondary"
      />
    </div>

    <SectionBlock v-if="resultReady" title="统一分析结果" description="从综合结论进入每个检测维度的摘要与原始证据。" class="fade-in">
      <el-tabs v-model="activeTab" class="audit-tabs">
        <el-tab-pane label="综合概览" name="overview">
          <div class="dimension-result-list">
            <article v-for="item in dimensions" :key="item.key" :class="{ 'is-muted': !enabled[item.key] }">
              <el-icon><component :is="item.icon" /></el-icon>
              <div>
                <strong>{{ item.label }}</strong>
                <span>{{ states[item.key].error || dimensionSummary[item.key].secondary }}</span>
              </div>
              <RiskBadge :status="enabled[item.key] ? dimensionStatus(item.key) : 'PENDING'" />
              <el-button text :disabled="!states[item.key].result" @click="router.push({ side: '/side-channel', payload: '/payload', motion: '/motion' }[item.key])">
                打开单项模块
              </el-button>
            </article>
          </div>
        </el-tab-pane>
        <el-tab-pane label="分维证据" name="evidence">
          <el-collapse class="dimension-evidence">
            <el-collapse-item v-for="item in dimensions" :key="item.key" :name="item.key">
              <template #title>
                <span class="evidence-title">{{ item.label }} <RiskBadge :status="dimensionStatus(item.key)" /></span>
              </template>
              <JsonViewer
                v-if="states[item.key].result"
                :data="states[item.key].result"
                :filename="`${taskId}-${item.key}.json`"
                :title="`${item.label}原始证据`"
              />
              <p v-else class="inline-warning">{{ states[item.key].error || '该维度未启用' }}</p>
            </el-collapse-item>
          </el-collapse>
        </el-tab-pane>
        <el-tab-pane label="统一 JSON" name="json">
          <JsonViewer :data="unifiedJson" :filename="`${taskId || 'unified_analysis'}.json`" title="三维统一分析结果" />
        </el-tab-pane>
      </el-tabs>
    </SectionBlock>
  </template>
</template>

<style scoped>
.unified-entry-grid {
  display: grid;
  grid-template-columns: minmax(0, 1.1fr) minmax(390px, 0.9fr);
  gap: 36px;
  align-items: center;
}

.unified-options {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 14px;
  margin-top: 16px;
}

.wheel-column {
  display: grid;
  justify-items: center;
  gap: 14px;
}

.analysis-wheel {
  position: relative;
  width: 360px;
  height: 330px;
}

.analysis-wheel::before,
.analysis-wheel::after {
  content: '';
  position: absolute;
  border-radius: 50%;
  pointer-events: none;
}

.analysis-wheel::before {
  inset: 35px 50px 35px;
  border: 1px solid #c0dade;
  background: linear-gradient(135deg, rgba(222, 237, 220, 0.44), rgba(192, 218, 222, 0.28));
}

.analysis-wheel::after {
  inset: 92px 108px;
  border: 1px dashed #aecfd1;
}

.wheel-node {
  position: absolute;
  z-index: 2;
  width: 138px;
  min-height: 94px;
  display: grid;
  grid-template-columns: 24px minmax(0, 1fr);
  gap: 2px 7px;
  align-items: center;
  padding: 11px;
  border: 1px solid var(--line);
  border-radius: 7px;
  background: white;
  color: var(--muted);
  text-align: left;
  cursor: pointer;
  box-shadow: 0 12px 26px rgba(119, 181, 180, 0.12);
}

.wheel-node.is-enabled {
  border-color: #aecfd1;
  color: #77b5b4;
}

.wheel-node.is-disabled {
  opacity: 0.5;
  box-shadow: none;
}

.wheel-node > .el-icon {
  grid-row: 1 / span 2;
  font-size: 22px;
}

.wheel-node strong {
  color: var(--ink);
  font-size: 13px;
}

.wheel-node small {
  color: var(--muted);
  font-size: 10px;
}

.wheel-node .risk-status {
  grid-column: 1 / -1;
  width: max-content;
  margin-top: 5px;
}

.node-1 { top: 0; left: 111px; }
.node-2 { right: 0; bottom: 18px; }
.node-3 { bottom: 18px; left: 0; }

.wheel-center {
  position: absolute;
  z-index: 1;
  top: 118px;
  left: 137px;
  width: 86px;
  height: 86px;
  display: grid;
  place-content: center;
  border: 1px solid #aecfd1;
  border-radius: 50%;
  background: white;
  color: #77b5b4;
  text-align: center;
  box-shadow: 0 12px 28px rgba(119, 181, 180, 0.16);
}

.wheel-center strong {
  font-size: 24px;
}

.wheel-center span {
  color: var(--muted);
  font-size: 10px;
}

.unified-metrics {
  margin-top: -7px;
}

.dimension-result-list {
  display: grid;
}

.dimension-result-list article {
  display: grid;
  grid-template-columns: 36px minmax(0, 1fr) auto auto;
  gap: 12px;
  align-items: center;
  padding: 15px 0;
  border-bottom: 1px solid var(--line-soft);
}

.dimension-result-list article:last-child {
  border-bottom: 0;
}

.dimension-result-list article > .el-icon {
  color: #77b5b4;
  font-size: 22px;
}

.dimension-result-list article > div {
  display: grid;
  gap: 3px;
}

.dimension-result-list article span {
  color: var(--muted);
  font-size: 11px;
}

.dimension-result-list article.is-muted {
  opacity: 0.55;
}

.evidence-title {
  display: inline-flex;
  align-items: center;
  gap: 10px;
}

.unified-entry-grid :deep(.el-segmented__item.is-selected) {
  background: #77b5b4 !important;
  color: #ffffff !important;
}

@media (max-width: 900px) {
  .unified-entry-grid {
    grid-template-columns: 1fr;
  }
}

@media (max-width: 520px) {
  .unified-options {
    grid-template-columns: 1fr;
  }

  .analysis-wheel {
    width: 330px;
    transform: scale(0.92);
  }

  .node-1 { left: 96px; }

  .wheel-center {
    left: 122px;
  }
}
</style>