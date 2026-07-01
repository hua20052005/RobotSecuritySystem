<script setup>
import { computed, nextTick, ref } from 'vue'

import api from '../api/client'
import JsonViewer from '../components/JsonViewer.vue'
import MetricCard from '../components/MetricCard.vue'
import ModuleHero from '../components/ModuleHero.vue'
import ResultSummary from '../components/ResultSummary.vue'
import RiskBadge from '../components/RiskBadge.vue'
import SectionBlock from '../components/SectionBlock.vue'
import UploadPanel from '../components/UploadPanel.vue'
import { downloadJson } from '../lib/download'
import { errorText } from '../lib/http-error'
import { useSingleUpload } from '../composables/useSingleUpload'

const { fileList, selectedFile, handleChange, handleRemove } = useSingleUpload()
const loading = ref(false)
const result = ref(null)
const activeTab = ref('overview')
const errorMessage = ref('')
const elapsedMs = ref(0)
const resultRef = ref(null)

const method = ref('command')
const minSegmentS = ref(0.25)
const stepS = ref(0.5)
const segmentPenalty = ref(0.02)
const scenario = ref('general')

const methodOptions = [
  { label: '指令 + 摇杆融合（推荐）', value: 'command' },
  { label: 'DP 模板切分', value: 'dp' },
  { label: '活动片段检测', value: 'activity' },
  { label: '滑动窗口扫描', value: 'scan' },
]

const scenarioOptions = [
  { label: '自由操控 / 通用演示', value: 'general' },
  { label: '巡逻任务', value: 'patrol' },
  { label: '低冲击交互展示', value: 'interaction' },
  { label: '完整动作表演', value: 'performance' },
]

const actions = computed(() => result.value?.actions || [])
const flow = computed(() => result.value?.flow_validation || null)
const violations = computed(() => flow.value?.violations || [])
const transitions = computed(() => flow.value?.transition_check?.transitions || [])
const candidates = computed(() => flow.value?.candidate_matches || [])
const selectedFileName = computed(() => selectedFile.value?.name || '')
const segments = computed(() =>
  (result.value?.recognition?.actions || []).map((row, index) => {
    const start = Number(row.t_start_s ?? row.start_s ?? row.time_s ?? 0)
    const end = Number(row.t_end_s ?? row.end_s ?? row.time_s ?? start)
    const duration = Number(row.duration_s ?? Math.max(0, end - start))
    const source = row.source || (duration === 0 ? 'fixed_command' : 'model')
    const sourceText = {
      fixed_command: '固定指令',
      fixed_signature: '固定指令',
      joystick_0x30_0x31: '摇杆移动',
      model: '模型识别',
    }[source] || source
    return {
      ...row,
      rowId: `${row.label || 'action'}-${index}`,
      start,
      end,
      duration,
      sourceText,
      timeText: duration > 0.001
        ? `${start.toFixed(3)} - ${end.toFixed(3)}`
        : `${start.toFixed(3)}`,
      confidenceText: Number.isFinite(Number(row.confidence ?? row.score))
        ? Number(row.confidence ?? row.score).toFixed(3)
        : '-',
    }
  }),
)

const status = computed(() => result.value?.summary?.flow_status || 'NOT_RUN')
const statusMeta = computed(() => {
  if (status.value === 'ANOMALY') return { type: 'danger', text: '异常', explain: '触发了任务场景约束、禁止规则或明确的流程异常。' }
  if (status.value === 'UNKNOWN_VALIDITY') return { type: 'warning', text: '待确认', explain: '未命中已知正常模板，但没有触发硬性安全规则，建议人工复核。' }
  if (status.value === 'NORMAL_WITH_TOLERANCE') return { type: 'primary', text: '容错正常', explain: '与正常模板存在轻微差异，偏差仍在当前容忍范围内。' }
  if (status.value === 'NORMAL') return { type: 'success', text: '正常', explain: '动作顺序通过场景规则、转移概率和正常模板校验。' }
  return { type: 'info', text: '未校验', explain: '没有识别到可校验的动作，或流程校验尚未完成。' }
})

const translateReason = (reason = '') => {
  if (!reason) return ''
  if (reason.includes('forbidden transition')) return `触发禁止转移规则：${reason}`
  if (reason.includes('No known complete template')) return '未命中已知完整正常模板，但没有违反硬性安全或场景规则，需要人工确认。'
  if (reason.includes('sequence ended before')) return '动作序列在匹配的任务流程完成前提前结束。'
  return reason
}

const evidenceRows = computed(() => {
  const rows = violations.value.map((item, index) => ({
    id: `rule-${index}`,
    category: item.hard ? '硬规则' : status.value === 'UNKNOWN_VALIDITY' ? '模板偏差' : '流程规则',
    severity: item.hard ? '异常' : '注意',
    index: item.index,
    previous: item.previous,
    actual: Array.isArray(item.actual) ? item.actual.join(' → ') : item.actual,
    probability: null,
    reason: translateReason(item.reason),
  }))

  transitions.value.forEach((item, index) => {
    if (!['ANOMALY', 'DEVIATION'].includes(item.decision) || item.level === 'forbidden') return
    rows.push({
      id: `transition-${index}`,
      category: item.decision === 'ANOMALY' ? '未见转移' : '低概率转移',
      severity: item.decision === 'ANOMALY' ? '异常' : '注意',
      index: item.index,
      previous: item.previous,
      actual: item.actual,
      probability: item.context_probability ?? item.probability,
      reason: item.decision === 'ANOMALY'
        ? '结合前序动作后，该动作不在已学习的合理后继集合中。'
        : '该动作可以发生，但在当前上下文中的出现概率较低。',
    })
  })

  if (!rows.length && ['ANOMALY', 'UNKNOWN_VALIDITY'].includes(status.value)) {
    rows.push({
      id: 'summary',
      category: '整体结论',
      severity: status.value === 'ANOMALY' ? '异常' : '注意',
      index: null,
      previous: null,
      actual: actions.value.join(' → '),
      probability: null,
      reason: statusMeta.value.explain,
    })
  }
  return rows
})

const templateSimilarity = computed(() => {
  const ratio = Number(candidates.value[0]?.error_ratio)
  return Number.isFinite(ratio) ? `${Math.max(0, (1 - ratio) * 100).toFixed(1)}%` : '-'
})

const timeline = computed(() =>
  actions.value.map((action, index) => {
    const segment = segments.value[index] || {}
    const transition = index > 0 ? transitions.value[index - 1] : null
    return {
      action,
      source: segment.sourceText || '动作序列',
      time: segment.timeText || '-',
      confidence: segment.confidenceText || '-',
      decision: transition?.decision || 'NORMAL',
    }
  }),
)

const mainReason = computed(() => evidenceRows.value[0]?.reason || statusMeta.value.explain)
const onFileChange = (file) => {
  handleChange(file)
  result.value = null
  errorMessage.value = ''
}

const onFileRemove = () => {
  handleRemove()
  result.value = null
  errorMessage.value = ''
}

const runRecognition = async () => {
  if (!selectedFile.value) {
    ElMessage.warning('请先上传 .pcap / .pcapng / .cap 文件')
    return
  }

  loading.value = true
  result.value = null
  errorMessage.value = ''
  const startedAt = performance.now()

  const formData = new FormData()
  formData.append('file', selectedFile.value)
  formData.append('mode', 'sequence')
  formData.append('method', method.value)
  formData.append('validate_flow', 'true')
  formData.append('scenario', scenario.value)
  formData.append('min_segment_s', String(minSegmentS.value))
  formData.append('step_s', String(stepS.value))
  formData.append('segment_penalty', String(segmentPenalty.value))

  try {
    const { data } = await api.post('/api/motion-recognition/recognize', formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
      timeout: 600000,
    })
    result.value = data
    elapsedMs.value = Math.round(performance.now() - startedAt)
    activeTab.value = 'overview'
    await nextTick()
    resultRef.value?.scrollIntoView({ behavior: 'smooth', block: 'start' })
    if (data.summary?.flow_status === 'ANOMALY') {
      ElMessage.error('识别完成：检测到动作流程异常')
    } else if (data.summary?.flow_status === 'UNKNOWN_VALIDITY') {
      ElMessage.warning('识别完成：该序列需要人工确认')
    } else {
      ElMessage.success('动作序列识别与流程校验完成')
    }
  } catch (error) {
    errorMessage.value = errorText(error, '动作序列识别失败，请检查后端服务、模型文件和上传的 pcap。')
    ElMessage.error(errorMessage.value)
  } finally {
    loading.value = false
  }
}

const exportJson = () => {
  if (!result.value) return
  downloadJson(`${result.value.run_id || 'motion_sequence'}_result.json`, result.value)
}
</script>

<template>
  <ModuleHero
    objective="恢复控制动作并判断动作转移与任务流程是否合理"
    input="机器狗控制链路 PCAP"
    output="动作时间线、转移风险与流程结论"
    scenario="自由操控、巡逻、交互与动作表演"
  />
  <section
    class="panel motion-workbench fade-in"
    v-loading.fullscreen.lock="loading"
    element-loading-text="正在识别动作并校验时序流程，请稍候…"
    element-loading-background="rgba(255, 255, 255, 0.88)"
  >
    <div class="section-header">
      <div>
        <h2 class="section-title">动作序列分析</h2>
        <p class="panel-sub">从控制流量识别动作，并自动检查上下文转移、任务场景和正常流程模板。</p>
      </div>
      <el-tag v-if="result" :type="statusMeta.type" size="large" effect="dark">{{ statusMeta.text }}</el-tag>
    </div>

    <div class="analysis-input-grid">
      <UploadPanel
        :file-list="fileList"
        :selected-file="selectedFile"
        :disabled="loading"
        :error="errorMessage"
        @change="onFileChange"
        @remove="onFileRemove"
      />

      <div class="control-stack">
        <label class="control-field">
          <span>任务场景</span>
          <el-select v-model="scenario">
            <el-option v-for="item in scenarioOptions" :key="item.value" :label="item.label" :value="item.value" />
          </el-select>
        </label>

        <label class="control-field">
          <span>识别方式</span>
          <el-select v-model="method">
            <el-option v-for="item in methodOptions" :key="item.value" :label="item.label" :value="item.value" />
          </el-select>
        </label>

        <div v-if="method !== 'command'" class="advanced-settings">
          <div class="field-heading">
            <strong>算法参数</strong>
            <el-tooltip content="这些参数只影响流量到动作片段的识别，不改变后续流程规则。" placement="top">
              <span class="help-dot">?</span>
            </el-tooltip>
          </div>
          <div class="parameter-grid">
            <label v-if="['dp', 'activity', 'scan'].includes(method)" class="control-field">
              <span>最短片段（秒）</span>
              <el-input-number v-model="minSegmentS" :min="0.05" :max="10" :step="0.05" />
            </label>
            <label v-if="method === 'scan'" class="control-field">
              <span>扫描步长（秒）</span>
              <el-input-number v-model="stepS" :min="0.05" :max="10" :step="0.05" />
            </label>
            <label v-if="method === 'dp'" class="control-field">
              <span>切分惩罚</span>
              <el-input-number v-model="segmentPenalty" :min="0" :max="1" :step="0.01" />
            </label>
          </div>
        </div>

        <div class="automatic-check">
          <span class="check-mark">✓</span>
          <div>
            <strong>识别后自动校验动作流程</strong>
            <span>当前场景：{{ scenarioOptions.find((item) => item.value === scenario)?.label }}</span>
          </div>
        </div>

        <div class="action-row">
          <el-button type="primary" size="large" :loading="loading" :disabled="!selectedFile || loading" @click="runRecognition">
            开始识别与分析
          </el-button>
          <el-button v-if="errorMessage" size="large" :disabled="!selectedFile" @click="runRecognition">重试</el-button>
        </div>
      </div>
    </div>
  </section>

  <section v-if="result" ref="resultRef" class="result-overview fade-in">
    <ResultSummary
      :status="status"
      :title="`流程结论：${statusMeta.text}`"
      :description="mainReason"
      :advice="status === 'ANOMALY' ? '查看判定依据和逐步转移风险，复核高风险控制动作。' : status === 'UNKNOWN_VALIDITY' ? '将该序列提交人工审核，确认后再扩充正常模板。' : '保留本次记录并继续监控后续控制序列。'"
      :task-id="result.run_id"
      :duration="`${(elapsedMs / 1000).toFixed(2)} s`"
    >
      <template #actions><el-button @click="exportJson">导出 JSON</el-button></template>
    </ResultSummary>

    <div class="grid-4 mt-18">
      <MetricCard title="识别动作" :value="String(actions.length)" subtitle="按时间排序的动作标签" />
      <MetricCard title="转移风险" :value="Number(flow?.transition_check?.max_risk || 0).toFixed(2)" subtitle="上下文中的最高异常风险" />
      <MetricCard title="判定依据" :value="String(evidenceRows.length)" subtitle="需要关注的规则与转移" />
      <MetricCard title="模板相似度" :value="templateSimilarity" subtitle="与最接近正常模板的相似程度" />
    </div>

    <div class="motion-timeline" aria-label="识别出的动作时间线">
      <template v-if="timeline.length">
        <template v-for="(item, index) in timeline" :key="`${item.action}-${index}`">
          <div class="timeline-node" :class="{ 'is-risk': ['ANOMALY', 'DEVIATION'].includes(item.decision) }">
            <strong>{{ item.action }}</strong>
            <span>{{ item.time }} s</span>
            <small>{{ item.source }} · 置信度 {{ item.confidence }}</small>
          </div>
          <span v-if="index < timeline.length - 1" class="sequence-arrow">→</span>
        </template>
      </template>
      <span v-else class="sequence-empty">未识别到动作</span>
    </div>
  </section>

  <SectionBlock v-if="result" title="审计证据" description="按审计步骤查看识别片段、判定依据、转移风险和正常模板。" class="fade-in">
    <el-tabs v-model="activeTab" class="audit-tabs">
      <el-tab-pane label="时间线概览" name="overview" />
      <el-tab-pane :label="`识别与依据 (${segments.length}/${evidenceRows.length})`" name="details" />
      <el-tab-pane :label="`逐步转移 (${transitions.length})`" name="transitions" />
      <el-tab-pane :label="`正常模板 (${candidates.length})`" name="templates" />
      <el-tab-pane label="JSON 结果" name="json" />
    </el-tabs>
    <p v-if="activeTab === 'overview'" class="tab-overview-copy">
      上方时间线按照抓包中的发生顺序恢复动作；红色节点表示对应转移被判为低概率、未见或明确异常。
    </p>
  </SectionBlock>

  <section v-if="result && activeTab === 'details'" class="grid-2 result-detail-grid fade-in">
    <div class="panel">
      <div class="section-header">
        <div>
          <h2 class="section-title">识别片段</h2>
          <p class="panel-sub">固定指令显示发生时刻，持续动作显示起止区间。</p>
        </div>
        <el-tag type="info">{{ segments.length }} 段</el-tag>
      </div>
      <div class="data-table">
        <el-table :data="segments" max-height="340" stripe empty-text="暂无片段明细" row-key="rowId">
          <el-table-column prop="label" label="动作" min-width="108" />
          <el-table-column prop="sourceText" label="来源" min-width="100" />
          <el-table-column prop="timeText" label="时间（秒）" min-width="144" />
          <el-table-column label="时长" width="90">
            <template #default="{ row }">{{ row.duration > 0.001 ? `${row.duration.toFixed(3)} s` : '瞬时' }}</template>
          </el-table-column>
          <el-table-column prop="confidenceText" label="置信度" width="88" />
        </el-table>
      </div>
    </div>

    <div class="panel">
      <div class="section-header">
        <div>
          <h2 class="section-title">判定依据</h2>
          <p class="panel-sub">汇总硬规则、场景约束、模板偏差和低概率转移。</p>
        </div>
        <el-tag :type="evidenceRows.some((item) => item.severity === '异常') ? 'danger' : 'info'">
          {{ evidenceRows.length }} 条
        </el-tag>
      </div>
      <div class="data-table">
        <el-table :data="evidenceRows" max-height="340" stripe empty-text="没有发现需要关注的异常依据" row-key="id">
          <el-table-column prop="category" label="依据" width="104" />
          <el-table-column label="位置" width="66">
            <template #default="{ row }">{{ row.index ?? '-' }}</template>
          </el-table-column>
          <el-table-column label="动作转移" min-width="154">
            <template #default="{ row }">
              {{ row.previous && row.actual ? `${row.previous} → ${row.actual}` : row.actual || '-' }}
            </template>
          </el-table-column>
          <el-table-column label="概率" width="78">
            <template #default="{ row }">{{ row.probability == null ? '-' : Number(row.probability).toFixed(3) }}</template>
          </el-table-column>
          <el-table-column prop="reason" label="说明" min-width="230" show-overflow-tooltip />
        </el-table>
      </div>
    </div>
  </section>

  <section v-if="transitions.length && activeTab === 'transitions'" class="panel fade-in">
    <div class="section-header">
      <div>
        <h2 class="section-title">逐步转移检查</h2>
        <p class="panel-sub">查看每一步在历史上下文中的学习概率与风险。</p>
      </div>
      <el-tag :type="Number(flow?.transition_check?.max_risk || 0) >= 0.8 ? 'danger' : 'info'">
        最高风险 {{ Number(flow?.transition_check?.max_risk || 0).toFixed(2) }}
      </el-tag>
    </div>
    <div class="data-table">
      <el-table :data="transitions" max-height="320" stripe>
        <el-table-column prop="index" label="步" width="64" />
        <el-table-column label="动作转移" min-width="210">
          <template #default="{ row }">{{ row.previous }} → {{ row.actual }}</template>
        </el-table-column>
        <el-table-column label="判断" width="124">
          <template #default="{ row }"><RiskBadge :status="row.decision" :label="row.decision" /></template>
        </el-table-column>
        <el-table-column label="上下文概率" width="118">
          <template #default="{ row }">{{ Number(row.context_probability ?? row.probability ?? 0).toFixed(3) }}</template>
        </el-table-column>
        <el-table-column label="风险" width="92">
          <template #default="{ row }">{{ Number(row.risk || 0).toFixed(3) }}</template>
        </el-table-column>
        <el-table-column prop="context" label="使用的上下文" min-width="180" show-overflow-tooltip />
      </el-table>
    </div>
  </section>

  <section v-if="candidates.length && activeTab === 'templates'" class="panel fade-in">
    <div class="section-header">
      <div>
        <h2 class="section-title">正常模板对照</h2>
        <p class="panel-sub">按编辑距离列出最接近的已学习正常流程。</p>
      </div>
      <el-tag type="info">Top {{ candidates.length }}</el-tag>
    </div>
    <div class="data-table">
      <el-table :data="candidates" max-height="260" stripe>
        <el-table-column prop="template_index" label="模板" width="82" />
        <el-table-column prop="edit_distance" label="编辑距离" width="100" />
        <el-table-column label="差异比例" width="100">
          <template #default="{ row }">{{ Number(row.error_ratio || 0).toFixed(3) }}</template>
        </el-table-column>
        <el-table-column label="正常序列" min-width="360" show-overflow-tooltip>
          <template #default="{ row }">{{ row.template?.join(' → ') }}</template>
        </el-table-column>
      </el-table>
    </div>
  </section>

  <section v-if="result && activeTab === 'json'" class="panel fade-in">
    <JsonViewer :data="result" :filename="`${result.run_id || 'motion_sequence'}_result.json`" title="动作序列原始结果" />
  </section>

  <section v-else class="empty-state fade-in">
    分析结果将在这里按“最终结论、识别片段、判定依据、逐步转移、模板对照”的顺序展示。
  </section>
</template>

<style scoped>
.result-overview {
  display: grid;
  gap: 16px;
}

.motion-workbench {
  border-top: 3px solid var(--accent);
}

.field-heading,
.decision-row,
.automatic-check,
.selected-file {
  display: flex;
  align-items: center;
}

.field-heading {
  justify-content: space-between;
  min-height: 28px;
  margin-bottom: 10px;
}

.field-heading strong {
  font-size: 14px;
}

.field-heading > span {
  color: var(--muted);
  font-size: 12px;
}

.upload-symbol {
  width: 42px;
  height: 42px;
  margin: 0 auto 10px;
  border: 1px solid #8bb0ed;
  border-radius: 50%;
  color: var(--accent);
  font-size: 25px;
  line-height: 39px;
}

.selected-file {
  gap: 12px;
  margin-top: 12px;
  padding: 11px 12px;
  border: 1px solid #b9d3c1;
  border-radius: 6px;
  background: #f5fbf7;
}

.file-mark {
  flex: 0 0 auto;
  padding: 5px 7px;
  border-radius: 4px;
  background: #237a4b;
  color: white;
  font-size: 10px;
  font-weight: 800;
}

.file-copy {
  display: grid;
  min-width: 0;
  flex: 1;
}

.file-copy strong {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  font-size: 13px;
}

.file-copy span {
  color: #4e715d;
  font-size: 12px;
}

.advanced-settings {
  padding: 14px;
  border: 1px solid var(--line-soft);
  border-radius: 6px;
  background: var(--surface-2);
}

.parameter-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 12px;
}

.help-dot {
  display: inline-grid;
  width: 20px;
  height: 20px;
  place-items: center;
  border: 1px solid var(--line-soft);
  border-radius: 50%;
  color: var(--muted);
  cursor: help;
  font-size: 12px;
}

.automatic-check {
  gap: 10px;
  padding: 11px 12px;
  border-left: 3px solid #2d8557;
  background: #f5faf7;
}

.check-mark {
  color: #237a4b;
  font-size: 18px;
  font-weight: 800;
}

.automatic-check > div {
  display: grid;
  gap: 2px;
}

.automatic-check strong {
  font-size: 13px;
}

.automatic-check span:last-child {
  color: var(--muted);
  font-size: 12px;
}

.decision-row {
  gap: 18px;
  min-height: 82px;
  padding-bottom: 18px;
  border-bottom: 1px solid var(--line-soft);
}

.decision-status {
  display: grid;
  min-width: 142px;
  padding: 12px 16px;
  border-left: 4px solid #718096;
  background: #f5f7f9;
}

.decision-status span,
.decision-copy span {
  color: var(--muted);
  font-size: 12px;
}

.decision-status strong {
  font-size: 25px;
}

.decision-status.is-normal {
  border-color: #237a4b;
  background: #f2faf5;
  color: #17653b;
}

.decision-status.is-normal_with_tolerance {
  border-color: #3478c8;
  background: #f3f7fc;
  color: #215f9f;
}

.decision-status.is-unknown_validity {
  border-color: #b47715;
  background: #fff8eb;
  color: #8a570d;
}

.decision-status.is-anomaly {
  border-color: #c53c45;
  background: #fff4f4;
  color: #a62630;
}

.decision-copy {
  display: grid;
  gap: 8px;
  min-width: 0;
}

.decision-copy strong {
  font-size: 15px;
  line-height: 1.55;
}

.motion-sequence-path {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  align-items: center;
  margin-top: 18px;
  padding: 15px;
  border: 1px solid var(--line-soft);
  border-radius: 6px;
  background: var(--surface-2);
}

.motion-timeline {
  display: flex;
  align-items: stretch;
  gap: 8px;
  overflow-x: auto;
  padding: 18px 4px 8px;
}

.timeline-node {
  position: relative;
  flex: 0 0 162px;
  min-height: 94px;
  display: grid;
  align-content: center;
  gap: 4px;
  padding: 13px 14px;
  border: 1px solid var(--line);
  border-top: 3px solid var(--normal);
  border-radius: 7px;
  background: var(--surface);
}

.timeline-node.is-risk {
  border-color: #efc5c8;
  border-top-color: var(--danger);
  background: var(--danger-soft);
}

.timeline-node strong {
  color: var(--ink);
  font-size: 14px;
}

.timeline-node span {
  color: var(--ink-2);
  font-size: 11px;
}

.timeline-node small {
  color: var(--muted);
  font-size: 10px;
  line-height: 1.4;
}

.motion-timeline .sequence-arrow {
  align-self: center;
  flex: 0 0 auto;
}

.tab-overview-copy {
  margin: 0;
  padding: 3px 0 6px;
  color: var(--muted);
  font-size: 13px;
}

.sequence-node {
  padding: 6px 9px;
  border: 1px solid #92b2e8;
  border-radius: 5px;
  background: #f3f7fd;
  color: #245caa;
  font-size: 13px;
  font-weight: 750;
}

.sequence-arrow {
  color: #7d8a9b;
}

.sequence-empty {
  color: var(--muted);
}

.result-detail-grid .panel {
  min-width: 0;
}

.data-table {
  margin-top: 12px;
}

@media (max-width: 760px) {
  .analysis-input-grid {
    grid-template-columns: 1fr;
  }

  .parameter-grid {
    grid-template-columns: 1fr;
  }

  .decision-row {
    align-items: stretch;
    flex-direction: column;
  }

  .decision-status {
    min-width: 0;
  }
}
</style>
