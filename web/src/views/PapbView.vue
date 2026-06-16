<script setup>
import { computed, onMounted, reactive, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'

import api from '../api/client'

const sequenceText = ref('start, inspect_area, pick_tool, grind_beans, prepare_filter, boil_water, pour_water, serve, clean_tool, shutdown')
const autoReview = ref(true)
const requireTerminal = ref(true)
const saveHistory = ref(true)
const loading = ref(false)
const retraining = ref(false)
const result = ref(null)
const summary = ref(null)
const modelDetail = ref(null)
const pending = ref([])
const reviewed = ref([])
const reviewComment = reactive({})
const uploadInput = ref(null)
const reportDialogVisible = ref(false)
const reportText = ref('')
const retrainForm = reactive({
  critical_min_support: 0.8,
  max_edit_distance: 1,
  max_error_ratio: 0,
  noncritical_actions: 'prepare_filter, stir, clean_tool',
})
const newTrainingText = ref('')

const statusMap = {
  NORMAL: { type: 'success', text: '正常', explain: '动作序列完整命中已学习的正常流程模板。' },
  NORMAL_WITH_TOLERANCE: { type: 'primary', text: '容错正常', explain: '序列和正常模板很接近，偏差只涉及非关键动作或轻微识别误差。' },
  UNKNOWN_VALIDITY: { type: 'warning', text: '未知但可能合理', explain: '没有命中已知完整模板，但暂时没有违反任务图和硬性规则，需要人工确认。' },
  ANOMALY: { type: 'danger', text: '异常', explain: '出现关键动作缺失、错误分支、终止后多动作、重复超限或特征距离异常。' },
}

const pipelineSteps = [
  { title: '上传或粘贴识别结果', text: '支持 JSON、逗号、换行、箭头分隔的动作标签序列。' },
  { title: '一键送入 PAPB', text: '后端进行模板对齐、任务图泛化和硬规则检查。' },
  { title: '查看流程图和结论', text: '高亮正常、异常、缺失、额外动作，方便展示。' },
  { title: '保存记录并更新模型', text: '结果写入历史；UNKNOWN 审核后可加入训练集。' },
]

const statusInfo = computed(() => {
  const status = result.value?.status || 'UNKNOWN'
  return statusMap[status] || { type: 'info', text: status, explain: '暂无状态说明。' }
})
const actionOptions = computed(() => summary.value?.actions || [])
const matchedOperations = computed(() => result.value?.template_match?.operations || [])
const candidateMatches = computed(() => result.value?.candidate_matches || [])
const violations = computed(() => result.value?.violations || [])
const mainViolation = computed(() => violations.value[0]?.reason || statusInfo.value.explain)
const bestTemplate = computed(() => result.value?.template_match?.template || [])

const transitionCheck = computed(() => result.value?.transition_check || { enabled: false, transitions: [] })
const transitions = computed(() => transitionCheck.value.transitions || [])
const transitionLevelMeta = {
  high: { text: '正常', type: 'success' },
  medium: { text: '偏低', type: 'info' },
  low: { text: '罕见', type: 'warning' },
  unseen: { text: '未见过', type: 'danger' },
  unknown: { text: '无统计', type: 'info' },
  forbidden: { text: '禁止', type: 'danger' },
}
const transitionLevel = (level) => transitionLevelMeta[level] || { text: level, type: 'info' }

const flowNodes = computed(() => {
  const actions = result.value?.input_actions || []
  const ops = matchedOperations.value
  const nodes = actions.map((action, index) => {
    const op = ops.find((item) => item.action_index === index)
    const violation = violations.value.find((item) => item.index === index)
    return {
      id: `${index}-${action}`,
      action,
      index,
      state: violation ? 'error' : op?.op === 'extra' ? 'extra' : 'ok',
      note: violation?.reason || op?.op || 'match',
    }
  })
  ops
    .filter((item) => item.op === 'missing')
    .forEach((item) => {
      nodes.splice(Math.max(0, item.action_index), 0, {
        id: `missing-${item.template_index}-${item.expected}`,
        action: item.expected,
        index: item.template_index,
        state: 'missing',
        note: 'missing',
      })
    })
  return nodes
})

const parseActions = (value) => value
  .replace(/->|→/g, ',')
  .replace(/\r?\n/g, ',')
  .replace(/，|、/g, ',')
  .split(',')
  .map((item) => item.trim())
  .filter(Boolean)

const errorText = (error, fallback) => {
  const detail = error.response?.data?.detail
  if (typeof detail === 'string') return detail
  if (detail?.message) return detail.message
  return fallback
}

const loadSummary = async () => {
  const { data } = await api.get('/api/papb/summary')
  summary.value = data
}

const loadModel = async () => {
  const { data } = await api.get('/api/papb/model')
  modelDetail.value = data
  summary.value = data.summary
}

const loadPending = async () => {
  const { data } = await api.get('/api/papb/review/pending')
  pending.value = data.pending || []
  reviewed.value = data.reviewed || []
}

const refreshAll = async () => {
  try {
    await Promise.all([loadSummary(), loadModel(), loadPending()])
  } catch (error) {
    ElMessage.error(errorText(error, '加载 PAPB 状态失败'))
  }
}

const runDetect = async (source = 'manual') => {
  loading.value = true
  result.value = null
  try {
    const { data } = await api.post('/api/papb/detect', {
      sequence: sequenceText.value,
      auto_review: autoReview.value,
      require_terminal: requireTerminal.value,
      save_history: saveHistory.value,
      source,
    })
    result.value = data
    if (data.status === 'UNKNOWN_VALIDITY' && data.review?.added) {
      ElMessage.warning('该序列已加入待审核池')
    } else if (data.status === 'ANOMALY') {
      ElMessage.error('检测到流程异常')
    } else {
      ElMessage.success('检测完成')
    }
    await refreshAll()
  } catch (error) {
    ElMessage.error(errorText(error, 'PAPB 检测失败'))
  } finally {
    loading.value = false
  }
}

const useExample = (actions) => {
  sequenceText.value = actions.join(', ')
}

const loadUpload = async (event) => {
  const file = event.target.files?.[0]
  if (!file) return
  try {
    const text = await file.text()
    let actions = []
    if (file.name.toLowerCase().endsWith('.json')) {
      const data = JSON.parse(text)
      const raw = data.actions || data.sequence || data.labels || data
      actions = Array.isArray(raw)
        ? raw.map((item) => typeof item === 'string' ? item : item.label).filter(Boolean)
        : parseActions(String(raw || ''))
    } else {
      actions = parseActions(text)
    }
    if (!actions.length) throw new Error('no actions')
    sequenceText.value = actions.join(', ')
    ElMessage.success(`已读取 ${actions.length} 个动作标签`)
    await runDetect('upload')
  } catch {
    ElMessage.error('无法解析该识别结果文件，请使用 JSON、TXT 或 CSV 动作序列')
  } finally {
    if (uploadInput.value) uploadInput.value.value = ''
  }
}

const reviewItem = async (item, decision) => {
  const actionText = decision === 'ACCEPT_NORMAL' ? '确认加入正常流程' : '标记为异常'
  try {
    await ElMessageBox.confirm(`确定要${actionText}吗？`, '审核确认', {
      type: decision === 'ACCEPT_NORMAL' ? 'warning' : 'error',
      confirmButtonText: '确定',
      cancelButtonText: '取消',
    })
    await api.post(`/api/papb/review/${item.review_id}`, {
      decision,
      comment: reviewComment[item.review_id] || '',
    })
    ElMessage.success('审核结果已保存')
    await refreshAll()
  } catch (error) {
    if (error === 'cancel') return
    ElMessage.error(errorText(error, '审核提交失败'))
  }
}

const retrain = async () => {
  retraining.value = true
  try {
    const noncritical = retrainForm.noncritical_actions
      .split(',')
      .map((item) => item.trim())
      .filter(Boolean)
    const { data } = await api.post('/api/papb/retrain', {
      critical_min_support: retrainForm.critical_min_support,
      max_edit_distance: retrainForm.max_edit_distance,
      max_error_ratio: retrainForm.max_error_ratio,
      noncritical_actions: noncritical,
    })
    summary.value = data.summary
    await loadModel()
    ElMessage.success('PAPB 模型已重新训练')
  } catch (error) {
    ElMessage.error(errorText(error, '重新训练失败'))
  } finally {
    retraining.value = false
  }
}

const addTrainingSequence = async () => {
  const actions = parseActions(newTrainingText.value)
  if (!actions.length) {
    ElMessage.warning('请先输入训练序列')
    return
  }
  try {
    await api.post('/api/papb/training-sequences', { actions, note: 'added from frontend' })
    newTrainingText.value = ''
    await refreshAll()
    ElMessage.success('训练序列已加入，建议重新训练模型')
  } catch (error) {
    ElMessage.error(errorText(error, '添加训练序列失败'))
  }
}

const buildLocalReport = () => {
  if (!result.value) return ''
  const lines = [
    '# PAPB 动作流程检测报告',
    '',
    `- 检测状态：${result.value.status}`,
    `- 输入动作数：${result.value.action_count}`,
    `- 有效前缀长度：${result.value.valid_prefix_length}`,
    `- 可能下一步：${result.value.expected_next?.join(', ') || '无'}`,
    `- 历史任务编号：${result.value.task_id || '未保存'}`,
    '',
    '## 输入动作序列',
    '',
    result.value.input_actions?.join(' -> ') || '',
    '',
    '## 主要结论',
    '',
    statusInfo.value.explain,
    '',
    '## 异常或偏差',
    '',
    violations.value.length
      ? violations.value.map((item) => `- 位置 ${item.index}: ${item.reason}; actual=${item.actual}; expected=${JSON.stringify(item.expected)}`).join('\n')
      : '- 无违规项',
    '',
    '## 最接近模板',
    '',
    bestTemplate.value.length ? bestTemplate.value.join(' -> ') : '无',
  ]
  return lines.join('\n')
}

const openReport = () => {
  reportText.value = buildLocalReport()
  reportDialogVisible.value = true
}

const downloadText = (filename, text) => {
  const blob = new Blob([text], { type: 'text/markdown;charset=utf-8' })
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = filename
  link.click()
  URL.revokeObjectURL(url)
}

const downloadJson = (filename, data) => {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json;charset=utf-8' })
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = filename
  link.click()
  URL.revokeObjectURL(url)
}

onMounted(refreshAll)
</script>

<template>
  <section class="panel fade-in">
    <div class="section-header">
      <div>
        <h2 class="section-title">PAPB 流程检测工作台</h2>
        <p class="panel-sub">把“动作识别结果”直接送入 PAPB，完成流程合法性检测、流程图解释、历史保存、审核更新和报告导出。</p>
      </div>
    </div>
    <div class="workflow-strip" style="margin-top: 18px;">
      <div v-for="(step, index) in pipelineSteps" :key="step.title" class="workflow-step">
        <span>{{ index + 1 }}</span>
        <div>
          <strong>{{ step.title }}</strong>
          <small>{{ step.text }}</small>
        </div>
      </div>
    </div>
  </section>

  <section class="panel fade-in">
    <div class="section-header">
      <div>
        <h2 class="section-title">上传/识别结果 → PAPB检测</h2>
        <p class="panel-sub">可以上传同伴模块输出的 JSON/TXT/CSV，也可以手动粘贴动作序列。</p>
      </div>
      <div class="action-row">
        <input ref="uploadInput" type="file" accept=".json,.txt,.csv" hidden @change="loadUpload" />
        <el-button @click="uploadInput?.click()">上传识别结果</el-button>
        <el-button @click="useExample(['start', 'pick_cup', 'boil_water', 'prepare_filter', 'pour_water', 'serve', 'shutdown'])">正常示例</el-button>
        <el-button @click="useExample(['start', 'pick_cup', 'grind_beans', 'prepare_filter', 'pour_water', 'serve', 'shutdown'])">异常示例</el-button>
      </div>
    </div>

    <div class="papb-layout" style="margin-top: 18px;">
      <div class="papb-input-block">
        <el-input v-model="sequenceText" type="textarea" :rows="8" placeholder="start, inspect_area, pick_tool, ... 或 start -> inspect_area -> pick_tool" />
        <div class="action-row">
          <el-checkbox v-model="autoReview">UNKNOWN 自动进入待审核池</el-checkbox>
          <el-checkbox v-model="requireTerminal">要求到达终止动作</el-checkbox>
          <el-checkbox v-model="saveHistory">保存到历史记录</el-checkbox>
        </div>
        <div class="action-row">
          <el-button type="primary" :loading="loading" @click="runDetect('manual')">开始检测</el-button>
          <el-button :disabled="!result" @click="openReport">生成报告</el-button>
          <el-button :disabled="!result" @click="downloadJson('papb_result.json', result)">导出JSON</el-button>
        </div>
      </div>

      <div class="papb-summary-block">
        <div class="metric-card">
          <div class="metric-title">正常模板</div>
          <div class="metric-value">{{ summary?.template_count || 0 }}</div>
          <div class="metric-sub">已学习完整任务路径</div>
        </div>
        <div class="metric-card">
          <div class="metric-title">训练序列</div>
          <div class="metric-value">{{ summary?.training_sequence_count || 0 }}</div>
          <div class="metric-sub">用于统计训练的数据</div>
        </div>
        <div class="metric-card">
          <div class="metric-title">待审核</div>
          <div class="metric-value">{{ summary?.pending_count || 0 }}</div>
          <div class="metric-sub">UNKNOWN_VALIDITY 序列</div>
        </div>
      </div>
    </div>
  </section>

  <section v-if="result" class="panel fade-in">
    <div class="section-header">
      <div>
        <h2 class="section-title">检测结论与动作流程图</h2>
        <p class="panel-sub">{{ statusInfo.explain }}</p>
      </div>
      <el-tag :type="statusInfo.type" size="large">{{ statusInfo.text }} · {{ result.status }}</el-tag>
    </div>

    <div class="result-summary">
      <div><strong>{{ result.action_count }}</strong><span>输入动作</span></div>
      <div><strong>{{ result.valid_prefix_length }}</strong><span>有效前缀</span></div>
      <div><strong>{{ result.expected_next?.join(', ') || '无' }}</strong><span>可能下一步</span></div>
      <div><strong>{{ result.task_id || '未保存' }}</strong><span>历史记录编号</span></div>
    </div>

    <div class="flow-graph">
      <template v-for="(node, index) in flowNodes" :key="node.id">
        <div class="flow-node" :class="node.state">
          <strong>{{ node.action }}</strong>
          <span>{{ node.note }}</span>
        </div>
        <div v-if="index < flowNodes.length - 1" class="flow-edge">→</div>
      </template>
    </div>

    <el-alert
      :title="mainViolation"
      :type="result.status === 'ANOMALY' ? 'error' : result.status === 'UNKNOWN_VALIDITY' ? 'warning' : 'success'"
      show-icon
      :closable="false"
      style="margin-top: 14px;"
    />

    <div class="grid-2" style="margin-top: 16px;">
      <div class="data-table">
        <div class="chart-title">异常或偏差说明</div>
        <el-table :data="violations" height="260" stripe empty-text="没有违规项">
          <el-table-column prop="index" label="位置" width="80" />
          <el-table-column prop="previous" label="前一动作" min-width="120" />
          <el-table-column prop="actual" label="实际动作" min-width="120" />
          <el-table-column prop="reason" label="原因" min-width="220" show-overflow-tooltip />
        </el-table>
      </div>
      <div class="data-table">
        <div class="chart-title">与正常模板的对齐</div>
        <el-table :data="matchedOperations" height="260" stripe empty-text="暂无对齐明细">
          <el-table-column prop="op" label="类型" width="90" />
          <el-table-column prop="actual" label="实际" min-width="110" />
          <el-table-column prop="expected" label="期望" min-width="110" />
          <el-table-column prop="action_index" label="位置" width="90" />
        </el-table>
      </div>
    </div>
  </section>

  <section v-if="result && transitionCheck.enabled && transitions.length" class="panel fade-in">
    <div class="section-header">
      <div>
        <h2 class="section-title">动作转移概率校验（马尔可夫）</h2>
        <p class="panel-sub">基于知识库转移矩阵评估每一步动作衔接的合理性，并命中硬约束禁止规则。风险 = 1 − 转移概率。</p>
      </div>
      <span class="pill-badge" :class="{ 'badge-danger': transitionCheck.forbidden_count }">
        禁止转移 {{ transitionCheck.forbidden_count || 0 }} 条 · 最高风险 {{ Number(transitionCheck.max_risk || 0).toFixed(2) }}
      </span>
    </div>
    <div class="data-table" style="margin-top: 14px;">
      <el-table :data="transitions" height="300" stripe>
        <el-table-column label="步" prop="index" width="64" />
        <el-table-column label="转移" min-width="220">
          <template #default="{ row }">{{ row.previous }} → {{ row.actual }}</template>
        </el-table-column>
        <el-table-column label="转移概率" width="120">
          <template #default="{ row }">{{ Number(row.probability || 0).toFixed(2) }}</template>
        </el-table-column>
        <el-table-column label="风险" width="110">
          <template #default="{ row }">{{ Number(row.risk || 0).toFixed(2) }}</template>
        </el-table-column>
        <el-table-column label="判定" width="110">
          <template #default="{ row }">
            <el-tag :type="transitionLevel(row.level).type" size="small" effect="light">
              {{ transitionLevel(row.level).text }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column label="命中规则" min-width="220" show-overflow-tooltip>
          <template #default="{ row }">{{ row.rule || '-' }}</template>
        </el-table-column>
      </el-table>
    </div>
  </section>

  <section v-if="candidateMatches.length" class="panel fade-in">
    <div class="section-header">
      <h2 class="section-title">相近正常模板</h2>
      <span class="pill-badge">Top {{ candidateMatches.length }}</span>
    </div>
    <div class="data-table" style="margin-top: 14px;">
      <el-table :data="candidateMatches" height="260" stripe>
        <el-table-column prop="template_index" label="模板" width="90" />
        <el-table-column prop="edit_distance" label="编辑距离" width="120" />
        <el-table-column prop="error_ratio" label="错误比例" width="120">
          <template #default="{ row }">{{ Number(row.error_ratio || 0).toFixed(3) }}</template>
        </el-table-column>
        <el-table-column label="模板路径" min-width="320" show-overflow-tooltip>
          <template #default="{ row }">{{ row.template?.join(' -> ') }}</template>
        </el-table-column>
      </el-table>
    </div>
  </section>

  <section class="grid-2 fade-in">
    <div class="panel">
      <div class="section-header">
        <div>
          <h2 class="section-title">待审核池</h2>
          <p class="panel-sub">UNKNOWN_VALIDITY 序列确认正常后，会加入训练数据。</p>
        </div>
        <el-button @click="loadPending">刷新</el-button>
      </div>
      <div class="data-table">
        <el-table :data="pending" height="340" stripe empty-text="暂无待审核序列">
          <el-table-column label="动作序列" min-width="240" show-overflow-tooltip>
            <template #default="{ row }">{{ row.actions?.join(' -> ') }}</template>
          </el-table-column>
          <el-table-column prop="papb_status" label="状态" width="150" />
          <el-table-column label="备注" min-width="170">
            <template #default="{ row }">
              <el-input v-model="reviewComment[row.review_id]" size="small" placeholder="审核备注" />
            </template>
          </el-table-column>
          <el-table-column label="操作" width="190" fixed="right">
            <template #default="{ row }">
              <el-button size="small" type="success" @click="reviewItem(row, 'ACCEPT_NORMAL')">确认正常</el-button>
              <el-button size="small" type="danger" plain @click="reviewItem(row, 'REJECT_ANOMALY')">异常</el-button>
            </template>
          </el-table-column>
        </el-table>
      </div>
    </div>

    <div class="panel">
      <div class="section-header">
        <div>
          <h2 class="section-title">模型/训练数据管理</h2>
          <p class="panel-sub">查看当前模板、追加正常序列，并重新统计训练 PAPB 模型。</p>
        </div>
      </div>

      <div class="papb-train-form">
        <label>
          <span>新增正常训练序列</span>
          <el-input v-model="newTrainingText" type="textarea" :rows="3" placeholder="start, action_a, action_b, shutdown" />
        </label>
        <div class="action-row">
          <el-button @click="addTrainingSequence">加入训练数据</el-button>
          <el-button type="primary" :loading="retraining" @click="retrain">重新训练模型</el-button>
        </div>
        <label>
          <span>关键动作支持率</span>
          <el-slider v-model="retrainForm.critical_min_support" :min="0" :max="1" :step="0.05" />
        </label>
        <label>
          <span>非关键动作</span>
          <el-input v-model="retrainForm.noncritical_actions" />
        </label>
      </div>

      <div class="data-table" style="margin-top: 16px;">
        <div class="chart-title">当前正常模板</div>
        <el-table :data="modelDetail?.normal_templates || []" height="220" stripe empty-text="暂无模板">
          <el-table-column label="序号" width="80">
            <template #default="{ $index }">{{ $index + 1 }}</template>
          </el-table-column>
          <el-table-column label="模板路径" show-overflow-tooltip>
            <template #default="{ row }">{{ row.join(' -> ') }}</template>
          </el-table-column>
        </el-table>
      </div>
    </div>
  </section>

  <el-dialog v-model="reportDialogVisible" title="PAPB 检测报告" width="760px">
    <pre class="json-preview">{{ reportText }}</pre>
    <template #footer>
      <el-button @click="reportDialogVisible = false">关闭</el-button>
      <el-button type="primary" @click="downloadText('papb_report.md', reportText)">下载 Markdown</el-button>
    </template>
  </el-dialog>
</template>
