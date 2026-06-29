<script setup>
import { computed, ref } from 'vue'

import api from '../api/client'
import MetricCard from '../components/MetricCard.vue'
import { downloadJson } from '../lib/download'
import { errorText } from '../lib/http-error'
import { useSingleUpload } from '../composables/useSingleUpload'

const { fileList, selectedFile, handleChange: handleFileChange, handleRemove } = useSingleUpload()
const loading = ref(false)
const result = ref(null)

const method = ref('dp')
const minSegmentS = ref(0.25)
const stepS = ref(0.5)
const segmentPenalty = ref(0.02)
const transcript = ref('')
const validateFlow = ref(true)

const actions = computed(() => result.value?.actions || [])
const flow = computed(() => result.value?.flow_validation || null)
const violations = computed(() => flow.value?.violations || [])
const segments = computed(() => result.value?.recognition?.actions || [])
const transitions = computed(() => flow.value?.transition_check?.transitions || [])
const candidates = computed(() => flow.value?.candidate_matches || [])

const status = computed(() => result.value?.summary?.flow_status || 'NOT_RUN')
const statusMeta = computed(() => {
  if (status.value === 'ANOMALY') return { type: 'danger', text: '异常', explain: '动作序列违反当前流程模型或出现未见过的动作转移。' }
  if (status.value === 'UNKNOWN_VALIDITY') return { type: 'warning', text: '未知', explain: '没有命中正常模板，但也未触发明确的硬规则异常。' }
  if (status.value === 'NORMAL_WITH_TOLERANCE') return { type: 'primary', text: '容错正常', explain: '动作序列与正常模板接近，偏差在容忍范围内。' }
  if (status.value === 'NORMAL') return { type: 'success', text: '正常', explain: '动作序列通过当前流程模型校验。' }
  return { type: 'info', text: '未校验', explain: '尚未执行流程校验，或没有识别到可校验的动作。' }
})
const mainReason = computed(() => violations.value[0]?.reason || statusMeta.value.explain)
const rawJson = computed(() => (result.value ? JSON.stringify(result.value, null, 2) : ''))

const runRecognition = async () => {
  if (!selectedFile.value) {
    ElMessage.warning('请先上传 .pcap / .pcapng / .cap 文件')
    return
  }

  loading.value = true
  result.value = null

  const formData = new FormData()
  formData.append('file', selectedFile.value)
  formData.append('mode', 'sequence')
  formData.append('method', method.value)
  formData.append('validate_flow', validateFlow.value ? 'true' : 'false')
  formData.append('min_segment_s', String(minSegmentS.value))
  formData.append('step_s', String(stepS.value))
  formData.append('segment_penalty', String(segmentPenalty.value))
  if (transcript.value.trim()) {
    formData.append('transcript', transcript.value.trim())
  }

  try {
    const { data } = await api.post('/api/motion-recognition/recognize', formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
      timeout: 600000, // 识别大 pcap 可能需要数分钟，给 10 分钟上限
    })
    result.value = data
    if (data.summary?.flow_status === 'ANOMALY') {
      ElMessage.error('识别完成：检测到动作流程异常')
    } else {
      ElMessage.success('动作序列识别完成')
    }
  } catch (error) {
    ElMessage.error(errorText(error, '动作序列识别失败，请检查后端服务、模型文件和上传的 pcap。'))
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
  <section
    class="panel fade-in"
    v-loading.fullscreen.lock="loading"
    element-loading-text="正在从流量中识别动作序列并校验流程，可能需要 1-2 分钟…"
    element-loading-background="rgba(255, 255, 255, 0.85)"
  >
    <div class="section-header">
      <div>
        <h2 class="section-title">动作序列识别与异常分析</h2>
        <p class="panel-sub">
          上传机器狗通信 pcap，系统先从流量中识别动作序列，再把动作序列送入流程模型，判断是否存在异常动作转移。
        </p>
      </div>
      <el-tag v-if="result" :type="statusMeta.type" size="large">{{ statusMeta.text }}</el-tag>
    </div>

    <div class="analysis-input-grid">
      <div class="upload-zone">
        <p class="panel-sub">pcap 文件</p>
        <el-upload
          drag
          :auto-upload="false"
          :limit="1"
          :file-list="fileList"
          :on-change="handleFileChange"
          :on-remove="handleRemove"
          accept=".pcap,.pcapng,.cap"
        >
          <div class="el-upload__text">拖拽 PCAP/PCAPNG/CAP 到此处，或点击选择</div>
        </el-upload>
      </div>

      <div class="control-stack">
        <div class="grid-3">
          <label class="control-field">
            <span>识别方法</span>
            <el-select v-model="method">
              <el-option label="DP 动态规划" value="dp" />
              <el-option label="活动片段" value="activity" />
              <el-option label="滑窗扫描" value="scan" />
            </el-select>
          </label>
          <label class="control-field">
            <span>最短片段 s</span>
            <el-input-number v-model="minSegmentS" :min="0.05" :max="10" :step="0.05" />
          </label>
          <label class="control-field">
            <span>扫描步长 s</span>
            <el-input-number v-model="stepS" :min="0.05" :max="10" :step="0.05" />
          </label>
        </div>

        <div class="grid-2">
          <label class="control-field">
            <span>切分惩罚</span>
            <el-input-number v-model="segmentPenalty" :min="0" :max="1" :step="0.01" />
          </label>
          <label class="control-field">
            <span>流程校验</span>
            <el-switch v-model="validateFlow" active-text="开启" inactive-text="关闭" />
          </label>
        </div>

        <label class="control-field">
          <span>人工参考序列，可选</span>
          <el-input v-model="transcript" placeholder="stand -> hello -> step -> backflip" />
        </label>

        <div class="action-row">
          <el-button type="primary" :loading="loading" @click="runRecognition">开始识别与分析</el-button>
          <el-button :disabled="!result" @click="exportJson">导出 JSON</el-button>
          <span class="pill-badge">第三模块：动作识别 + 时序异常分析</span>
        </div>
      </div>
    </div>
  </section>

  <section v-if="result" class="panel fade-in">
    <div class="section-header">
      <div>
        <h2 class="section-title">最终判断</h2>
        <p class="panel-sub">{{ mainReason }}</p>
      </div>
      <span class="pill-badge">run_id: {{ result.run_id }}</span>
    </div>

    <div class="grid-3 mt-18">
      <MetricCard title="识别动作数" :value="String(actions.length)" subtitle="从 pcap 中识别出的动作标签" />
      <MetricCard title="流程状态" :value="statusMeta.text" subtitle="PAPB 动作转移校验结果" />
      <MetricCard title="异常条目" :value="String(violations.length)" subtitle="违反流程或模板的位置数量" />
    </div>

    <div class="motion-sequence-path">
      <template v-if="actions.length">
        <span v-for="(action, index) in actions" :key="`${action}-${index}`">{{ action }}</span>
      </template>
      <span v-else>未识别到动作</span>
    </div>
  </section>

  <section v-if="result" class="grid-2 fade-in">
    <div class="panel">
      <div class="section-header">
        <h2 class="section-title">识别片段</h2>
        <span class="pill-badge">{{ segments.length }} 段</span>
      </div>
      <div class="data-table mt-14">
        <el-table :data="segments" max-height="280" stripe empty-text="暂无片段明细">
          <el-table-column prop="label" label="动作" min-width="110" />
          <el-table-column label="开始 s" width="100">
            <template #default="{ row }">{{ Number(row.start_s || 0).toFixed(2) }}</template>
          </el-table-column>
          <el-table-column label="结束 s" width="100">
            <template #default="{ row }">{{ Number(row.end_s || 0).toFixed(2) }}</template>
          </el-table-column>
          <el-table-column label="分数" width="100">
            <template #default="{ row }">{{ Number(row.score || row.confidence || 0).toFixed(3) }}</template>
          </el-table-column>
        </el-table>
      </div>
    </div>

    <div class="panel">
      <div class="section-header">
        <h2 class="section-title">异常原因</h2>
        <span class="pill-badge" :class="{ 'badge-danger': violations.length }">{{ violations.length }} 条</span>
      </div>
      <div class="data-table mt-14">
        <el-table :data="violations" max-height="280" stripe empty-text="暂无异常原因">
          <el-table-column prop="index" label="位置" width="72" />
          <el-table-column prop="previous" label="前一动作" min-width="110" />
          <el-table-column prop="actual" label="实际动作" min-width="110" />
          <el-table-column prop="reason" label="原因" min-width="240" show-overflow-tooltip />
        </el-table>
      </div>
    </div>
  </section>

  <section v-if="transitions.length" class="panel fade-in">
    <div class="section-header">
      <h2 class="section-title">动作转移风险</h2>
      <span class="pill-badge">最高风险 {{ Number(flow?.transition_check?.max_risk || 0).toFixed(2) }}</span>
    </div>
    <div class="data-table mt-14">
      <el-table :data="transitions" max-height="300" stripe>
        <el-table-column prop="index" label="步" width="72" />
        <el-table-column label="转移" min-width="220">
          <template #default="{ row }">{{ row.previous }} -> {{ row.actual }}</template>
        </el-table-column>
        <el-table-column prop="level" label="等级" width="110" />
        <el-table-column label="概率" width="110">
          <template #default="{ row }">{{ Number(row.probability || 0).toFixed(3) }}</template>
        </el-table-column>
        <el-table-column label="风险" width="110">
          <template #default="{ row }">{{ Number(row.risk || 0).toFixed(3) }}</template>
        </el-table-column>
      </el-table>
    </div>
  </section>

  <section v-if="candidates.length" class="panel fade-in">
    <div class="section-header">
      <h2 class="section-title">最接近的正常模板</h2>
      <span class="pill-badge">Top {{ candidates.length }}</span>
    </div>
    <div class="data-table mt-14">
      <el-table :data="candidates" max-height="260" stripe>
        <el-table-column prop="template_index" label="模板" width="90" />
        <el-table-column prop="edit_distance" label="编辑距离" width="110" />
        <el-table-column label="错误比例" width="110">
          <template #default="{ row }">{{ Number(row.error_ratio || 0).toFixed(3) }}</template>
        </el-table-column>
        <el-table-column label="模板序列" min-width="320" show-overflow-tooltip>
          <template #default="{ row }">{{ row.template?.join(' -> ') }}</template>
        </el-table-column>
      </el-table>
    </div>
  </section>

  <section v-if="result" class="panel fade-in">
    <el-collapse class="raw-collapse">
      <el-collapse-item name="raw">
        <template #title>
          <h2 class="section-title">完整返回 JSON（调试 / 复现实验 / 写论文表格用，点击展开）</h2>
        </template>
        <pre class="json-preview">{{ rawJson }}</pre>
      </el-collapse-item>
    </el-collapse>
  </section>

  <section v-else class="empty-state fade-in">
    上传一段动作序列 pcap 后，这里会输出识别动作、流程异常判断和可导出的结构化证据。
  </section>
</template>

<style scoped>
.motion-sequence-path {
  display: flex;
  flex-wrap: wrap;
  gap: 10px;
  align-items: center;
  margin-top: 18px;
  padding: 16px;
  border: 1px solid var(--line-soft);
  border-radius: var(--radius);
  background: var(--surface-2);
}

.motion-sequence-path span {
  display: inline-flex;
  align-items: center;
  min-height: 32px;
  padding: 6px 12px;
  border: 1px solid #9bbcf7;
  border-radius: 999px;
  background: var(--accent-soft);
  color: var(--accent);
  font-size: 13px;
  font-weight: 800;
}
</style>
