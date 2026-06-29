<script setup>
import { computed, nextTick, onMounted, ref, watch } from 'vue'

import api from '../api/client'
import MarkdownReport from '../components/MarkdownReport.vue'
import MetricCard from '../components/MetricCard.vue'
import { downloadText } from '../lib/download'
import { errorText } from '../lib/http-error'
import { useSingleUpload } from '../composables/useSingleUpload'
import { useChart } from '../composables/useChart'

const featureOptions = ref([])
const selectedFeatures = ref([])
const contamination = ref(0.06)
const targetIp = ref('')
const { fileList, selectedFile, handleChange: handleFileChange, handleRemove } = useSingleUpload()

const loading = ref(false)
const result = ref(null)
const reportLoading = ref(false)
const aiReport = ref('')
const reportDialogVisible = ref(false)

const summary = computed(() => result.value?.summary || { total: 0, abnormal: 0, ratio: 0, avg_score: 0 })
const anomalyTable = computed(() => result.value?.anomalies || { columns: [], rows: [], total: 0, limit: 0 })
const targetHitsTable = computed(() => result.value?.target_hits || { columns: [], rows: [], total: 0, limit: 0 })
const ipProfilesTable = computed(() => result.value?.ip_port_profiles || { columns: [], rows: [], total: 0 })
const portProfilesTable = computed(() => result.value?.port_profiles || { columns: [], rows: [], total: 0 })
const publicLookupRows = computed(() => (ipProfilesTable.value.rows || []).filter((row) => row.scope === 'public'))

const scatterRef = ref(null)
const histRef = ref(null)
const scatterChart = useChart(scatterRef)
const histChart = useChart(histRef)

const publicLookupLoading = ref(false)
const publicLookupVisible = ref(false)
const publicLookupTable = ref({ columns: [], rows: [], total: 0, lookup: { queried: 0, limit: 0, error: null } })

// 二次判断（规则 + LLM 分组研判）：把异常候选按 源→目的 聚合，规则定一批，剩下交 LLM 一次研判
const judgeLoading = ref(false)
const judgeResult = ref(null)
const judgeSummary = computed(() => judgeResult.value?.summary || null)
const judgeMeta = computed(() => judgeResult.value?.llm || null)
const judgeGroups = computed(() => judgeResult.value?.groups || [])
const verdictSourceLabel = { rule: '规则', llm: 'AI', default: '待复核' }

const featureOrder = ['dst_ip_num', 'port', 'size', 'entropy', 'src_ip_num', 'interval']
const featureLabelMap = {
  dst_ip_num: '目的 IP 编码',
  port: '目的端口',
  size: '包长度',
  entropy: '载荷熵',
  src_ip_num: '源 IP 编码',
  interval: '发送间隔',
  idx: '序号',
}
const columnLabelMap = {
  idx: '序号',
  src: '源 IP',
  dst: '目的 IP',
  port: '目的端口',
  size: '包长度',
  interval: '发送间隔',
  entropy: '载荷熵',
  anomaly_score: '异常分数',
  src_ip_num: '源 IP 编码',
  dst_ip_num: '目的 IP 编码',
  timestamp: '时间戳',
  raw_hex_head: '载荷前缀',
}
const profileColumnLabelMap = {
  ip: 'IP 地址',
  ip_long: 'IP Long',
  scope: '地址类型',
  count: '出现次数',
  observed_as_src: '源包数',
  observed_as_dst: '目的包数',
  ports: '端口',
  ptr: '反向域名',
  best_location: '高精归属地定位',
  ip_api_location: '归属地(ip-api)',
  ipwhois_location: '归属地(ipwho.is)',
  isp: '运营商/ISP',
  org: '归属组织',
  asn: 'ASN',
  risk_tags: '风险标签',
  lookup_status: '查询状态',
}
const portColumnLabelMap = {
  port: '端口',
  service: '服务',
  count: '出现次数',
  src_ips: '源 IP',
  dst_ips: '目的 IP',
}
const fallbackFeatures = featureOrder.map((key) => ({ key, label: featureLabelMap[key] || key }))
const fallbackDefaults = ['size', 'interval', 'port']

const featureLabel = (key) => featureLabelMap[key] || key
const columnLabel = (key) => columnLabelMap[key] || key
const profileColumnLabel = (key) => profileColumnLabelMap[key] || key
const portColumnLabel = (key) => portColumnLabelMap[key] || key

const fetchFeatures = async () => {
  try {
    const { data } = await api.get('/api/side-channel/features')
    const rawFeatures = data.features?.length ? data.features : fallbackFeatures
    featureOptions.value = rawFeatures.map((item) => {
      if (typeof item === 'string') return { key: item, label: featureLabel(item) }
      const key = item.key || ''
      return { ...item, key, label: featureLabel(key || item.label || '') }
    })
    selectedFeatures.value = data.defaults?.length ? data.defaults : fallbackDefaults
  } catch {
    featureOptions.value = fallbackFeatures
    selectedFeatures.value = fallbackDefaults
    ElMessage.error('特征列表读取失败，已使用默认特征。')
  }
}

const toNumber = (value, fallback = 0) => {
  const parsed = Number(value)
  return Number.isFinite(parsed) ? parsed : fallback
}

const normalizeScatterPoints = (points) => {
  if (!Array.isArray(points)) return []
  return points
    .map((item) => {
      if (!Array.isArray(item) || item.length < 3) return null
      const x = toNumber(item[0], NaN)
      const y = toNumber(item[1], NaN)
      const score = toNumber(item[2], NaN)
      if (!Number.isFinite(x) || !Number.isFinite(y) || !Number.isFinite(score)) return null
      return [x, y, score]
    })
    .filter(Boolean)
}

const normalizeHistogram = (histogram) => {
  const bins = Array.isArray(histogram?.bins) ? histogram.bins.map((value) => toNumber(value, 0)) : []
  const counts = Array.isArray(histogram?.counts) ? histogram.counts.map((value) => toNumber(value, 0)) : []
  return { bins, counts }
}

const openPublicLookup = async () => {
  if (!publicLookupRows.value.length) {
    ElMessage.warning('当前没有可查询的公网 IP。')
    return
  }

  publicLookupLoading.value = true
  try {
    const { data } = await api.post('/api/side-channel/public-lookup', {
      items: publicLookupRows.value,
    })
    publicLookupTable.value = data
    publicLookupVisible.value = true
  } catch (error) {
    ElMessage.error(errorText(error, '公网归属地查询失败。'))
  } finally {
    publicLookupLoading.value = false
  }
}

const runJudge = async () => {
  const rows = anomalyTable.value.rows || []
  if (!rows.length) {
    ElMessage.warning('当前没有异常包可供二次判断。')
    return
  }

  judgeLoading.value = true
  try {
    const { data } = await api.post('/api/side-channel/judge', {
      candidates: rows,
      target_ip: targetIp.value.trim() || null,
      scene: '机器人侧信道流量异常二次判断',
      use_llm: true,
    })
    judgeResult.value = data
    const s = data.summary || {}
    ElMessage.success(
      `二次判断完成：${s.total_groups || 0} 个分组中确认风险 ${s.risk_groups || 0} 组、排除误报 ${s.benign_groups || 0} 组。`,
    )
  } catch (error) {
    ElMessage.error(errorText(error, '二次判断失败，请检查后端日志。'))
  } finally {
    judgeLoading.value = false
  }
}

const renderCharts = () => {
  if (!result.value) return

  const scatterData = normalizeScatterPoints(result.value.scatter?.points)
  const histogramData = normalizeHistogram(result.value.histogram)

  try {
    const scores = scatterData.map((item) => item[2]).filter((item) => Number.isFinite(item))
    const minScore = scores.length ? Math.min(...scores) : -0.3
    const maxScore = scores.length ? Math.max(...scores) : 0.3

    scatterChart.setOption({
      tooltip: { trigger: 'item' },
      grid: { left: 54, right: 72, top: 26, bottom: 52 },
      xAxis: {
        name: featureLabel(result.value.features?.x || 'x'),
        nameLocation: 'middle',
        nameGap: 32,
        axisLabel: { color: '#657589' },
        splitLine: { lineStyle: { color: '#e2eaf1' } },
      },
      yAxis: {
        name: featureLabel(result.value.features?.y || 'y'),
        nameLocation: 'middle',
        nameGap: 42,
        axisLabel: { color: '#657589' },
        splitLine: { lineStyle: { color: '#e2eaf1' } },
      },
      visualMap: {
        min: minScore,
        max: maxScore,
        dimension: 2,
        orient: 'vertical',
        right: 4,
        top: 20,
        inRange: { color: ['#b54708', '#0f766e'] },
        textStyle: { color: '#657589' },
      },
      series: [{ type: 'scatter', data: scatterData, symbolSize: 8, itemStyle: { opacity: 0.82 } }],
    }, true)

    histChart.setOption({
      tooltip: { trigger: 'axis' },
      grid: { left: 44, right: 18, top: 24, bottom: 44 },
      xAxis: {
        type: 'category',
        data: histogramData.bins.map((value) => value.toFixed(3)),
        axisLabel: { color: '#657589', interval: 4 },
      },
      yAxis: { axisLabel: { color: '#657589' }, splitLine: { lineStyle: { color: '#e2eaf1' } } },
      series: [{ type: 'bar', data: histogramData.counts, itemStyle: { color: '#0f766e' }, barWidth: '60%' }],
    }, true)
  } catch (error) {
    // Keep UI usable when chart rendering fails due unexpected runtime data.
    console.error('renderCharts failed:', error)
  }
}

const runAnalysis = async () => {
  if (!selectedFile.value) {
    ElMessage.warning('请选择 .pcap 或 .pcapng 文件。')
    return
  }

  loading.value = true
  result.value = null
  aiReport.value = ''
  judgeResult.value = null

  const formData = new FormData()
  formData.append('file', selectedFile.value)
  formData.append('features', JSON.stringify(selectedFeatures.value))
  formData.append('contamination', contamination.value.toString())
  if (targetIp.value.trim()) formData.append('target_ip', targetIp.value.trim())

  try {
    const { data } = await api.post('/api/side-channel/analyze', formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
    })
    result.value = data
    await nextTick()
    renderCharts()
  } catch (error) {
    ElMessage.error(errorText(error, '侧信道分析失败，请检查后端日志。'))
  } finally {
    loading.value = false
  }
}

const buildEvidence = () => {
  if (!result.value) return {}
  return {
    scene: 'side_channel_analysis',
    parameters: {
      features: selectedFeatures.value,
      contamination: contamination.value,
      target_ip: targetIp.value.trim() || null,
      file_name: selectedFile.value?.name || null,
    },
    summary: result.value.summary,
    axes: result.value.features,
    sampled: result.value.scatter?.sampled || false,
    anomaly_rows: result.value.anomalies?.rows?.slice(0, 20) || [],
    target_hits: result.value.target_hits?.rows?.slice(0, 20) || [],
    ip_port_profiles: result.value.ip_port_profiles?.rows?.slice(0, 30) || [],
    port_profiles: result.value.port_profiles?.rows?.slice(0, 30) || [],
    second_pass_judgement: judgeResult.value
      ? {
          overall_risk: judgeResult.value.overall_risk,
          assessment: judgeResult.value.assessment,
          summary: judgeResult.value.summary,
          risk_groups: (judgeResult.value.groups || []).filter((g) => g.is_risk).slice(0, 20),
        }
      : null,
  }
}

const generateReport = async () => {
  if (!result.value) return
  reportLoading.value = true
  try {
    const { data } = await api.post('/api/reports/generate', {
      scene: '侧信道分析',
      task_id: result.value.run_id || '',
      evidence: buildEvidence(),
    })
    aiReport.value = data.report || ''
    reportDialogVisible.value = true
  } catch (error) {
    ElMessage.error(errorText(error, '报告生成失败。'))
  } finally {
    reportLoading.value = false
  }
}

onMounted(fetchFeatures)

watch(result, async () => {
  await nextTick()
  await nextTick()
  renderCharts()
})
</script>

<template>
  <section
    class="panel fade-in"
    v-loading.fullscreen.lock="loading"
    element-loading-text="正在解析流量并运行 IsolationForest，文件较大时可能需要 1-2 分钟…"
    element-loading-background="rgba(255, 255, 255, 0.85)"
  >
    <div class="section-header">
      <div>
        <h2 class="section-title">分析输入</h2>
        <p class="panel-sub">上传流量文件，选择用于 IsolationForest 的侧信道特征，并可指定需要重点追踪的目的 IP。</p>
      </div>
      <div class="pill-badge">PCAP / PCAPNG</div>
    </div>

    <div class="analysis-input-grid">
      <div class="upload-zone">
        <el-upload
          drag
          :auto-upload="false"
          :limit="1"
          :file-list="fileList"
          :on-change="handleFileChange"
          :on-remove="handleRemove"
          accept=".pcap,.pcapng"
        >
          <div class="el-upload__text">拖入流量文件，或点击选择</div>
        </el-upload>
      </div>

      <div class="control-stack">
        <label class="control-field">
          <span>特征</span>
          <el-checkbox-group v-model="selectedFeatures">
            <el-checkbox v-for="item in featureOptions" :key="item.key" :value="item.key">
              {{ item.label }}
            </el-checkbox>
          </el-checkbox-group>
        </label>

        <label class="control-field">
          <span>异常比例预估：{{ (contamination * 100).toFixed(0) }}%</span>
          <el-slider v-model="contamination" :min="0.01" :max="0.2" :step="0.01" />
        </label>

        <label class="control-field">
          <span>目标 IP</span>
          <el-input v-model="targetIp" placeholder="例如 10.0.4.3，可留空" />
        </label>

        <div class="action-row">
          <el-button type="primary" :loading="loading" @click="runAnalysis">运行分析</el-button>
          <span class="pill-badge">最多展示 5000 个散点</span>
        </div>
      </div>
    </div>
  </section>

  <section v-if="result" class="panel fade-in">
    <div class="section-header">
      <div>
        <h2 class="section-title">检测概览</h2>
        <p class="panel-sub">模型在当前文件内部寻找离群通信行为，分数越低越可疑。</p>
      </div>
      <div class="action-row">
        <span v-if="result.scatter?.sampled" class="pill-badge">已抽样绘图</span>
        <el-button :loading="reportLoading" @click="generateReport">生成报告</el-button>
      </div>
    </div>
    <div class="metric-strip">
      <MetricCard title="总包数" :value="summary.total.toLocaleString()" subtitle="参与侧信道建模的 IP 包" />
      <MetricCard title="异常包" :value="summary.abnormal.toLocaleString()" subtitle="IsolationForest 标记为异常" />
      <MetricCard title="异常比例" :value="(summary.ratio * 100).toFixed(2) + '%'" subtitle="当前文件内的离群占比" />
      <MetricCard title="平均分数" :value="Number(summary.avg_score || 0).toFixed(4)" subtitle="decision_function 均值" />
    </div>
  </section>

  <section v-if="result" class="analysis-grid fade-in">
    <div class="chart-card">
      <div class="chart-title">特征空间</div>
      <div ref="scatterRef" class="chart-box"></div>
    </div>
    <div class="chart-card">
      <div class="chart-title">异常分数分布</div>
      <div ref="histRef" class="chart-box"></div>
    </div>
  </section>

  <section v-if="result" class="panel fade-in">
    <div class="section-header">
      <div>
        <h2 class="section-title">IP统计</h2>
        <p class="panel-sub">默认只做本地汇总；如需公网归属地，请点击按钮单独查询。</p>
      </div>
      <div class="action-row">
        <span class="pill-badge">{{ ipProfilesTable.total || 0 }} 个地址 / {{ portProfilesTable.total || 0 }} 个端口</span>
        <el-button :loading="publicLookupLoading" :disabled="!publicLookupRows.length" @click="openPublicLookup">
          查询公网归属地
        </el-button>
      </div>
    </div>
    <div class="data-table mt-16">
      <el-table :data="ipProfilesTable.rows || []" max-height="300" stripe>
        <el-table-column
          v-for="col in ipProfilesTable.columns || []"
          :key="col"
          :prop="col"
          :label="profileColumnLabel(col)"
          min-width="140"
          show-overflow-tooltip
        />
      </el-table>
    </div>
  </section>

  <section v-if="result" class="panel fade-in">
    <div class="section-header">
      <h2 class="section-title">端口统计</h2>
      <span class="pill-badge">按出现次数排序</span>
    </div>
    <div class="data-table mt-16">
      <el-table :data="portProfilesTable.rows || []" max-height="300" stripe>
        <el-table-column
          v-for="col in portProfilesTable.columns || []"
          :key="col"
          :prop="col"
          :label="portColumnLabel(col)"
          min-width="140"
          show-overflow-tooltip
        />
      </el-table>
    </div>
  </section>

  <section v-if="result" class="panel fade-in">
    <div class="section-header">
      <div>
        <h2 class="section-title">异常包明细</h2>
        <p class="panel-sub">先看模型筛出的异常，再用规则与 LLM 做二次判断，尽量把误报压下去。</p>
      </div>
      <div class="action-row">
        <span class="pill-badge">前 {{ result.anomalies.limit }} 条</span>
        <el-button :loading="judgeLoading" :disabled="!anomalyTable.rows?.length" @click="runJudge">
          二次判断
        </el-button>
      </div>
    </div>

    <div class="data-table mt-16">
      <el-table :data="anomalyTable.rows || []" max-height="360" stripe>
        <el-table-column
          v-for="col in anomalyTable.columns || []"
          :key="col"
          :prop="col"
          :label="columnLabel(col)"
          min-width="120"
          show-overflow-tooltip
        />
      </el-table>
    </div>
  </section>

  <section v-if="result && judgeResult" class="panel fade-in">
    <div class="section-header">
      <div>
        <h2 class="section-title">二次判断结果</h2>
        <p class="panel-sub">异常候选按「源 → 目的」聚合成分组，规则先定，剩下交 LLM 一次性整体研判。</p>
      </div>
      <div class="action-row">
        <span class="pill-badge">LLM: {{ judgeMeta?.used ? (judgeMeta?.model || '已启用') : '未启用' }}</span>
      </div>
    </div>

    <div class="judge-summary-card">
      <span class="judge-summary-flag" :class="judgeResult.overall_risk ? 'danger' : 'success'">
        {{ judgeResult.overall_risk ? '发现真风险' : '未发现明确风险' }}
      </span>
      <div class="judge-summary-text">
        <strong>{{ judgeResult.assessment }}</strong>
        <span>
          共 {{ judgeSummary?.total_groups || 0 }} 个分组（{{ judgeSummary?.total_candidates || 0 }} 个候选包）：
          风险 {{ judgeSummary?.risk_groups || 0 }} 组、正常 {{ judgeSummary?.benign_groups || 0 }} 组；
          规则定 {{ judgeSummary?.rule_decided_groups || 0 }} 组，LLM 定 {{ judgeSummary?.llm_decided_groups || 0 }} 组。
        </span>
        <span v-if="judgeMeta?.error" class="inline-warning">LLM 降级：{{ judgeMeta.error }}</span>
      </div>
    </div>

    <div class="data-table mt-16">
      <el-table :data="judgeGroups" max-height="360" stripe :default-sort="{ prop: 'is_risk', order: 'descending' }">
        <el-table-column label="判定" min-width="90" fixed="left">
          <template #default="{ row }">
            <span :class="['verdict-pill', row.is_risk ? 'danger' : 'success']">
              {{ row.is_risk ? '真风险' : '正常' }}
            </span>
          </template>
        </el-table-column>
        <el-table-column prop="src" label="源 IP" min-width="140" show-overflow-tooltip />
        <el-table-column prop="dst" label="目的 IP" min-width="140" show-overflow-tooltip />
        <el-table-column prop="scope" label="地址类型" min-width="100" />
        <el-table-column prop="packets" label="包数" min-width="80" sortable />
        <el-table-column prop="port_count" label="端口数" min-width="90" sortable />
        <el-table-column prop="ports" label="端口" min-width="140" show-overflow-tooltip />
        <el-table-column prop="services" label="服务" min-width="120" show-overflow-tooltip />
        <el-table-column label="依据" min-width="90">
          <template #default="{ row }">
            {{ verdictSourceLabel[row.verdict_source] || verdictSourceLabel.default }}
          </template>
        </el-table-column>
        <el-table-column prop="reason" label="理由" min-width="240" show-overflow-tooltip />
        <el-table-column prop="confidence" label="置信度" min-width="90" sortable />
      </el-table>
    </div>
  </section>

  <section v-if="result && targetHitsTable.rows.length" class="panel fade-in">
    <div class="section-header">
      <h2 class="section-title">目标 IP 命中</h2>
      <span class="pill-badge">{{ targetHitsTable.total }} 条</span>
    </div>
    <div class="data-table mt-16">
      <el-table :data="targetHitsTable.rows || []" max-height="300" stripe>
        <el-table-column
          v-for="col in targetHitsTable.columns || []"
          :key="col"
          :prop="col"
          :label="columnLabel(col)"
          min-width="120"
          show-overflow-tooltip
        />
      </el-table>
    </div>
  </section>

  <section v-else-if="!result" class="empty-state fade-in">
    选择一份 PCAP 文件后运行分析。结果会显示异常包、IP 画像和端口服务识别。
  </section>

  <el-dialog v-model="reportDialogVisible" title="分析报告" width="760px">
    <MarkdownReport :content="aiReport" />
    <template #footer>
      <div class="action-row">
        <el-button @click="reportDialogVisible = false">关闭</el-button>
        <el-button type="primary" @click="downloadText('side_channel_report.md', aiReport)">
          下载报告
        </el-button>
      </div>
    </template>
  </el-dialog>

  <el-dialog v-model="publicLookupVisible" title="公网归属地结果" width="1100px">
    <p v-if="publicLookupTable.lookup?.error" class="inline-warning mb-12">
      部分联网查询失败，已保留已有结果：{{ publicLookupTable.lookup.error }}
    </p>
    <div class="data-table">
      <el-table :data="publicLookupTable.rows || []" max-height="520" stripe>
        <el-table-column
          v-for="col in publicLookupTable.columns || []"
          :key="col"
          :prop="col"
          :label="profileColumnLabel(col)"
          min-width="150"
          show-overflow-tooltip
        />
      </el-table>
    </div>
    <template #footer>
      <div class="action-row">
        <el-button @click="publicLookupVisible = false">关闭</el-button>
      </div>
    </template>
  </el-dialog>
</template>
