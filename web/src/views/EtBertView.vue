<script setup>
import { computed, nextTick, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import * as echarts from 'echarts'
import { ElMessage } from 'element-plus'

import api from '../api/client'
import JsonViewer from '../components/JsonViewer.vue'
import MetricCard from '../components/MetricCard.vue'
import ModuleHero from '../components/ModuleHero.vue'
import ResultSummary from '../components/ResultSummary.vue'
import RiskBadge from '../components/RiskBadge.vue'
import SectionBlock from '../components/SectionBlock.vue'
import UploadPanel from '../components/UploadPanel.vue'

const fileList = ref([])
const selectedFile = ref(null)
const modelMode = ref('packet')
const maxPackets = ref(500)
const loading = ref(false)
const reportLoading = ref(false)
const result = ref(null)
const activeTab = ref('overview')
const errorMessage = ref('')
const elapsedMs = ref(0)
const resultRef = ref(null)

// ── 图表 refs ─────
const pieRef = ref(null)
const barRef = ref(null)
const confRef = ref(null)
const protoRef = ref(null)
const sizeRef = ref(null)
const portRef = ref(null)

let charts = {}

const disposeCharts = () => {
  Object.values(charts).forEach(c => c?.dispose())
  charts = {}
}

const initChart = (refKey, el) => {
  if (!el) return
  if (charts[refKey]) charts[refKey].dispose()
  charts[refKey] = echarts.init(el)
  return charts[refKey]
}

// ── 文件上传 ─────
const handleFileChange = (file) => { selectedFile.value = file.raw; fileList.value = [file] }
const handleRemove = () => { selectedFile.value = null; fileList.value = [] }

const threatColor = (label) => {
  const d = { '正常': '#22c55e', '正常流': '#22c55e',
    '指令码异常': '#f97316', '参数值异常': '#facc15', '格式违规': '#ef4444',
    '注入流异常': '#a855f7', '速率泛洪': '#ec4899',
    '方向振荡': '#3b82f6', '指令码扫描': '#eab308' }
  return d[label] || '#6b7280'
}

// ── 检测摘要文本 ─────
const summaryText = computed(() => {
  if (!result.value) return ''
  const r = result.value
  const total = r.total_samples || 0
  const abnormal = Object.entries(r.summary || {}).filter(([k]) => !k.startsWith('正常')).reduce((s, [, v]) => s + v, 0)
  const normal = total - abnormal
  const abnormalRatio = r.abnormal_ratio || 0
  const modelLabel = r.model_type === 'packet' ? '包级' : '流级'
  const lowConf = r.low_confidence_count || 0

  // 找出异常最多的类型
  const topAbnormal = Object.entries(r.summary || {}).filter(([k]) => !k.startsWith('正常'))
    .sort(([, a], [, b]) => b - a)
  const topList = topAbnormal.slice(0, 3).map(([k, v]) => `${k}(${v}个)`).join('、')

  let level = '正常', levelColor = '#22c55e', advice = ''
  if (abnormalRatio > 20) { level = '高危', levelColor = '#ef4444'; advice = '建议立即对该控制链路进行断网隔离，并排查异常来源。' }
  else if (abnormalRatio > 5) { level = '可疑', levelColor = '#f97316'; advice = '建议对异常包进行回溯分析，确认是否为攻击行为。' }
  else if (abnormalRatio > 0) { level = '低风险', levelColor = '#eab308'; advice = '少量异常包可能来源于操控噪声或环境干扰，建议持续监控。' }
  else { level = '正常', levelColor = '#22c55e'; advice = '当前流量未见明显异常，控制链路通信正常。' }

  return { total, abnormal, normal, abnormalRatio, modelLabel, lowConf, topAbnormal, topList, level, levelColor, advice }
})

const protoColors = { 'UDP': '#3b82f6', 'TCP': '#f97316', 'Other': '#9ca3af' }

const onModelSwitch = () => {
  result.value = null
  errorMessage.value = ''
}

const lowConfidenceRows = computed(() =>
  (result.value?.predictions || []).filter((row) => Number(row.confidence || 0) < 50),
)
const topCategory = computed(() => {
  const entries = Object.entries(result.value?.summary || {}).sort(([, a], [, b]) => b - a)
  return entries[0]?.[0] || '-'
})
const resultStatus = computed(() => {
  const ratio = Number(result.value?.abnormal_ratio || 0)
  if (ratio > 20) return 'ANOMALY'
  if (ratio > 5) return 'TOLERATED'
  if (ratio > 0) return 'UNKNOWN'
  return 'NORMAL'
})

// ── 执行检测 ─────
const runDetection = async () => {
  if (!selectedFile.value) { ElMessage.warning('请先上传 .pcap 文件'); return }
  loading.value = true; result.value = null; errorMessage.value = ''; disposeCharts()
  const startedAt = performance.now()
  const formData = new FormData()
  formData.append('file', selectedFile.value)
  formData.append('max_packets', maxPackets.value.toString())
  const url = modelMode.value === 'packet'
    ? '/api/etbert/detect/packet'
    : '/api/etbert/detect/flow'
  try {
    const { data } = await api.post(url, formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
      timeout: 300000,
    })
    result.value = data
    elapsedMs.value = Math.round(performance.now() - startedAt)
    activeTab.value = 'overview'
    await nextTick()
    resultRef.value?.scrollIntoView({ behavior: 'smooth', block: 'start' })
  } catch (error) {
    let msg = '检测失败'
    if (error.code === 'ECONNABORTED') msg = '请求超时：CPU 推理较慢，请降低最大包数或检查后端是否运行'
    else if (error.response?.data?.detail) msg = typeof error.response.data.detail === 'string' ? error.response.data.detail : JSON.stringify(error.response.data.detail)
    else if (error.message) msg = error.message
    errorMessage.value = msg
    ElMessage.error(msg)
  } finally {
    loading.value = false
  }
}

// ── 下载检测报告 ─────
const downloadReport = async () => {
  if (!selectedFile.value) { ElMessage.warning('请先上传 .pcap 文件'); return }
  reportLoading.value = true
  const formData = new FormData()
  formData.append('file', selectedFile.value)
  formData.append('max_packets', maxPackets.value.toString())
  const url = modelMode.value === 'packet'
    ? '/api/etbert/report/packet'
    : '/api/etbert/report/flow'
  try {
    const { data } = await api.post(url, formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
      timeout: 300000,
    })
    const rows = data.report || []
    let csv = 'packet_index,protocol,anomaly_prob\n'
    for (const r of rows) {
      csv += `${r.packet_index},${r.protocol},${r.anomaly_prob !== null ? r.anomaly_prob : ''}\n`
    }
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8' })
    const link = document.createElement('a')
    link.href = URL.createObjectURL(blob)
    link.download = `etbert_report_${data.run_id || 'result'}.csv`
    link.click()
    URL.revokeObjectURL(link.href)
    ElMessage.success('检测报告已下载')
  } catch (error) {
    let msg = '报告生成失败'
    if (error.code === 'ECONNABORTED') msg = '请求超时，请降低最大包数'
    else if (error.response?.data?.detail) msg = typeof error.response.data.detail === 'string' ? error.response.data.detail : JSON.stringify(error.response.data.detail)
    ElMessage.error(msg)
  } finally {
    reportLoading.value = false
  }
}

// ── 图表渲染（watch result 变化后等 DOM 就绪）─────
const renderAll = () => {
  if (!result.value) return
  const summary = result.value.summary || {}
  const preds = result.value.predictions || []
  const proto = result.value.proto_stats || {}
  const cats = Object.keys(summary)
  const vals = Object.values(summary)

  // --- 饼图：类别分布 ---
  const pie = initChart('pie', pieRef.value)
  if (pie) {
    pie.setOption({
      tooltip: { trigger: 'item', formatter: '{b}: {c} ({d}%)' },
      legend: { orient: 'vertical', right: 5, top: 'center', textStyle: { fontSize: 11 } },
      series: [{ type: 'pie', radius: ['35%', '65%'], center: ['38%', '50%'],
        data: cats.map(k => ({ name: k, value: summary[k], itemStyle: { color: threatColor(k) } })),
        label: { formatter: '{b}\n{d}%', fontSize: 10 } }],
    }, { notMerge: true })
  }

  // --- 柱状图：类别计数 ---
  const bar = initChart('bar', barRef.value)
  if (bar) {
    bar.setOption({
      tooltip: { trigger: 'axis' },
      xAxis: { type: 'category', data: cats, axisLabel: { rotate: 30, fontSize: 10 } },
      yAxis: { type: 'value' },
      series: [{ type: 'bar', barWidth: '55%',
        data: cats.map(k => ({ value: summary[k], itemStyle: { color: threatColor(k) } })) }],
      grid: { bottom: 80, top: 10 },
    }, { notMerge: true })
  }

  // --- 直方图：置信度 ---
  const conf = initChart('conf', confRef.value)
  if (conf && preds.length) {
    const bins = [0, 50, 60, 70, 80, 90, 95, 100]
    const counts = new Array(bins.length - 1).fill(0)
    preds.forEach(r => {
      for (let i = 0; i < bins.length - 1; i++)
        if (r.confidence >= bins[i] && r.confidence < bins[i+1]) { counts[i]++; break }
    })
    conf.setOption({
      tooltip: { trigger: 'axis' },
      xAxis: { type: 'category', data: bins.slice(0, -1).map((b, i) => `${b}-${bins[i+1]}`) },
      yAxis: { type: 'value' },
      series: [{ type: 'bar', barWidth: '70%', data: counts,
        itemStyle: { color: p => p.value > 0 ? '#b45309' : '#e5e7eb' } }],
    }, { notMerge: true })
  }

  // --- 协议分布饼图 ---
  const protoDist = proto.protocol_distribution || {}
  const pCats = Object.keys(protoDist)
  const protoPie = initChart('proto', protoRef.value)
  if (protoPie && pCats.length) {
    protoPie.setOption({
      tooltip: { trigger: 'item', formatter: '{b}: {c} ({d}%)' },
      legend: { bottom: 0, textStyle: { fontSize: 10 } },
      series: [{ type: 'pie', radius: ['40%', '70%'],
        data: pCats.map(k => ({ name: k, value: protoDist[k], itemStyle: { color: protoColors[k] || '#9ca3af' } })),
        label: { formatter: '{b}\n{d}%', fontSize: 10 } }],
    }, { notMerge: true })
  }

  // --- 包大小分布 ---
  const sizeDist = proto.payload_size_distribution || {}
  const sCats = Object.keys(sizeDist)
  const sizeBar = initChart('size', sizeRef.value)
  if (sizeBar && sCats.length) {
    sizeBar.setOption({
      tooltip: { trigger: 'axis' },
      xAxis: { type: 'category', data: sCats, axisLabel: { rotate: 20, fontSize: 9 } },
      yAxis: { type: 'value' },
      series: [{ type: 'bar', barWidth: '55%', data: sCats.map(k => ({ value: sizeDist[k], itemStyle: { color: '#5B9BD5' } })) }],
      grid: { bottom: 50, top: 10 },
    }, { notMerge: true })
  }

  // --- 端口分布 ---
  const topPorts = proto.top_ports || {}
  const ptCats = Object.keys(topPorts)
  const portBar = initChart('port', portRef.value)
  if (portBar && ptCats.length) {
    portBar.setOption({
      tooltip: { trigger: 'axis' },
      xAxis: { type: 'category', data: ptCats.map(p => `:${p}`), axisLabel: { fontSize: 10 } },
      yAxis: { type: 'value', name: '包数' },
      series: [{ type: 'bar', barWidth: '50%', data: ptCats.map(k => ({ value: topPorts[k], itemStyle: { color: '#ED7D31' } })) }],
      grid: { bottom: 20, top: 10 },
    }, { notMerge: true })
  }
}

// 关键修复: watch 使用 flush:'post' 确保 DOM 已更新后再初始化图表
watch(result, async (val) => {
  if (!val) return
  await nextTick()
  renderAll()
}, { flush: 'post' })

watch(activeTab, async () => {
  await nextTick()
  renderAll()
})

const handleResize = () => Object.values(charts).forEach(c => c?.resize())
onMounted(() => window.addEventListener('resize', handleResize))
onBeforeUnmount(() => { window.removeEventListener('resize', handleResize); disposeCharts() })
</script>

<template>
  <ModuleHero
    objective="识别控制载荷中的异常指令、参数与通信模式"
    input="PCAP / PCAPNG 载荷流量"
    output="异常类别、置信度与样本证据"
    scenario="控制链路内容审计"
  />
  <SectionBlock
    title="检测配置"
    description="上传控制链路抓包，选择包级或流级推理方式后开始检测。"
    class="fade-in"
    v-loading="loading"
  >
    <div class="analysis-input-grid payload-config">
      <UploadPanel
        :file-list="fileList"
        :selected-file="selectedFile"
        :disabled="loading"
        :error="errorMessage"
        accept=".pcap,.pcapng"
        @change="handleFileChange"
        @remove="handleRemove"
      />
      <div class="control-stack">
        <label class="control-field">
          <span>检测粒度</span>
          <el-radio-group v-model="modelMode" @change="onModelSwitch">
            <el-radio-button value="packet">包级（单包）</el-radio-button>
            <el-radio-button value="flow">流级（32 包窗口）</el-radio-button>
          </el-radio-group>
        </label>
        <label class="control-field">
          <span>最大处理包数</span>
          <el-input-number v-model="maxPackets" :min="100" :step="500" :max="50000" />
        </label>
        <div class="config-note">
          <strong>{{ modelMode === 'packet' ? '逐包识别异常载荷' : '按连续 32 包恢复流级上下文' }}</strong>
          <span>模型切换不会改变原始抓包文件。</span>
        </div>
        <div class="action-row">
          <el-button type="primary" size="large" :loading="loading" :disabled="!selectedFile || loading" @click="runDetection">
            {{ loading ? '正在检测' : '开始检测' }}
          </el-button>
          <el-button v-if="errorMessage" size="large" :disabled="!selectedFile" @click="runDetection">重试</el-button>
        </div>
      </div>
    </div>
  </SectionBlock>

  <div v-if="!result && !loading && !errorMessage" class="result-placeholder">
    检测完成后将在此显示风险结论、关键指标和可追溯证据。
  </div>

  <template v-if="result">
    <div ref="resultRef">
      <ResultSummary
        :status="resultStatus"
        :title="`${summaryText.modelLabel}检测完成：${summaryText.level}`"
        :description="summaryText.advice"
        :advice="summaryText.abnormal > 0 ? '查看异常类别和低置信度样本，必要时导出报告复核。' : '保留检测记录并持续监控该控制链路。'"
        :task-id="result.run_id"
        :duration="`${(elapsedMs / 1000).toFixed(2)} s`"
      >
        <template #actions>
          <el-button :loading="reportLoading" @click="downloadReport">{{ reportLoading ? '生成中' : '导出报告' }}</el-button>
        </template>
      </ResultSummary>
    </div>

    <div class="grid-4 metric-grid fade-in">
      <MetricCard title="检测样本" :value="(result.total_samples || 0).toLocaleString()" subtitle="本次进入模型的样本数" />
      <MetricCard title="异常比例" :value="`${(result.abnormal_ratio || 0).toFixed(2)}%`" subtitle="异常样本占全部样本比例" />
      <MetricCard title="主要类别" :value="topCategory" subtitle="当前数量最多的预测类别" />
      <MetricCard title="低置信度" :value="`${result.low_confidence_count || 0}`" subtitle="置信度低于 50% 的样本" />
    </div>

    <SectionBlock title="检测证据" description="在概览、类别分布、样本明细和原始数据之间切换。" class="fade-in">
      <el-tabs v-model="activeTab" class="audit-tabs">
        <el-tab-pane label="检测概览" name="overview">
          <div class="audit-conclusion">
            <RiskBadge :status="resultStatus" :label="summaryText.level" />
            <p>
              共处理 <b>{{ summaryText.total.toLocaleString() }}</b> 个样本，正常
              <b>{{ summaryText.normal.toLocaleString() }}</b> 个，异常
              <b>{{ summaryText.abnormal.toLocaleString() }}</b> 个。
              <template v-if="summaryText.topList">主要异常：{{ summaryText.topList }}。</template>
            </p>
          </div>
          <div v-if="result.proto_stats" class="grid-3 chart-grid">
            <div><div class="chart-title">协议分布</div><div ref="protoRef" class="chart-box"></div></div>
            <div><div class="chart-title">包大小分布</div><div ref="sizeRef" class="chart-box"></div></div>
            <div><div class="chart-title">Top-5 端口</div><div ref="portRef" class="chart-box"></div></div>
          </div>
        </el-tab-pane>

        <el-tab-pane label="类别分布" name="distribution">
          <div class="grid-3 chart-grid">
            <div><div class="chart-title">类别占比</div><div ref="pieRef" class="chart-box"></div></div>
            <div><div class="chart-title">类别计数</div><div ref="barRef" class="chart-box"></div></div>
            <div><div class="chart-title">置信度分布</div><div ref="confRef" class="chart-box"></div></div>
          </div>
        </el-tab-pane>

        <el-tab-pane label="前 100 条明细" name="details">
          <div class="data-table">
            <el-table :data="(result.predictions || []).slice(0, 100)" height="430" stripe empty-text="没有样本明细">
              <el-table-column type="index" label="序号" width="70" />
              <el-table-column prop="pred_name" label="判定类别" min-width="150">
                <template #default="{ row }"><el-tag :color="threatColor(row.pred_name)" effect="dark">{{ row.pred_name }}</el-tag></template>
              </el-table-column>
              <el-table-column prop="confidence" label="置信度" width="120">
                <template #default="{ row }"><RiskBadge :status="row.confidence < 50 ? 'UNKNOWN' : 'NORMAL'" :label="`${row.confidence.toFixed(1)}%`" /></template>
              </el-table-column>
              <el-table-column label="Top-3 概率" min-width="320">
                <template #default="{ row }">
                  {{ Object.entries(row.all_probs || {}).sort((a,b) => b[1]-a[1]).slice(0,3).map(([name, value]) => `${name} ${value.toFixed(1)}%`).join(' · ') }}
                </template>
              </el-table-column>
            </el-table>
          </div>
        </el-tab-pane>

        <el-tab-pane :label="`低置信度样本 (${lowConfidenceRows.length})`" name="low-confidence">
          <div class="data-table">
            <el-table :data="lowConfidenceRows" height="380" stripe empty-text="没有低置信度样本">
              <el-table-column type="index" label="序号" width="70" />
              <el-table-column prop="pred_name" label="预测类别" min-width="180" />
              <el-table-column label="置信度" width="140">
                <template #default="{ row }"><RiskBadge status="UNKNOWN" :label="`${row.confidence.toFixed(1)}%`" /></template>
              </el-table-column>
            </el-table>
          </div>
        </el-tab-pane>

        <el-tab-pane label="JSON 结果" name="json">
          <JsonViewer :data="result" :filename="`${result.run_id || 'etbert'}_result.json`" />
        </el-tab-pane>
      </el-tabs>
    </SectionBlock>
  </template>
</template>
