<script setup>
import { computed, nextTick, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import * as echarts from 'echarts'
import { ElMessage } from 'element-plus'

import api from '../api/client'
import MetricCard from '../components/MetricCard.vue'

const fileList = ref([])
const selectedFile = ref(null)
const modelMode = ref('packet')
const maxPackets = ref(500)
const loading = ref(false)
const reportLoading = ref(false)
const result = ref(null)

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
}

// ── 执行检测 ─────
const runDetection = async () => {
  if (!selectedFile.value) { ElMessage.warning('请先上传 .pcap 文件'); return }
  loading.value = true; result.value = null; disposeCharts()
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
  } catch (error) {
    let msg = '检测失败'
    if (error.code === 'ECONNABORTED') msg = '请求超时：CPU 推理较慢，请降低最大包数或检查后端是否运行'
    else if (error.response?.data?.detail) msg = typeof error.response.data.detail === 'string' ? error.response.data.detail : JSON.stringify(error.response.data.detail)
    else if (error.message) msg = error.message
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

const handleResize = () => Object.values(charts).forEach(c => c?.resize())
onMounted(() => window.addEventListener('resize', handleResize))
onBeforeUnmount(() => { window.removeEventListener('resize', handleResize); disposeCharts() })
</script>

<template>
  <section class="panel fade-in">
    <div class="section-header">
      <div>
        <h2 class="section-title">ET-BERT 双粒度流量检测</h2>
        <p class="panel-sub">基于预训练 Transformer 的包级 + 流级深度异常检测</p>
      </div>
      <div class="pill-badge">ET-BERT</div>
    </div>

    <div class="grid-2" style="margin-top: 20px;">
      <div>
        <p class="panel-sub">流量文件</p>
        <el-upload drag :auto-upload="false" :limit="1" :file-list="fileList"
          :on-change="handleFileChange" :on-remove="handleRemove" accept=".pcap,.pcapng">
          <div class="el-upload__text">拖拽 PCAP 到此，或点击选择</div>
        </el-upload>
      </div>
      <div>
        <p class="panel-sub">检测粒度</p>
        <el-radio-group v-model="modelMode" @change="onModelSwitch" style="margin-bottom:12px">
          <el-radio-button value="packet">包级 (单包)</el-radio-button>
          <el-radio-button value="flow">流级 (32包窗口)</el-radio-button>
        </el-radio-group>
        <p class="panel-sub" style="margin-top:16px">最大处理包数</p>
        <el-input-number v-model="maxPackets" :min="100" :step="500" :max="50000" />
        <div class="action-row" style="margin-top:20px">
          <el-button type="primary" :loading="loading" @click="runDetection">
            {{ loading ? '检测中...' : '开始检测' }}
          </el-button>
          <el-button v-if="result" type="success" :loading="reportLoading" @click="downloadReport" style="margin-left:8px">
            {{ reportLoading ? '生成中...' : '下载检测报告' }}
          </el-button>
        </div>
      </div>
    </div>
  </section>

  <!-- 指标卡 -->
  <section v-if="result" class="panel fade-in">
    <div class="section-header">
      <h2 class="section-title">检测结果</h2>
      <span class="pill-badge">{{ result.model }} · {{ result.model_type === 'packet' ? '包级' : '流级' }}</span>
    </div>
    <div class="grid-3" style="margin-top: 18px;">
      <MetricCard title="检测样本数" :value="(result.total_samples || 0).toLocaleString()"
        subtitle="packet: 包数 / flow: 窗口数" />
      <MetricCard title="异常比例" :value="(result.abnormal_ratio || 0).toFixed(2) + '%'"
        :subtitle="result.abnormal_ratio > 10 ? '⚠ 高异常率' : '✓ 正常范围'" />
      <MetricCard title="低置信度告警" :value="(result.low_confidence_count || 0) + ' 条'"
        subtitle="置信度 < 50%，可能为未知攻击" />
    </div>

    <!-- 检测摘要 -->
    <div class="summary-card" :style="{ borderLeftColor: summaryText.levelColor }">
      <div class="summary-header">
        <span class="summary-level" :style="{ background: summaryText.levelColor }">
          {{ summaryText.level }}
        </span>
        <span class="summary-title">{{ summaryText.modelLabel }}检测报告</span>
      </div>
      <p class="summary-body">
        本次{{ summaryText.modelLabel }}检测共处理 <b>{{ summaryText.total.toLocaleString() }}</b> 个{{ summaryText.modelLabel === '包级' ? '包' : '流窗口' }}，
        其中正常 <b>{{ summaryText.normal.toLocaleString() }}</b> 个{{ summaryText.modelLabel === '包级' ? '包' : '流窗口' }}，
        检出异常 <b>{{ summaryText.abnormal.toLocaleString() }}</b> 个{{ summaryText.modelLabel === '包级' ? '包' : '流窗口' }}，
        异常占比 <b>{{ summaryText.abnormalRatio.toFixed(2) }}%</b>。
        <template v-if="summaryText.abnormal > 0">
          主要异常类型：{{ summaryText.topList }}。
        </template>
        低置信度告警 {{ summaryText.lowConf }} 条。
        {{ summaryText.advice }}
      </p>
    </div>
  </section>

  <!-- 图表区 1: 检测结果图表 -->
  <section v-if="result" class="grid-3 fade-in">
    <div class="chart-card"><div class="chart-title">类别分布</div><div ref="pieRef" class="chart-box" style="height:260px"></div></div>
    <div class="chart-card"><div class="chart-title">类别计数</div><div ref="barRef" class="chart-box" style="height:260px"></div></div>
    <div class="chart-card"><div class="chart-title">置信度分布</div><div ref="confRef" class="chart-box" style="height:260px"></div></div>
  </section>

  <!-- 图表区 2: 协议与通信统计 -->
  <section v-if="result && result.proto_stats" class="grid-3 fade-in">
    <div class="chart-card"><div class="chart-title">协议分布</div><div ref="protoRef" class="chart-box" style="height:240px"></div></div>
    <div class="chart-card"><div class="chart-title">包大小分布</div><div ref="sizeRef" class="chart-box" style="height:240px"></div></div>
    <div class="chart-card"><div class="chart-title">Top-5 端口</div><div ref="portRef" class="chart-box" style="height:240px"></div></div>
  </section>

  <!-- 明细表 -->
  <section v-if="result && result.predictions.length" class="panel fade-in">
    <div class="section-header">
      <h2 class="section-title">检测明细（前 100 条）</h2>
    </div>
    <div class="data-table" style="margin-top:16px">
      <el-table :data="result.predictions" height="400" stripe>
        <el-table-column type="index" label="序号" width="60" />
        <el-table-column prop="pred_name" label="判定类别" min-width="120">
          <template #default="{ row }">
            <el-tag :color="threatColor(row.pred_name)" effect="dark" size="small" style="border:none;color:#fff">
              {{ row.pred_name }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="confidence" label="置信度" min-width="100">
          <template #default="{ row }">
            <span :style="{ color: row.confidence < 50 ? '#ef4444' : row.confidence > 90 ? '#22c55e' : '#f59e0b', fontWeight: 'bold' }">
              {{ row.confidence.toFixed(1) }}%
            </span>
          </template>
        </el-table-column>
        <el-table-column label="Top-3 概率" min-width="300">
          <template #default="{ row }">
            <div style="display:flex;gap:6px;flex-wrap:wrap">
              <span v-for="(prob, clsName) in Object.fromEntries(
                Object.entries(row.all_probs || {}).sort((a,b) => b[1]-a[1]).slice(0,3)
              )" :key="clsName"
                style="font-size:11px;background:#f3f4f6;padding:1px 6px;border-radius:4px">
                {{ clsName }}: <b>{{ prob.toFixed(1) }}%</b>
              </span>
            </div>
          </template>
        </el-table-column>
      </el-table>
    </div>
  </section>

  <section v-else-if="!result && !loading" class="empty-state fade-in">
    上传 PCAP 文件并选择检测粒度，开始 ET-BERT 双粒度推理。
  </section>
</template>
