<script setup>
import { computed, onBeforeUnmount, onMounted, ref, watch, nextTick } from 'vue'
import echarts from '../lib/echarts'
import { ElMessage } from 'element-plus'

import api from '../api/client'
import MarkdownReport from '../components/MarkdownReport.vue'
import MetricCard from '../components/MetricCard.vue'

const fileList = ref([])
const selectedFile = ref(null)
const limit = ref(0)
const verbose = ref(false)
const loading = ref(false)
const result = ref(null)
const reportLoading = ref(false)
const aiReport = ref('')
const reportDialogVisible = ref(false)

const threatRef = ref(null)
const protocolRef = ref(null)
let threatChart = null
let protocolChart = null

const columnLabelMap = {
  packet_index: '包序号',
  protocol: '协议',
  final_score: '风险得分',
  threat_level: '威胁等级',
  confidence: '置信度',
  rule_hits: '规则命中',
  elapsed_ms: '耗时 (ms)',
}

const columnLabel = (key) => columnLabelMap[key] || key

const downloadText = (filename, text) => {
  const blob = new Blob([text], { type: 'text/markdown;charset=utf-8' })
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = filename
  link.click()
  URL.revokeObjectURL(url)
}

const handleFileChange = (file) => {
  selectedFile.value = file.raw
  fileList.value = [file]
}

const handleRemove = () => {
  selectedFile.value = null
  fileList.value = []
}

const joinUrl = (base, path) => {
  const cleanBase = base?.replace(/\/$/, '') || ''
  return `${cleanBase}${path}`
}

const downloadCsv = computed(() => {
  if (!result.value?.download_csv_url) return ''
  return joinUrl(api.defaults.baseURL, result.value.download_csv_url)
})

const downloadSummary = computed(() => {
  if (!result.value?.download_summary_url) return ''
  return joinUrl(api.defaults.baseURL, result.value.download_summary_url)
})

const renderCharts = () => {
  if (!result.value?.summary) return

  if (threatRef.value && !threatChart) {
    threatChart = echarts.init(threatRef.value)
  }
  if (protocolRef.value && !protocolChart) {
    protocolChart = echarts.init(protocolRef.value)
  }

  const threatDist = result.value.summary.threat_level_distribution || {}
  const threatLabels = Object.keys(threatDist)
  const threatValues = Object.values(threatDist)

  if (threatChart) {
    threatChart.setOption({
      tooltip: { trigger: 'axis' },
      xAxis: { type: 'category', data: threatLabels, axisLabel: { color: '#6b645d' } },
      yAxis: { axisLabel: { color: '#6b645d' } },
      series: [
        {
          type: 'bar',
          data: threatValues,
          itemStyle: { color: '#b45309' },
          barWidth: '60%',
        },
      ],
    })
  }

  const protocolDist = result.value.summary.protocol_distribution || {}
  const protocolLabels = Object.keys(protocolDist)
  const protocolValues = Object.values(protocolDist)

  if (protocolChart) {
    protocolChart.setOption({
      tooltip: { trigger: 'axis' },
      xAxis: { type: 'value', axisLabel: { color: '#6b645d' } },
      yAxis: {
        type: 'category',
        data: protocolLabels,
        axisLabel: { color: '#6b645d' },
      },
      series: [
        {
          type: 'bar',
          data: protocolValues,
          itemStyle: { color: '#0f766e' },
          barWidth: '60%',
        },
      ],
    })
  }
}

const runDetection = async () => {
  if (!selectedFile.value) {
    ElMessage.warning('请先上传 .pcap 或 .pcapng 文件。')
    return
  }

  loading.value = true
  result.value = null
  aiReport.value = ''

  const formData = new FormData()
  formData.append('file', selectedFile.value)
  if (limit.value > 0) {
    formData.append('limit', limit.value.toString())
  }
  formData.append('verbose', verbose.value ? 'true' : 'false')

  try {
    const { data } = await api.post('/detect-file', formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
    })
    result.value = data
    await nextTick()
    renderCharts()
  } catch (error) {
    ElMessage.error('载荷检测失败，请检查后端日志。')
  } finally {
    loading.value = false
  }
}

const buildEvidence = () => {
  if (!result.value) return {}
  return {
    scene: 'payload_detection',
    parameters: {
      limit: limit.value,
      verbose: verbose.value,
      file_name: selectedFile.value?.name || null,
      run_id: result.value.run_id || null,
    },
    summary: result.value.summary,
    preview_rows: result.value.preview?.slice(0, 30) || [],
    stdout_tail: result.value.stdout_tail || [],
  }
}

const generateReport = async () => {
  if (!result.value) return
  reportLoading.value = true
  try {
    const { data } = await api.post('/api/reports/generate', {
      scene: '通信包载荷检测',
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

const handleResize = () => {
  threatChart?.resize()
  protocolChart?.resize()
}

onMounted(() => {
  window.addEventListener('resize', handleResize)
})

onBeforeUnmount(() => {
  window.removeEventListener('resize', handleResize)
  threatChart?.dispose()
  protocolChart?.dispose()
})

watch(result, async () => {
  await nextTick()
  renderCharts()
})
</script>

<template>
  <section class="panel fade-in">
    <div class="section-header">
      <div>
        <h2 class="section-title">载荷检测</h2>
        <p class="panel-sub">逐包风险评分并输出结构化证据。</p>
      </div>
    </div>

    <div class="grid-2" style="margin-top: 20px;">
      <div>
        <p class="panel-sub">流量文件</p>
        <el-upload
          drag
          :auto-upload="false"
          :limit="1"
          :file-list="fileList"
          :on-change="handleFileChange"
          :on-remove="handleRemove"
          accept=".pcap,.pcapng"
        >
          <div class="el-upload__text">拖拽 PCAP/PCAPNG 到此，或点击选择</div>
        </el-upload>
      </div>
      <div>
        <p class="panel-sub">处理范围</p>
        <el-input-number v-model="limit" :min="0" :step="100" />
        <p class="panel-sub" style="margin-top: 18px;">详细日志</p>
        <el-switch v-model="verbose" />
        <div class="action-row" style="margin-top: 20px;">
          <el-button type="primary" :loading="loading" @click="runDetection">开始载荷检测</el-button>
          <span class="pill-badge">返回预览行 + 汇总</span>
        </div>
      </div>
    </div>
  </section>

  <section v-if="result" class="panel fade-in">
    <div class="section-header">
      <h2 class="section-title">指标总览</h2>
      <el-button :loading="reportLoading" @click="generateReport">生成 AI 报告</el-button>
    </div>
    <div class="grid-3" style="margin-top: 18px;">
      <MetricCard
        title="处理包数"
        :value="(result.summary.processed_packets || 0).toLocaleString()"
        subtitle="已评分的包数量"
      />
      <MetricCard
        title="平均风险分"
        :value="Number(result.summary.avg_final_score || 0).toFixed(4)"
        subtitle="越高风险越大"
      />
      <MetricCard
        title="高危占比"
        :value="(Number(result.summary.high_or_critical_ratio || 0) * 100).toFixed(2) + '%'"
        subtitle="高危 + 严重"
      />
    </div>
  </section>

  <section v-if="result" class="grid-2 fade-in">
    <div class="chart-card">
      <div class="chart-title">威胁等级分布</div>
      <div ref="threatRef" class="chart-box"></div>
    </div>
    <div class="chart-card">
      <div class="chart-title">协议分布</div>
      <div ref="protocolRef" class="chart-box"></div>
    </div>
  </section>

  <section v-if="result" class="panel fade-in">
    <div class="section-header">
      <h2 class="section-title">逐包预览</h2>
      <div class="action-row">
        <el-button v-if="downloadCsv" tag="a" :href="downloadCsv" target="_blank">下载 CSV</el-button>
        <el-button v-if="downloadSummary" tag="a" :href="downloadSummary" target="_blank">下载汇总</el-button>
      </div>
    </div>
    <div class="data-table" style="margin-top: 16px;">
      <el-table :data="result.preview" height="360" stripe>
        <el-table-column
          v-for="col in Object.keys(result.preview?.[0] || {})"
          :key="col"
          :prop="col"
          :label="columnLabel(col)"
          min-width="140"
          show-overflow-tooltip
        />
      </el-table>
    </div>
  </section>

  <section v-else-if="!result" class="empty-state fade-in">
    上传 PCAP 并开始载荷检测后展示分布与预览。
  </section>

  <el-dialog v-model="reportDialogVisible" title="AI 检测报告" width="760px">
    <MarkdownReport :content="aiReport" />
    <template #footer>
      <div class="action-row">
        <el-button @click="reportDialogVisible = false">关闭</el-button>
        <el-button type="primary" @click="downloadText('payload_ai_report.md', aiReport)">
          下载报告
        </el-button>
      </div>
    </template>
  </el-dialog>
</template>
