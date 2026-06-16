<script setup>
import { nextTick, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import echarts from '../lib/echarts'
import { ElMessage } from 'element-plus'

import api from '../api/client'
import MarkdownReport from '../components/MarkdownReport.vue'
import MetricCard from '../components/MetricCard.vue'

const featureOptions = ref([])
const selectedFeatures = ref([])
const contamination = ref(0.06)
const targetIp = ref('')
const fileList = ref([])
const selectedFile = ref(null)

const loading = ref(false)
const result = ref(null)
const reportLoading = ref(false)
const aiReport = ref('')
const reportDialogVisible = ref(false)

const scatterRef = ref(null)
const histRef = ref(null)
let scatterChart = null
let histChart = null

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
  observed_as_src: '源包数',
  observed_as_dst: '目的包数',
  ports: '端口',
  services: '端口服务',
  ptr: '反向域名',
  best_location: '高精归属地定位',
  ip_api_location: '归属地(ip-api)',
  ipwhois_location: '归属地(ipwho.is)',
  ip2region_location: '归属地(IP2REGION)',
  geolite2_location: '归属地(GeoLite2)',
  dbip_location: '归属地(DbIp)',
  isp: '运营商/ISP',
  org: '归属组织',
  asn: 'ASN',
  risk_tags: '风险标签',
  lookup_status: '查询状态',
}
const fallbackFeatures = featureOrder.map((key) => ({ key, label: featureLabelMap[key] || key }))
const fallbackDefaults = ['size', 'interval', 'port']

const featureLabel = (key) => featureLabelMap[key] || key
const columnLabel = (key) => columnLabelMap[key] || key
const profileColumnLabel = (key) => profileColumnLabelMap[key] || key

const downloadText = (filename, text) => {
  const blob = new Blob([text], { type: 'text/markdown;charset=utf-8' })
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = filename
  link.click()
  URL.revokeObjectURL(url)
}

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

const handleFileChange = (file) => {
  selectedFile.value = file.raw
  fileList.value = [file]
}

const handleRemove = () => {
  selectedFile.value = null
  fileList.value = []
}

const renderCharts = () => {
  if (!result.value) return

  if (scatterRef.value && !scatterChart) scatterChart = echarts.init(scatterRef.value)
  if (histRef.value && !histChart) histChart = echarts.init(histRef.value)

  if (scatterChart) {
    const points = result.value.scatter?.points || []
    const scores = points.map((item) => item[2]).filter((item) => typeof item === 'number')
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
      series: [{ type: 'scatter', data: points, symbolSize: 8, itemStyle: { opacity: 0.82 } }],
    })
  }

  if (histChart) {
    histChart.setOption({
      tooltip: { trigger: 'axis' },
      grid: { left: 44, right: 18, top: 24, bottom: 44 },
      xAxis: {
        type: 'category',
        data: result.value.histogram?.bins?.map((v) => v.toFixed(3)) || [],
        axisLabel: { color: '#657589', interval: 4 },
      },
      yAxis: { axisLabel: { color: '#657589' }, splitLine: { lineStyle: { color: '#e2eaf1' } } },
      series: [{ type: 'bar', data: result.value.histogram?.counts || [], itemStyle: { color: '#0f766e' }, barWidth: '60%' }],
    })
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
    ElMessage.error(error.response?.data?.detail || '侧信道分析失败，请检查后端日志。')
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
    ip_lookup: result.value.ip_port_profiles?.lookup || {},
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
    ElMessage.error(error.response?.data?.detail || '报告生成失败。')
  } finally {
    reportLoading.value = false
  }
}

const handleResize = () => {
  scatterChart?.resize()
  histChart?.resize()
}

onMounted(async () => {
  await fetchFeatures()
  window.addEventListener('resize', handleResize)
})

onBeforeUnmount(() => {
  window.removeEventListener('resize', handleResize)
  scatterChart?.dispose()
  histChart?.dispose()
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
      <MetricCard title="总包数" :value="result.summary.total.toLocaleString()" subtitle="参与侧信道建模的 IP 包" />
      <MetricCard title="异常包" :value="result.summary.abnormal.toLocaleString()" subtitle="IsolationForest 标记为异常" />
      <MetricCard title="异常比例" :value="(result.summary.ratio * 100).toFixed(2) + '%'" subtitle="当前文件内的离群占比" />
      <MetricCard title="平均分数" :value="Number(result.summary.avg_score || 0).toFixed(4)" subtitle="decision_function 均值" />
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
      <h2 class="section-title">IP 与端口画像</h2>
      <span class="pill-badge">
        {{ result.ip_port_profiles?.total || 0 }} 个地址 / 查询 {{ result.ip_port_profiles?.lookup?.queried || 0 }} 个公网 IP
      </span>
    </div>
    <p v-if="result.ip_port_profiles?.lookup?.error" class="inline-warning">
      联网查询失败，已保留本地端口识别：{{ result.ip_port_profiles.lookup.error }}
    </p>
    <div class="data-table" style="margin-top: 16px;">
      <el-table :data="result.ip_port_profiles?.rows || []" height="380" stripe>
        <el-table-column
          v-for="col in result.ip_port_profiles?.columns || []"
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
      <h2 class="section-title">异常包明细</h2>
      <span class="pill-badge">前 {{ result.anomalies.limit }} 条</span>
    </div>
    <div class="data-table" style="margin-top: 16px;">
      <el-table :data="result.anomalies.rows" height="360" stripe>
        <el-table-column
          v-for="col in result.anomalies.columns"
          :key="col"
          :prop="col"
          :label="columnLabel(col)"
          min-width="120"
          show-overflow-tooltip
        />
      </el-table>
    </div>
  </section>

  <section v-if="result && result.target_hits.rows.length" class="panel fade-in">
    <div class="section-header">
      <h2 class="section-title">目标 IP 命中</h2>
      <span class="pill-badge">{{ result.target_hits.total }} 条</span>
    </div>
    <div class="data-table" style="margin-top: 16px;">
      <el-table :data="result.target_hits.rows" height="300" stripe>
        <el-table-column
          v-for="col in result.target_hits.columns"
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
</template>
