<script setup>
import { onBeforeUnmount, onMounted, ref, watch, nextTick } from 'vue'
import * as echarts from 'echarts'
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
  dst_ip_num: '目的 IP 数值化',
  port: '目的端口',
  size: '报文长度',
  entropy: '载荷熵值',
  src_ip_num: '源 IP 数值化',
  interval: '发包间隔',
  idx: '序号',
}
const columnLabelMap = {
  idx: '序号',
  src: '源地址',
  dst: '目的地址',
  port: '目的端口',
  size: '报文长度',
  interval: '发包间隔',
  entropy: '载荷熵值',
  anomaly_score: '离群得分',
  src_ip_num: '源 IP 数值',
  dst_ip_num: '目的 IP 数值',
  timestamp: '时间戳',
  raw_hex_head: '载荷前缀',
}
const fallbackFeatures = featureOrder.map((key) => ({
  key,
  label: featureLabelMap[key] || key,
}))
const fallbackDefaults = ['size', 'interval', 'port']

const featureLabel = (key) => featureLabelMap[key] || key
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

const fetchFeatures = async () => {
  try {
    const { data } = await api.get('/api/side-channel/features')
    const rawFeatures = data.features?.length ? data.features : fallbackFeatures
    featureOptions.value = rawFeatures.map((item) => {
      if (typeof item === 'string') {
        return { key: item, label: featureLabel(item) }
      }
      const key = item.key || ''
      return {
        ...item,
        key,
        label: featureLabel(key || item.label || ''),
      }
    })
    selectedFeatures.value = data.defaults?.length ? data.defaults : fallbackDefaults
  } catch (error) {
    featureOptions.value = fallbackFeatures
    selectedFeatures.value = fallbackDefaults
    ElMessage.error('特征列表加载失败，已使用默认项。')
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

  if (scatterRef.value && !scatterChart) {
    scatterChart = echarts.init(scatterRef.value)
  }
  if (histRef.value && !histChart) {
    histChart = echarts.init(histRef.value)
  }

  if (scatterChart) {
    const points = result.value.scatter?.points || []
    const scores = points.map((item) => item[2]).filter((item) => typeof item === 'number')
    const minScore = scores.length ? Math.min(...scores) : -0.3
    const maxScore = scores.length ? Math.max(...scores) : 0.3

    scatterChart.setOption({
      tooltip: { trigger: 'item' },
      xAxis: {
        name: featureLabel(result.value.features?.x || 'x'),
        nameLocation: 'middle',
        nameGap: 32,
        axisLabel: { color: '#6b645d' },
      },
      yAxis: {
        name: featureLabel(result.value.features?.y || 'y'),
        nameLocation: 'middle',
        nameGap: 42,
        axisLabel: { color: '#6b645d' },
      },
      visualMap: {
        min: minScore,
        max: maxScore,
        dimension: 2,
        orient: 'vertical',
        right: 0,
        top: 20,
        inRange: { color: ['#b45309', '#0f766e'] },
        textStyle: { color: '#6b645d' },
      },
      series: [
        {
          type: 'scatter',
          data: points,
          symbolSize: 8,
          itemStyle: { opacity: 0.8 },
        },
      ],
    })
  }

  if (histChart) {
    histChart.setOption({
      tooltip: { trigger: 'axis' },
      xAxis: {
        type: 'category',
        data: result.value.histogram?.bins?.map((v) => v.toFixed(3)) || [],
        axisLabel: { color: '#6b645d', interval: 4 },
      },
      yAxis: { axisLabel: { color: '#6b645d' } },
      series: [
        {
          type: 'bar',
          data: result.value.histogram?.counts || [],
          itemStyle: { color: '#0f766e' },
          barWidth: '60%',
        },
      ],
    })
  }
}

const runAnalysis = async () => {
  if (!selectedFile.value) {
    ElMessage.warning('请先上传 .pcap 或 .pcapng 文件。')
    return
  }

  loading.value = true
  result.value = null
  aiReport.value = ''

  const formData = new FormData()
  formData.append('file', selectedFile.value)
  formData.append('features', JSON.stringify(selectedFeatures.value))
  formData.append('contamination', contamination.value.toString())
  if (targetIp.value.trim()) {
    formData.append('target_ip', targetIp.value.trim())
  }

  try {
    const { data } = await api.post('/api/side-channel/analyze', formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
    })
    result.value = data
    await nextTick()
    renderCharts()
  } catch (error) {
    ElMessage.error('侧信道分析失败，请检查后端日志。')
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
    ElMessage.error(error.response?.data?.detail || 'AI 报告生成失败，请检查后端配置。')
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
        <h2 class="section-title">侧信道异常审计</h2>
        <p class="panel-sub">上传流量包，配置特征信号，观察异常聚类与风险分布。</p>
      </div>
      <div class="pill-badge">孤立森林</div>
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

        <p class="panel-sub" style="margin-top: 18px;">特征信号</p>
        <el-checkbox-group v-model="selectedFeatures">
          <el-checkbox
            v-for="item in featureOptions"
            :key="item.key"
            :value="item.key"
          >
            {{ item.label }}
          </el-checkbox>
        </el-checkbox-group>
      </div>

      <div>
        <p class="panel-sub">风险阈值</p>
        <el-slider v-model="contamination" :min="0.01" :max="0.2" :step="0.01" />

        <p class="panel-sub" style="margin-top: 18px;">目标 IP（可选）</p>
        <el-input v-model="targetIp" placeholder="例如 10.0.4.3" />

        <div class="action-row" style="margin-top: 20px;">
          <el-button type="primary" :loading="loading" @click="runAnalysis">开始分析</el-button>
          <span class="pill-badge">默认显示 5000 个点</span>
        </div>
      </div>
    </div>
  </section>

  <section v-if="result" class="panel fade-in">
    <div class="section-header">
      <h2 class="section-title">指标总览</h2>
      <div class="action-row">
        <span class="pill-badge" v-if="result.scatter?.sampled">抽样视图</span>
        <el-button :loading="reportLoading" @click="generateReport">生成 AI 报告</el-button>
      </div>
    </div>
    <div class="grid-3" style="margin-top: 18px;">
      <MetricCard
        title="总包数"
        :value="result.summary.total.toLocaleString()"
        subtitle="参与分析的包总量"
      />
      <MetricCard
        title="异常包数"
        :value="result.summary.abnormal.toLocaleString()"
        subtitle="孤立森林判定异常"
      />
      <MetricCard
        title="异常占比"
        :value="(result.summary.ratio * 100).toFixed(2) + '%'"
        subtitle="风险密度"
      />
      <MetricCard
        title="平均得分"
        :value="Number(result.summary.avg_score || 0).toFixed(4)"
        subtitle="越低通常越可疑"
      />
    </div>
  </section>

  <section v-if="result" class="grid-2 fade-in">
    <div class="chart-card">
      <div class="chart-title">异常分布散点</div>
      <div ref="scatterRef" class="chart-box"></div>
    </div>
    <div class="chart-card">
      <div class="chart-title">得分分布</div>
      <div ref="histRef" class="chart-box"></div>
    </div>
  </section>

  <section v-if="result" class="panel fade-in">
    <div class="section-header">
      <h2 class="section-title">异常包清单</h2>
      <span class="pill-badge">前 {{ result.anomalies.limit }} 行</span>
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
      <span class="pill-badge">{{ result.target_hits.total }} 条命中</span>
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
    上传 PCAP 并开始分析后展示指标与图表。
  </section>

  <el-dialog v-model="reportDialogVisible" title="AI 检测报告" width="760px">
    <MarkdownReport :content="aiReport" />
    <template #footer>
      <div class="action-row">
        <el-button @click="reportDialogVisible = false">关闭</el-button>
        <el-button type="primary" @click="downloadText('side_channel_ai_report.md', aiReport)">
          下载报告
        </el-button>
      </div>
    </template>
  </el-dialog>
</template>
