<script setup>
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import { ElMessage } from 'element-plus'

import api from '../api/client'
import { errorText } from '../lib/http-error'

const props = defineProps({
  endpoint: { type: String, required: true },
  expectedModule: { type: String, required: true },
  extraConfig: { type: Object, default: () => ({}) },
  defaultWindow: { type: Number, default: 8 },
})

const emit = defineEmits(['result', 'status'])

const host = ref('192.168.2.1')
const username = ref('ysc')
const networkInterface = ref('p2p0')
const sshPassword = ref('')
const sudoPassword = ref('')
const samePassword = ref(true)
const captureSeconds = ref(props.defaultWindow)
const busy = ref(false)
const status = ref(null)
let timer = null
let lastResultId = ''

const ownsSession = computed(() => status.value?.config?.module === props.expectedModule)
const running = computed(() => Boolean(status.value?.running && ownsSession.value))
const occupied = computed(() => Boolean(status.value?.running && !ownsSession.value))
const phaseType = computed(() => {
  if (status.value?.phase === 'error') return 'danger'
  if (running.value) return 'success'
  if (occupied.value) return 'warning'
  return 'info'
})
const moduleLabel = {
  motion: '动作时序',
  side_channel: '侧信道',
  payload: '负载检测',
}

const publishStatus = (data) => {
  status.value = data
  emit('status', data)
  if (
    ownsSession.value
    && data.latest_result
    && data.latest_result.run_id !== lastResultId
  ) {
    lastResultId = data.latest_result.run_id
    emit('result', data.latest_result)
  }
}

const poll = async () => {
  try {
    const { data } = await api.get(`${props.endpoint}/status`, { timeout: 10000 })
    publishStatus(data)
  } catch (error) {
    status.value = {
      running: false,
      phase: 'error',
      message: '无法连接实时监测后端',
      latest_error: errorText(error),
    }
  }
}

const start = async () => {
  busy.value = true
  lastResultId = ''
  try {
    const { data } = await api.post(`${props.endpoint}/start`, {
      host: host.value,
      username: username.value,
      interface: networkInterface.value,
      ssh_password: sshPassword.value,
      sudo_password: samePassword.value ? sshPassword.value : sudoPassword.value,
      capture_seconds: Number(captureSeconds.value),
      ...props.extraConfig,
    }, { timeout: 15000 })
    publishStatus(data)
    sshPassword.value = ''
    sudoPassword.value = ''
    ElMessage.success('实时监测已启动')
  } catch (error) {
    ElMessage.error(errorText(error, '实时监测启动失败'))
    await poll()
  } finally {
    busy.value = false
  }
}

const stop = async () => {
  busy.value = true
  try {
    const { data } = await api.post(`${props.endpoint}/stop`, null, { timeout: 15000 })
    publishStatus(data)
    ElMessage.success('实时监测已停止')
  } catch (error) {
    ElMessage.error(errorText(error, '停止实时监测失败'))
  } finally {
    busy.value = false
  }
}

onMounted(() => {
  poll()
  timer = window.setInterval(poll, 2000)
})

onBeforeUnmount(() => {
  if (timer) window.clearInterval(timer)
})
</script>

<template>
  <div class="live-capture-panel">
    <div class="live-settings">
      <div class="live-heading">
        <div>
          <strong>机器狗实时连接</strong>
          <span>滚动抓取完整 PCAP 窗口，分析后立即删除临时文件</span>
        </div>
        <el-tag :type="phaseType">{{ occupied ? '其他模块占用' : status?.phase || 'idle' }}</el-tag>
      </div>

      <div class="live-field-grid">
        <label class="control-field">
          <span>机器狗地址</span>
          <el-input v-model="host" :disabled="running || occupied" />
        </label>
        <label class="control-field">
          <span>SSH 用户</span>
          <el-input v-model="username" :disabled="running || occupied" />
        </label>
        <label class="control-field">
          <span>监听网卡</span>
          <el-input v-model="networkInterface" :disabled="running || occupied" />
        </label>
        <label class="control-field">
          <span>SSH 登录密码</span>
          <el-input
            v-model="sshPassword"
            type="password"
            show-password
            autocomplete="new-password"
            :disabled="running || occupied"
          />
        </label>
        <label class="control-field">
          <span>分析窗口（秒）</span>
          <el-input-number
            v-model="captureSeconds"
            :min="2"
            :max="60"
            :step="1"
            :disabled="running || occupied"
          />
        </label>
        <label class="control-field password-option">
          <span>权限认证</span>
          <el-checkbox v-model="samePassword" :disabled="running || occupied">
            sudo 与 SSH 使用相同密码
          </el-checkbox>
        </label>
        <label v-if="!samePassword" class="control-field">
          <span>sudo 密码</span>
          <el-input
            v-model="sudoPassword"
            type="password"
            show-password
            autocomplete="new-password"
            :disabled="running || occupied"
          />
        </label>
      </div>
    </div>

    <div class="live-status">
      <div class="status-dot" :class="{ active: running }"></div>
      <div class="status-copy">
        <strong>{{ occupied ? `${moduleLabel[status?.config?.module] || '其他模块'}正在使用实时抓包` : status?.message || '尚未启动' }}</strong>
        <span v-if="status?.latest_error" class="error-text">{{ status.latest_error }}</span>
      </div>
      <dl>
        <div><dt>分析窗口</dt><dd>{{ ownsSession ? status?.window_count || 0 : 0 }}</dd></div>
        <div><dt>累计流量</dt><dd>{{ ownsSession ? ((status?.packet_bytes || 0) / 1024).toFixed(1) : '0.0' }} KB</dd></div>
      </dl>
      <el-button
        v-if="!running"
        type="primary"
        size="large"
        :loading="busy"
        :disabled="occupied"
        @click="start"
      >
        开始实时监测
      </el-button>
      <el-button v-else type="danger" size="large" :loading="busy" @click="stop">
        停止监测
      </el-button>
    </div>
  </div>
</template>

<style scoped>
.live-capture-panel {
  display: grid;
  grid-template-columns: minmax(0, 1.45fr) minmax(280px, 0.7fr);
  gap: 20px;
}

.live-settings,
.live-status {
  min-width: 0;
  padding: 16px;
  border: 1px solid var(--line-soft);
  border-radius: 7px;
  background: var(--surface-2);
}

.live-heading,
.live-status {
  display: flex;
  align-items: center;
}

.live-heading {
  justify-content: space-between;
  gap: 16px;
  margin-bottom: 14px;
}

.live-heading > div,
.status-copy {
  display: grid;
  gap: 3px;
}

.live-heading strong,
.status-copy strong {
  font-size: 14px;
}

.live-heading span,
.status-copy span {
  color: var(--muted);
  font-size: 12px;
}

.live-field-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 13px;
}

.live-status {
  align-content: start;
  align-items: stretch;
  grid-template-columns: 12px 1fr;
  gap: 14px 10px;
  background: var(--surface);
}

.status-dot {
  width: 10px;
  height: 10px;
  margin-top: 5px;
  border-radius: 50%;
  background: #9aa5af;
}

.status-dot.active {
  background: #238557;
  box-shadow: 0 0 0 4px rgba(35, 133, 87, 0.12);
}

.status-copy {
  min-width: 0;
}

.status-copy .error-text {
  color: var(--danger);
  overflow-wrap: anywhere;
}

.live-status dl {
  grid-column: 1 / -1;
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  margin: 0;
  border-block: 1px solid var(--line-soft);
}

.live-status dl div {
  display: grid;
  gap: 4px;
  padding: 11px;
  text-align: center;
}

.live-status dt {
  color: var(--muted);
  font-size: 11px;
}

.live-status dd {
  margin: 0;
  font-size: 17px;
  font-weight: 750;
}

.live-status .el-button {
  grid-column: 1 / -1;
}

@media (max-width: 760px) {
  .live-capture-panel,
  .live-field-grid {
    grid-template-columns: 1fr;
  }
}
</style>
