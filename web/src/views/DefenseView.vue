<script setup>
import { computed, reactive, ref } from 'vue'
import {
  CircleCheck,
  Connection,
  Promotion,
  Refresh,
  SwitchButton,
  Warning,
} from '@element-plus/icons-vue'

import api from '../api/client'
import { errorText } from '../lib/http-error'

const connection = reactive({
  host: localStorage.getItem('defense_robot_host') || '192.168.2.1',
  username: localStorage.getItem('defense_robot_user') || 'ysc',
  ssh_password: '',
})
const busy = ref('')
const environment = ref(null)
const selectedLog = ref('defense')
const logContent = ref('')
const safetyConfirmed = ref(false)
const operationError = ref('')

const serviceLabels = {
  etbert_api: 'ET-BERT API',
  payload_bridge: '载荷检测桥接',
  side_bridge: '侧信道检测桥接',
  proxy: 'UDP 防御代理',
}
const fileLabels = {
  proxy: 'UDP 防御代理',
  payload_bridge: '载荷检测桥接脚本',
  side_bridge: '侧信道检测桥接脚本',
  command_sender: '安全测试指令脚本',
  etbert_app: 'ET-BERT API',
  python: '机器人 Python 环境',
}
const modeLabel = computed(() => ({
  stopped: '未运行',
  transparent: '透明转发',
  defense: '完整防御',
})[environment.value?.mode] || '尚未检查')
const modeDisplay = computed(() => (
  environment.value?.readiness === 'degraded'
    ? `${modeLabel.value}（组件异常）`
    : modeLabel.value
))

const credentials = () => ({
  host: connection.host.trim(),
  username: connection.username.trim(),
  ssh_password: connection.ssh_password,
})

const rememberEndpoint = () => {
  localStorage.setItem('defense_robot_host', connection.host.trim())
  localStorage.setItem('defense_robot_user', connection.username.trim())
}

const run = async (name, endpoint, payload = {}, successText = '') => {
  if (!connection.host.trim() || !connection.username.trim() || !connection.ssh_password) {
    ElMessage.warning('请填写机器狗地址、用户名和 SSH 密码。')
    return null
  }
  busy.value = name
  operationError.value = ''
  rememberEndpoint()
  try {
    const timeout = endpoint === 'start-full' ? 200000 : 45000
    const { data } = await api.post(`/api/defense/${endpoint}`, { ...credentials(), ...payload }, { timeout })
    if (data.services) environment.value = { ...(environment.value || {}), ...data, connected: true }
    if (successText || data.message) ElMessage.success(successText || data.message)
    return data
  } catch (error) {
    operationError.value = errorText(error, '防御控制操作失败。')
    ElMessage.error(operationError.value)
    return null
  } finally {
    busy.value = ''
  }
}

const checkEnvironment = async () => {
  const data = await run('check', 'check')
  if (data) {
    environment.value = data
    ElMessage.success('机器狗环境检查完成')
  }
}

const startTransparent = async () => {
  try {
    await ElMessageBox.confirm(
      '透明转发会绕过检测和拦截，仅用于防御对比实验。确认启动？',
      '启动对照组',
      { type: 'warning', confirmButtonText: '启动透明转发', cancelButtonText: '取消' },
    )
  } catch {
    return
  }
  await run('transparent', 'start-transparent')
}

const startFull = async () => {
  await run('full', 'start-full')
}

const stopAll = async () => {
  try {
    await ElMessageBox.confirm('将停止机器狗上的代理和检测桥接进程。', '停止实验进程', {
      type: 'warning',
      confirmButtonText: '确认停止',
      cancelButtonText: '取消',
    })
  } catch {
    return
  }
  await run('stop', 'stop')
}

const sendCommand = async (command) => {
  if (command !== 'HEARTBEAT' && !safetyConfirmed.value) {
    ElMessage.warning('请先确认机器狗周围场地安全。')
    return
  }
  if (command !== 'HEARTBEAT') {
    try {
      await ElMessageBox.confirm(`即将向防御入口发送 ${command}，机器狗可能立即动作。`, '实体动作确认', {
        type: 'warning',
        confirmButtonText: '发送一次',
        cancelButtonText: '取消',
      })
    } catch {
      return
    }
  }
  await run(`command-${command}`, 'send-test', {
    command,
    count: 1,
    safety_confirmed: safetyConfirmed.value,
  })
}

const refreshLogs = async () => {
  const data = await run('logs', 'logs', { log: selectedLog.value, lines: 100 })
  if (data) logContent.value = data.content || '日志文件存在，但目前没有内容。'
}
</script>

<template>
  <section class="defense-intro">
    <div>
      <span>ACTIVE DEFENSE</span>
      <h1>系统集成防御</h1>
      <p>通过受控 SSH 通道管理机器狗上的透明转发与完整防御链，并从统一入口验证放行和拦截效果。</p>
    </div>
    <div class="mode-state" :class="`is-${environment?.mode || 'unknown'}`">
      <i></i>
      <span>当前模式</span>
      <strong>{{ modeDisplay }}</strong>
    </div>
  </section>

  <section class="panel connection-panel">
    <div class="section-header">
      <div>
        <h2 class="section-title">机器狗连接</h2>
        <p class="panel-sub">密码只随本次请求发送，不写入浏览器存储。连接机器狗 AP 后再执行检查。</p>
      </div>
      <el-button :icon="Refresh" :loading="busy === 'check'" @click="checkEnvironment">检查环境</el-button>
    </div>
    <div class="connection-grid">
      <label><span>机器狗地址</span><el-input v-model="connection.host" placeholder="192.168.2.1" /></label>
      <label><span>SSH 用户</span><el-input v-model="connection.username" placeholder="ysc" /></label>
      <label><span>SSH 密码</span><el-input v-model="connection.ssh_password" type="password" show-password /></label>
    </div>
    <div v-if="operationError" class="operation-error">
      <el-icon><Warning /></el-icon>
      <pre>{{ operationError }}</pre>
    </div>
  </section>

  <section class="status-band">
    <div class="status-title">
      <span>运行状态</span>
      <strong>{{ environment?.connected ? 'SSH 已连接' : '等待环境检查' }}</strong>
    </div>
    <div v-for="(label, key) in serviceLabels" :key="key" class="service-state">
      <el-icon :class="{ active: environment?.services?.[key] }">
        <CircleCheck v-if="environment?.services?.[key]" />
        <Warning v-else />
      </el-icon>
      <span>{{ label }}</span>
      <b>{{ environment?.services?.[key] ? '运行中' : '未运行' }}</b>
    </div>
    <div class="service-state">
      <el-icon :class="{ active: environment?.ports?.udp_43894 }"><Connection /></el-icon>
      <span>防御入口 43894/UDP</span>
      <b>{{ environment?.ports?.udp_43894 ? '监听中' : '未监听' }}</b>
    </div>
  </section>

  <section v-if="environment?.files" class="panel">
    <div class="section-header">
      <div>
        <h2 class="section-title">组件完整性</h2>
        <p class="panel-sub">完整防御启动前，代理、两个桥接脚本和 Python 环境必须存在。</p>
      </div>
    </div>
    <div class="file-grid">
      <span v-for="(label, key) in fileLabels" :key="key" :class="{ missing: !environment.files[key] }">
        <el-icon><CircleCheck v-if="environment.files[key]" /><Warning v-else /></el-icon>
        {{ label }}
        <b>{{ environment.files[key] ? '已就绪' : '缺失' }}</b>
      </span>
    </div>
  </section>

  <section class="control-layout">
    <div class="control-column">
      <div class="control-head">
        <span>01</span>
        <div><strong>对照组：透明转发</strong><small>43894 → 43893，不启用检测和拦截</small></div>
      </div>
      <p>仅用于证明无防御时控制包能够直接影响机器狗。启动后日志应显示 PASS / FORWARD。</p>
      <el-button type="warning" :icon="Promotion" :loading="busy === 'transparent'" @click="startTransparent">
        启动透明转发
      </el-button>
    </div>

    <div class="control-column emphasized">
      <div class="control-head">
        <span>02</span>
        <div><strong>实验组：完整防御</strong><small>载荷 + 侧信道 + 风险融合 + UDP 代理</small></div>
      </div>
      <p>严格按实验流程依次启动本机 ET-BERT、载荷桥接、侧信道桥接和防御代理，并等待每一阶段就绪。</p>
      <el-button type="primary" :icon="CircleCheck" :loading="busy === 'full'" @click="startFull">
        启动完整防御
      </el-button>
    </div>

    <div class="control-column">
      <div class="control-head">
        <span>03</span>
        <div><strong>停止与恢复</strong><small>释放 43894 和 8010 相关实验进程</small></div>
      </div>
      <p>切换实验模式前先停止现有进程，避免端口占用或旧检测结果干扰下一轮实验。</p>
      <el-button type="danger" plain :icon="SwitchButton" :loading="busy === 'stop'" @click="stopAll">
        停止全部实验进程
      </el-button>
    </div>
  </section>

  <section class="panel test-panel">
    <div class="section-header">
      <div>
        <h2 class="section-title">受控链路验证</h2>
        <p class="panel-sub">指令固定发送到机器人本机 127.0.0.1:43894，不能输入自定义命令或绕过防御入口。</p>
      </div>
    </div>
    <div class="test-actions">
      <el-button :icon="Connection" :loading="busy === 'command-HEARTBEAT'" @click="sendCommand('HEARTBEAT')">
        发送 HEARTBEAT
      </el-button>
      <el-button
        type="primary"
        plain
        :loading="busy === 'command-STAND_UP'"
        :disabled="!safetyConfirmed"
        @click="sendCommand('STAND_UP')"
      >
        发送 STAND_UP
      </el-button>
      <el-button
        type="primary"
        plain
        :loading="busy === 'command-STAND_DOWN'"
        :disabled="!safetyConfirmed"
        @click="sendCommand('STAND_DOWN')"
      >
        发送 STAND_DOWN
      </el-button>
      <el-checkbox v-model="safetyConfirmed">已清空机器狗周围场地并准备急停</el-checkbox>
    </div>
  </section>

  <section class="panel log-panel">
    <div class="section-header">
      <div>
        <h2 class="section-title">远程运行日志</h2>
        <p class="panel-sub">查看透明转发、防御处置或各检测模块的最新记录。</p>
      </div>
      <div class="log-actions">
        <el-select v-model="selectedLog" style="width: 190px">
          <el-option label="完整防御日志" value="defense" />
          <el-option label="透明转发日志" value="transparent" />
          <el-option label="检测结果 JSONL" value="detection" />
          <el-option label="组件运行日志" value="services" />
        </el-select>
        <el-button :icon="Refresh" :loading="busy === 'logs'" @click="refreshLogs">刷新日志</el-button>
      </div>
    </div>
    <pre>{{ logContent || '连接机器狗后，选择日志并点击刷新。' }}</pre>
  </section>
</template>

<style scoped>
.defense-intro {
  display: flex;
  align-items: flex-end;
  justify-content: space-between;
  gap: 28px;
  padding: 34px 38px;
  border-bottom: 1px solid #dfe6eb;
  background: #f5f8fa;
}

.defense-intro > div:first-child {
  max-width: 700px;
}

.defense-intro span {
  color: #24736b;
  font-size: 11px;
  font-weight: 750;
}

.defense-intro h1 {
  margin: 8px 0 10px;
  color: #18212b;
  font-size: 32px;
}

.defense-intro p {
  margin: 0;
  color: #61707d;
  line-height: 1.7;
}

.mode-state {
  display: grid;
  grid-template-columns: 10px auto;
  gap: 2px 10px;
  min-width: 160px;
  padding-left: 20px;
  border-left: 1px solid #cfd9df;
}

.mode-state i {
  grid-row: 1 / 3;
  align-self: center;
  width: 9px;
  height: 9px;
  border-radius: 50%;
  background: #929da7;
}

.mode-state strong {
  color: #263440;
}

.mode-state.is-defense i {
  background: #168b62;
}

.mode-state.is-transparent i {
  background: #d98a17;
}

.panel,
.control-layout,
.status-band {
  margin: 18px 28px 0;
}

.connection-grid {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 14px;
  margin-top: 18px;
}

.operation-error {
  display: grid;
  grid-template-columns: 24px 1fr;
  gap: 10px;
  margin-top: 16px;
  padding: 13px 15px;
  border: 1px solid #e7b9b9;
  border-radius: 5px;
  background: #fff5f5;
  color: #a62f2f;
}

.operation-error .el-icon {
  margin-top: 2px;
}

.operation-error pre {
  margin: 0;
  overflow: auto;
  color: inherit;
  font: 12px/1.65 Consolas, monospace;
  white-space: pre-wrap;
}

.connection-grid label {
  display: grid;
  gap: 7px;
}

.connection-grid label > span {
  color: #3d4b57;
  font-size: 12px;
  font-weight: 700;
}

.status-band {
  display: grid;
  grid-template-columns: 1.1fr repeat(5, minmax(0, 1fr));
  border-top: 1px solid #dce4e9;
  border-bottom: 1px solid #dce4e9;
}

.status-title,
.service-state {
  display: grid;
  min-height: 84px;
  align-content: center;
  padding: 14px;
  border-right: 1px solid #dce4e9;
}

.status-title span,
.service-state span {
  color: #778490;
  font-size: 11px;
}

.status-title strong {
  margin-top: 4px;
  font-size: 14px;
}

.service-state {
  grid-template-columns: 22px 1fr;
}

.service-state .el-icon {
  grid-row: 1 / 3;
  align-self: center;
  color: #a6afb6;
}

.service-state .el-icon.active {
  color: #168b62;
}

.service-state b {
  margin-top: 3px;
  color: #46535f;
  font-size: 12px;
}

.file-grid {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 10px 18px;
  margin-top: 18px;
}

.file-grid > span {
  display: grid;
  grid-template-columns: 22px 1fr auto;
  align-items: center;
  padding: 10px 0;
  border-bottom: 1px solid #e6ebee;
  color: #3c4954;
  font-size: 13px;
}

.file-grid .el-icon {
  color: #168b62;
}

.file-grid b {
  color: #168b62;
  font-size: 11px;
}

.file-grid .missing .el-icon,
.file-grid .missing b {
  color: #c23f3f;
}

.control-layout {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  border: 1px solid #dce4e9;
  background: white;
}

.control-column {
  display: flex;
  min-height: 230px;
  flex-direction: column;
  padding: 24px;
  border-right: 1px solid #dce4e9;
}

.control-column:last-child {
  border-right: 0;
}

.control-column.emphasized {
  border-top: 3px solid #168b62;
}

.control-head {
  display: flex;
  gap: 12px;
}

.control-head > span {
  color: #8a96a1;
  font-size: 11px;
  font-weight: 750;
}

.control-head div {
  display: grid;
  gap: 5px;
}

.control-head strong {
  color: #26313b;
  font-size: 15px;
}

.control-head small,
.control-column p {
  color: #75828d;
  font-size: 12px;
}

.control-column p {
  flex: 1;
  margin: 22px 0;
  line-height: 1.7;
}

.control-column .el-button {
  align-self: flex-start;
}

.test-actions,
.log-actions {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 10px;
}

.test-actions {
  margin-top: 18px;
}

.test-actions .el-checkbox {
  margin-left: auto;
}

.log-panel {
  margin-bottom: 32px;
}

.log-panel pre {
  min-height: 220px;
  max-height: 420px;
  margin: 18px 0 0;
  padding: 16px;
  overflow: auto;
  border: 1px solid #d7e0e5;
  border-radius: 5px;
  background: #111820;
  color: #c8d5d1;
  font: 12px/1.65 Consolas, monospace;
  white-space: pre-wrap;
}

@media (max-width: 1100px) {
  .connection-grid,
  .file-grid {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }

  .status-band {
    grid-template-columns: repeat(3, minmax(0, 1fr));
  }
}

@media (max-width: 760px) {
  .defense-intro {
    align-items: flex-start;
    flex-direction: column;
    padding: 26px 20px;
  }

  .mode-state {
    border-left: 0;
    padding-left: 0;
  }

  .panel,
  .control-layout,
  .status-band {
    margin-inline: 14px;
  }

  .connection-grid,
  .file-grid,
  .control-layout,
  .status-band {
    grid-template-columns: 1fr;
  }

  .control-column,
  .status-title,
  .service-state {
    border-right: 0;
    border-bottom: 1px solid #dce4e9;
  }

  .test-actions {
    align-items: stretch;
    flex-direction: column;
  }

  .test-actions .el-checkbox {
    margin-left: 0;
  }
}
</style>
