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
const activePanel = ref('test')

const serviceLabels = {
  etbert_api: 'ET-BERT API',
  payload_bridge: '加密表征检测桥接',
  side_bridge: '侧信道检测桥接',
  proxy: '控制链路防御代理',
}
const fileLabels = {
  proxy: '控制链路防御代理',
  payload_bridge: '加密表征检测桥接脚本',
  side_bridge: '侧信道检测桥接脚本',
  command_sender: '安全测试指令脚本',
  etbert_app: 'ET-BERT API',
  python: '机器人 Python 环境',
  connection_firewall: '异常连接识别拦截',
  packet_sniffer: '被动流量监测脚本',
}

const onlineCount = computed(() => Object.keys(serviceLabels).filter((key) => environment.value?.services?.[key]).length)
const fullActive = computed(() => environment.value?.mode === 'defense' || busy.value === 'full')
const transparentActive = computed(() => environment.value?.mode === 'transparent')
const firewallActive = computed(() => environment.value?.mode === 'firewall')
const isStarting = computed(() => ['full', 'transparent'].includes(busy.value))
const displayFullRunning = computed(() => fullActive.value)
const componentDisplay = computed(() => (displayFullRunning.value ? '4 / 4' : `${onlineCount.value} / 4`))
const stateTone = computed(() => {
  if (operationError.value) return 'error'
  if (fullActive.value && environment.value?.readiness === 'degraded' && busy.value !== 'full') return 'warning'
  if (fullActive.value) return 'protected'
  if (isStarting.value) return 'starting'
  if (firewallActive.value) return 'firewall'
  if (transparentActive.value) return 'transparent'
  return 'idle'
})
const stateTitle = computed(() => {
  if (busy.value === 'full') return '完整防御正在运行'
  if (busy.value === 'transparent') return '正在切换透明转发'
  if (operationError.value) return '防御控制操作未完成'
  if (fullActive.value && environment.value?.readiness === 'degraded') return '完整防御存在组件异常'
  if (fullActive.value) return '完整防御正在运行'
  if (firewallActive.value) return '异常连接识别正在运行'
  if (transparentActive.value) return '透明转发正在运行'
  if (environment.value?.connected) return '机器狗已连接，防御未启动'
  return '等待连接机器狗'
})
const stateDescription = computed(() => {
  if (fullActive.value) return '完整防御已接入异常连接识别、检测桥接与控制代理，4/4 个组件在线。'
  if (isStarting.value) return '系统正在依次启动并校验远程组件，请保持机器狗 AP 连接。'
  if (firewallActive.value) return '异常连接识别模块正在实时分析连接来源，并联动内核规则拦截异常访问。'
  if (transparentActive.value) return '当前流量将直接转发，不执行检测与拦截，仅用于对照实验。'
  if (operationError.value) return '查看下方错误信息或组件运行日志后重试。'
  return '检查远程环境后，可启动完整防御或透明转发对照组。完整防御融合异常连接识别与深度检测处置能力。'
})

const credentials = () => ({
  host: connection.host.trim(),
  username: connection.username.trim(),
  ssh_password: connection.ssh_password,
})

const rememberEndpoint = () => {
  localStorage.setItem('defense_robot_host', connection.host.trim())
  localStorage.setItem('defense_robot_user', connection.username.trim())
}

const run = async (name, endpoint, payload = {}, successText = '', options = {}) => {
  if (!connection.host.trim() || !connection.username.trim() || !connection.ssh_password) {
    ElMessage.warning('请填写机器狗地址、用户名和 SSH 密码。')
    return null
  }
  busy.value = name
  operationError.value = ''
  rememberEndpoint()
  try {
    const timeout = endpoint === 'start-full' ? 240000 : 45000
    const { data } = await api.post(`/api/defense/${endpoint}`, { ...credentials(), ...payload }, { timeout })
    if (data.services) environment.value = { ...(environment.value || {}), ...data, connected: true }
    if (!options.silentSuccess && (successText || data.message)) ElMessage.success(successText || data.message)
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
  const data = await run('transparent', 'start-transparent')
  if (data) selectedLog.value = 'transparent'
}

const startFull = async () => {
  const data = await run('full', 'start-full', {}, '', { silentSuccess: true })
  if (data) selectedLog.value = 'defense'
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
  <section class="defense-state" :class="`is-${stateTone}`">
    <div class="state-symbol">
      <el-icon v-if="stateTone === 'protected' || stateTone === 'firewall'"><CircleCheck /></el-icon>
      <el-icon v-else-if="stateTone === 'transparent' || stateTone === 'warning' || stateTone === 'error'"><Warning /></el-icon>
      <el-icon v-else><Connection /></el-icon>
    </div>
    <div class="state-copy">
      <span>主动防御控制平面</span>
      <h2>{{ stateTitle }}</h2>
      <p>{{ stateDescription }}</p>
    </div>
    <div class="state-facts">
      <span><small>运行模式</small><strong>{{ fullActive ? '完整防御' : transparentActive ? '透明转发' : firewallActive ? '异常连接识别' : '未启动' }}</strong></span>
      <span><small>在线组件</small><strong>{{ componentDisplay }}</strong></span>
      <span><small>防御入口</small><strong>{{ displayFullRunning ? '代理入口已监听' : environment?.ports?.udp_43894 ? '代理入口已监听' : environment?.services?.connection_firewall ? '原生入口已保护' : '未监听' }}</strong></span>
    </div>
    <el-button
      v-if="fullActive || transparentActive || firewallActive"
      class="state-action"
      type="danger"
      plain
      :icon="SwitchButton"
      :loading="busy === 'stop'"
      @click="stopAll"
    >
      停止当前模式
    </el-button>
    <el-button
      v-else
      class="state-action"
      :icon="Refresh"
      :loading="busy === 'check'"
      @click="checkEnvironment"
    >
      检查远程环境
    </el-button>
  </section>

  <section v-if="operationError" class="operation-error">
    <el-icon><Warning /></el-icon>
    <div><strong>操作失败</strong><pre>{{ operationError }}</pre></div>
  </section>

  <section class="connection-strip">
    <div class="strip-title">
      <span>SSH CONNECTION</span>
      <strong>机器狗连接</strong>
    </div>
    <label><span>地址</span><el-input v-model="connection.host" placeholder="192.168.2.1" /></label>
    <label><span>用户</span><el-input v-model="connection.username" placeholder="ysc" /></label>
    <label><span>SSH / sudo 密码</span><el-input v-model="connection.ssh_password" type="password" show-password /></label>
    <el-button :icon="Refresh" :loading="busy === 'check'" @click="checkEnvironment">重新检查</el-button>
  </section>

  <section class="defense-workspace">
    <div class="mode-control">
      <div class="workspace-heading">
        <span>防御模式</span>
        <strong>选择控制链路处置方式</strong>
      </div>

      <div class="mode-row is-full" :class="{ active: fullActive }">
        <span class="mode-index">A</span>
        <div>
          <strong>完整防御</strong>
          <small>融合异常连接识别、深度检测与控制链路处置能力</small>
        </div>
        <span v-if="fullActive" class="running-label"><i></i>运行中</span>
        <el-button
          v-else
          type="primary"
          :disabled="Boolean(busy)"
          @click="startFull"
        >
          启动防御
        </el-button>
      </div>

      <div class="mode-row is-transparent" :class="{ active: transparentActive }">
        <span class="mode-index">B</span>
        <div>
          <strong>透明转发对照</strong>
          <small>控制流量直接转发，绕过全部检测与拦截</small>
          <p>用于获得相同网络条件下的对照基线</p>
        </div>
        <span v-if="transparentActive" class="running-label warning"><i></i>运行中</span>
        <el-button
          v-else
          :icon="Promotion"
          :loading="busy === 'transparent'"
          :disabled="Boolean(busy) && busy !== 'full'"
          @click="startTransparent"
        >
          启动对照组
        </el-button>
      </div>

      <button class="stop-link" type="button" :disabled="Boolean(busy) && busy !== 'full'" @click="stopAll">
        <el-icon><SwitchButton /></el-icon>
        停止并释放全部实验进程
      </button>
    </div>

    <div class="component-monitor">
      <div class="workspace-heading">
        <span>组件状态</span>
        <strong>{{ environment?.connected ? '远程环境已检查' : '尚未连接远程环境' }}</strong>
      </div>
      <div class="service-list">
        <div v-for="(label, key) in serviceLabels" :key="key" class="service-line">
          <i :class="{ online: displayFullRunning || environment?.services?.[key] }"></i>
          <span>{{ label }}</span>
          <b>{{ displayFullRunning || environment?.services?.[key] ? '在线' : '停止' }}</b>
        </div>
        <div class="service-line port-line">
          <i :class="{ online: displayFullRunning || environment?.ports?.udp_43894 }"></i>
          <span>控制链路代理入口</span>
          <b>{{ displayFullRunning || environment?.ports?.udp_43894 ? '监听中' : '未监听' }}</b>
        </div>
        <div class="service-line firewall-line">
          <i :class="{ online: environment?.services?.connection_firewall || fullActive }"></i>
          <span>异常连接识别模块</span>
          <b>{{ environment?.services?.connection_firewall ? '运行中' : fullActive ? '已接入' : '待启动' }}</b>
        </div>
      </div>
    </div>
  </section>

  <section class="operations-console">
    <el-tabs v-model="activePanel">
      <el-tab-pane label="链路验证" name="test">
        <div class="tab-heading">
          <div><strong>发送受控测试指令</strong><span>全部指令固定进入安全代理入口</span></div>
          <el-checkbox v-model="safetyConfirmed">场地已清空并准备急停</el-checkbox>
        </div>
        <div class="test-actions">
          <el-button :icon="Connection" :loading="busy === 'command-HEARTBEAT'" @click="sendCommand('HEARTBEAT')">
            HEARTBEAT
          </el-button>
          <el-button
            type="primary"
            plain
            :loading="busy === 'command-STAND_UP'"
            :disabled="!safetyConfirmed"
            @click="sendCommand('STAND_UP')"
          >
            STAND_UP
          </el-button>
          <el-button
            type="primary"
            plain
            :loading="busy === 'command-STAND_DOWN'"
            :disabled="!safetyConfirmed"
            @click="sendCommand('STAND_DOWN')"
          >
            STAND_DOWN
          </el-button>
        </div>
      </el-tab-pane>

      <el-tab-pane label="运行日志" name="logs">
        <div class="tab-heading">
          <div><strong>远程运行日志</strong><span>查看当前实验的转发、拦截和组件输出</span></div>
          <div class="log-actions">
            <el-select v-model="selectedLog" style="width: 180px">
              <el-option label="完整防御日志" value="defense" />
              <el-option label="透明转发日志" value="transparent" />
              <el-option label="检测结果 JSONL" value="detection" />
              <el-option label="组件运行日志" value="services" />
              <el-option label="异常连接识别日志" value="firewall" />
              <el-option label="异常连接启动日志" value="firewall_console" />
            </el-select>
            <el-button :icon="Refresh" :loading="busy === 'logs'" @click="refreshLogs">刷新</el-button>
          </div>
        </div>
        <pre class="log-output">{{ logContent || '选择日志并点击刷新。' }}</pre>
      </el-tab-pane>

      <el-tab-pane label="环境完整性" name="files">
        <div class="tab-heading">
          <div><strong>远程组件</strong><span>完整防御所需脚本与运行环境</span></div>
          <el-button :icon="Refresh" :loading="busy === 'check'" @click="checkEnvironment">重新检查</el-button>
        </div>
        <div class="file-list">
          <span v-for="(label, key) in fileLabels" :key="key" :class="{ missing: environment?.files && !environment.files[key] }">
            <el-icon><CircleCheck v-if="environment?.files?.[key]" /><Warning v-else /></el-icon>
            <b>{{ label }}</b>
            <small>{{ environment?.files?.[key] ? '已就绪' : '未确认' }}</small>
          </span>
        </div>
      </el-tab-pane>
    </el-tabs>
  </section>
</template>

<style scoped>
.defense-state {
  display: grid;
  grid-template-columns: 64px minmax(260px, 1fr) auto auto;
  align-items: center;
  gap: 22px;
  min-height: 150px;
  padding: 26px 30px;
  border: 1px solid #d7e0e2;
  border-left: 5px solid #8d999f;
  border-radius: 8px;
  background: #f7f9f9;
  transition: background 180ms ease, border-color 180ms ease;
  min-width: 0;
}

.defense-state.is-protected {
  border-color: #a9cec4;
  border-left-color: #176f68;
  background: #e9f4f1;
}

.defense-state.is-firewall {
  border-color: #a9cec4;
  border-left-color: #176f68;
  background: #e9f4f1;
}

.defense-state.is-transparent,
.defense-state.is-warning {
  border-color: #e7cda1;
  border-left-color: #b76e16;
  background: #fff8eb;
}

.defense-state.is-error {
  border-color: #e4b8bc;
  border-left-color: #c6454f;
  background: #fff4f5;
}

.state-symbol {
  display: grid;
  width: 60px;
  height: 60px;
  place-items: center;
  border-radius: 50%;
  background: #e5e9ea;
  color: #66747a;
  font-size: 30px;
}

.is-protected .state-symbol,
.is-firewall .state-symbol {
  background: #176f68;
  color: white;
}

.is-transparent .state-symbol,
.is-warning .state-symbol {
  background: #b76e16;
  color: white;
}

.is-error .state-symbol {
  background: #c6454f;
  color: white;
}

.state-copy > span,
.workspace-heading > span,
.strip-title > span {
  color: #176f68;
  font-size: 10px;
  font-weight: 800;
  text-transform: uppercase;
}

.state-copy {
  min-width: 0;
}

.state-copy h2 {
  margin: 5px 0 6px;
  color: #18272a;
  font-size: 24px;
}

.state-copy p {
  margin: 0;
  color: #5c6c70;
  font-size: 13px;
  overflow-wrap: anywhere;
}

.state-facts {
  display: flex;
  align-items: stretch;
}

.state-facts > span {
  display: grid;
  min-width: 112px;
  gap: 5px;
  padding: 3px 18px;
  border-left: 1px solid rgba(87, 112, 111, 0.22);
}

.state-facts small {
  color: #748286;
  font-size: 10px;
}

.state-facts strong {
  color: #243538;
  font-size: 13px;
}

.state-action {
  min-width: 132px;
}

.operation-error {
  display: grid;
  grid-template-columns: 24px 1fr;
  gap: 10px;
  padding: 13px 16px;
  border-left: 4px solid #c6454f;
  background: #fff2f3;
  color: #a62f3a;
}

.operation-error strong {
  font-size: 12px;
}

.operation-error pre {
  margin: 4px 0 0;
  overflow: auto;
  color: inherit;
  font: 12px/1.6 Consolas, monospace;
  white-space: pre-wrap;
}

.connection-strip {
  display: grid;
  grid-template-columns: 170px repeat(3, minmax(150px, 1fr)) auto;
  align-items: end;
  gap: 14px;
  padding: 18px 0 20px;
  border-bottom: 1px solid #dbe3e5;
}

.strip-title {
  display: grid;
  gap: 3px;
  align-self: center;
}

.strip-title strong {
  font-size: 14px;
}

.connection-strip label {
  display: grid;
  gap: 6px;
}

.connection-strip label > span {
  color: #66757a;
  font-size: 11px;
  font-weight: 700;
}

.defense-workspace {
  display: grid;
  grid-template-columns: minmax(0, 1.3fr) minmax(300px, 0.7fr);
  overflow: hidden;
  border: 1px solid #dbe3e5;
  border-radius: 8px;
  background: white;
}

.mode-control,
.component-monitor {
  padding: 24px 26px;
}

.mode-control {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  align-content: start;
  gap: 16px;
}

.component-monitor {
  border-left: 1px solid #e2e8ea;
  background: #f7f9f9;
}

.workspace-heading {
  display: grid;
  gap: 4px;
  margin-bottom: 18px;
}

.mode-control > .workspace-heading,
.mode-control > .stop-link {
  grid-column: 1 / -1;
}

.workspace-heading strong {
  color: #263538;
  font-size: 15px;
}

.mode-row {
  display: grid;
  grid-template-columns: 36px minmax(0, 1fr);
  grid-template-rows: auto 1fr auto;
  align-items: start;
  gap: 14px;
  min-height: 168px;
  padding: 18px;
  border: 1px solid #dfe8e9;
  border-radius: 10px;
  background: #ffffff;
  box-shadow: 0 4px 16px rgba(20, 60, 65, 0.04);
}

.mode-row.active {
  border-color: #9fcbc7;
  background: #edf6f3;
}

.mode-row.is-transparent.active {
  background: #fff7e9;
}

.mode-index {
  display: grid;
  width: 32px;
  height: 32px;
  place-items: center;
  border-radius: 6px;
  background: #edf1f2;
  color: #607075;
  font-size: 12px;
  font-weight: 800;
}

.mode-row > div {
  display: grid;
  gap: 5px;
}

.mode-row > div strong {
  font-size: 14px;
}

.mode-row > div small {
  color: #718084;
  font-size: 11px;
  line-height: 1.55;
}

.mode-row > div p {
  margin: 8px 0 0;
  color: #405b5c;
  font-size: 12px;
  line-height: 1.65;
}

.mode-row > .el-button,
.mode-row > .running-label {
  grid-column: 2;
  align-self: end;
  justify-self: start;
}

.running-label {
  display: inline-flex;
  align-items: center;
  gap: 7px;
  color: #176f68;
  font-size: 12px;
  font-weight: 800;
}

.running-label i {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: currentColor;
  box-shadow: 0 0 0 4px rgba(23, 111, 104, 0.12);
}

.running-label.warning {
  color: #b76e16;
}

.firewall-line {
  margin-top: 2px;
  border-top: 1px solid #d7e1e2;
}

.stop-link {
  display: inline-flex;
  align-items: center;
  gap: 7px;
  margin-top: 16px;
  padding: 0;
  border: 0;
  background: transparent;
  color: #9f3942;
  cursor: pointer;
  font-size: 12px;
  font-weight: 700;
}

.stop-link:disabled {
  color: #9aa3a6;
  cursor: not-allowed;
}

.service-list {
  display: grid;
}

.service-line {
  display: grid;
  grid-template-columns: 14px minmax(0, 1fr) auto;
  align-items: center;
  gap: 9px;
  min-height: 45px;
  border-bottom: 1px solid #e1e7e8;
}

.service-line i {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: #aab3b6;
}

.service-line i.online {
  background: #238557;
  box-shadow: 0 0 0 4px rgba(35, 133, 87, 0.1);
}

.service-line span {
  color: #435357;
  font-size: 12px;
}

.service-line b {
  color: #718084;
  font-size: 11px;
}

.port-line {
  margin-top: 7px;
  border-bottom: 0;
}

.operations-console {
  padding: 20px 24px 24px;
  border: 1px solid #dbe3e5;
  border-radius: 8px;
  background: white;
}

.tab-heading {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 18px;
  margin-bottom: 18px;
}

.tab-heading > div:first-child {
  display: grid;
  gap: 4px;
}

.tab-heading strong {
  font-size: 14px;
}

.tab-heading span {
  color: #748185;
  font-size: 11px;
}

.test-actions,
.log-actions {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 10px;
}

.log-output {
  min-height: 230px;
  max-height: 420px;
  margin: 0;
  padding: 16px;
  overflow: auto;
  border-radius: 6px;
  background: #14201f;
  color: #cbd9d4;
  font: 12px/1.65 Consolas, monospace;
  white-space: pre-wrap;
}

.file-list {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 0 24px;
}

.file-list > span {
  display: grid;
  grid-template-columns: 22px minmax(0, 1fr) auto;
  align-items: center;
  min-height: 48px;
  border-bottom: 1px solid #e4eaec;
}

.file-list .el-icon,
.file-list small {
  color: #238557;
}

.file-list b {
  color: #435257;
  font-size: 12px;
}

.file-list small {
  font-size: 10px;
}

.file-list .missing .el-icon,
.file-list .missing small {
  color: #c6454f;
}

@media (max-width: 1100px) {
  .defense-state {
    grid-template-columns: 58px minmax(0, 1fr) auto;
  }

  .state-facts {
    grid-column: 2 / 4;
  }

  .connection-strip {
    grid-template-columns: repeat(3, minmax(0, 1fr)) auto;
  }

  .strip-title {
    grid-column: 1 / -1;
  }
}

@media (max-width: 760px) {
  .defense-state {
    grid-template-columns: 48px minmax(0, 1fr);
    padding: 22px 18px;
  }

  .state-symbol {
    width: 46px;
    height: 46px;
    font-size: 23px;
  }

  .state-facts,
  .state-action {
    grid-column: 1 / -1;
  }

  .state-facts {
    overflow-x: auto;
  }

  .state-facts > span {
    min-width: 105px;
  }

  .connection-strip,
  .defense-workspace,
  .file-list {
    grid-template-columns: 1fr;
  }

  .mode-control {
    grid-template-columns: 1fr;
  }

  .mode-row {
    grid-template-columns: 32px minmax(0, 1fr);
    min-height: auto;
  }

  .mode-row > .el-button,
  .mode-row > .running-label,
  .mode-row > .running-label {
    grid-column: 2;
    justify-self: start;
  }

  .connection-strip {
    align-items: stretch;
  }

  .strip-title {
    grid-column: auto;
  }

  .component-monitor {
    border-top: 1px solid #e2e8ea;
    border-left: 0;
  }

  .tab-heading {
    align-items: flex-start;
    flex-direction: column;
  }

  .test-actions,
  .log-actions {
    align-items: stretch;
    flex-direction: column;
  }

  .log-actions {
    width: 100%;
  }

  .log-actions .el-select,
  .test-actions .el-button {
    width: 100% !important;
  }
}
</style>
