<script setup>
import { inject } from 'vue'
import { useRouter } from 'vue-router'

const router = useRouter()
const openAuth = inject('openAuth')

const modules = [
  {
    title: '侧信道流量分析',
    text: '读取 PCAP，提取包长、间隔、端口、熵和 IP 画像，定位异常通信行为。',
    path: '/side-channel',
  },
  {
    title: '通信载荷检测',
    text: '运行载荷检测流水线，输出威胁等级、协议分布和可导出的检测明细。',
    path: '/payload',
  },
  {
    title: '动作序列识别与异常分析',
    text: '上传机器狗通信 PCAP，识别动作序列并判断动作转移是否异常。',
    path: '/motion',
  },
  {
    title: 'PAPB 流程校验',
    text: '校验任务动作序列，识别缺失、插入、顺序错误和未知流程。',
    path: '/papb',
  },
]

const workflow = [
  '导入流量或动作序列',
  '提取行为特征',
  '对照模型和规则',
  '保存审计证据',
]
</script>

<template>
  <main class="entry-page">
    <section class="entry-panel entry-panel-wide">
      <div class="entry-copy">
        <p class="entry-kicker">Robot Security System</p>
        <h1>机器人控制流量审计台</h1>
        <p>
          面向比赛演示和本地复核的安全分析工具。它把侧信道、载荷、运动时序和 PAPB
          流程校验放在同一个工作台里，方便从一份流量证据追到具体异常。
        </p>
        <div class="entry-actions">
          <el-button type="primary" size="large" @click="router.push('/side-channel')">
            开始分析
          </el-button>
          <el-button size="large" @click="router.push('/history')">查看历史</el-button>
          <el-button size="large" @click="openAuth?.('login')">登录</el-button>
        </div>

        <div class="entry-workflow">
          <div v-for="(step, index) in workflow" :key="step" class="workflow-step">
            <span>{{ index + 1 }}</span>
            <strong>{{ step }}</strong>
          </div>
        </div>
      </div>

      <div class="entry-modules">
        <button
          v-for="(item, index) in modules"
          :key="item.path"
          class="entry-module"
          type="button"
          @click="router.push(item.path)"
        >
          <span class="entry-module-index">0{{ index + 1 }}</span>
          <strong>{{ item.title }}</strong>
          <span>{{ item.text }}</span>
        </button>
      </div>
    </section>
  </main>
</template>
