<script setup>
import { inject } from 'vue'
import { useRouter } from 'vue-router'

const router = useRouter()
const openAuth = inject('openAuth')

const modules = [
  {
    title: '侧信道分析',
    text: '基于报文长度、间隔、端口和熵值识别异常通信行为。',
    path: '/side-channel',
  },
  {
    title: '载荷检测',
    text: '对通信包载荷执行逐包评分，输出 CSV 与 JSON 证据。',
    path: '/payload',
  },
  {
    title: '运动时序建模',
    text: '把动作流量转为符号序列，分析模板偏移与任务转移异常。',
    path: '/motion',
  },
]
</script>

<template>
  <main class="entry-page">
    <section class="entry-panel">
      <div class="entry-copy">
        <p class="entry-kicker">Robot Security System</p>
        <h1>机器人网络安全检测工作台</h1>
        <p>
          面向比赛演示和取证复核的三模块系统。进入后通过左侧栏切换检测能力，
          每个模块独立运行并保留可下载证据。
        </p>
        <div class="entry-actions">
          <el-button type="primary" size="large" @click="router.push('/side-channel')">
            进入工作台
          </el-button>
          <el-button size="large" @click="openAuth?.('login')">登录</el-button>
          <el-button size="large" @click="openAuth?.('register')">注册</el-button>
        </div>
      </div>

      <div class="entry-modules">
        <button
          v-for="item in modules"
          :key="item.path"
          class="entry-module"
          type="button"
          @click="router.push(item.path)"
        >
          <span class="entry-module-index">0{{ modules.indexOf(item) + 1 }}</span>
          <strong>{{ item.title }}</strong>
          <span>{{ item.text }}</span>
        </button>
      </div>
    </section>
  </main>
</template>
