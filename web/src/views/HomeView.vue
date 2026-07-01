<script setup>
import { inject } from 'vue'
import { useRouter } from 'vue-router'
import {
  ArrowRight,
  Connection,
  DataAnalysis,
  Lock,
  SetUp,
} from '@element-plus/icons-vue'

import robotDogHero from '../assets/robot-dog-hero.png'

const router = useRouter()
const openAuth = inject('openAuth')

const modules = [
  {
    title: '侧信道流量分析',
    description: '从包长、方向和时间行为中定位可疑通信模式。',
    route: '/side-channel',
    icon: DataAnalysis,
    tone: 'cyan',
    index: '01',
    input: 'PCAP 元数据',
    output: '异常连接与可疑包',
  },
  {
    title: '通信载荷检测',
    description: '使用 ET-BERT 双粒度模型检查流量与报文异常。',
    route: '/payload',
    icon: Lock,
    tone: 'coral',
    index: '02',
    input: 'PCAP 载荷',
    output: '异常类别与置信度',
  },
  {
    title: '动作序列分析',
    description: '识别机器狗动作，并检查上下文转移与流程一致性。',
    route: '/motion',
    icon: Connection,
    tone: 'green',
    index: '03',
    input: '控制链路 PCAP',
    output: '动作时间线与流程结论',
  },
  {
    title: '系统集成防御',
    description: '远程编排检测桥接与 UDP 防御代理，验证放行和拦截。',
    route: '/defense',
    icon: SetUp,
    tone: 'amber',
    index: '04',
    input: '实时控制流量',
    output: '风险处置与拦截日志',
  },
]

const pipeline = ['PCAP 上传', '侧信道分析', '载荷检测', '动作序列识别', 'PAPB 流程校验', '审计报告']
const capabilities = [
  '非侵入式流量审计',
  '双粒度载荷检测',
  '动作序列恢复',
  '流程异常告警',
  '历史追溯与证据导出',
]
</script>

<template>
  <main class="home">
    <header class="home-nav">
      <RouterLink class="home-brand" to="/">
        <span class="home-brand-mark">R</span>
        <span><strong>RobotSec</strong><small>Security Console</small></span>
      </RouterLink>
      <div class="home-nav-actions">
        <button type="button" @click="openAuth?.('login')">登录</button>
        <el-button type="primary" @click="router.push('/unified-analysis')">进入工作台</el-button>
      </div>
    </header>

    <section class="home-hero" :style="{ backgroundImage: `url(${robotDogHero})` }">
      <div class="hero-copy">
        <span class="hero-kicker"><i></i> Robot traffic intelligence</span>
        <h1>机器人控制流量<br>安全审计系统</h1>
        <p>把通信侧信道、载荷内容和动作时序放入一条清晰的审计链路，从原始抓包追踪到可解释的异常证据。</p>
        <div class="hero-actions">
          <el-button type="primary" size="large" @click="router.push('/unified-analysis')">
            三维统一分析
            <el-icon class="el-icon--right"><ArrowRight /></el-icon>
          </el-button>
          <button class="text-action" type="button" @click="router.push('/motion')">查看动作序列模块</button>
        </div>
      </div>

      <div class="hero-status">
        <span class="status-pulse"></span>
        <div><strong>审计节点已就绪</strong><small>Local analysis pipeline</small></div>
      </div>
    </section>

    <section class="module-section">
      <div class="module-heading">
        <div>
          <span>核心模块</span>
          <h2>从流量到行为的三层检测</h2>
        </div>
        <p>按需进入任一模块，也可以沿侧信道、载荷、动作序列的顺序完成整套分析。</p>
      </div>

      <div class="module-grid">
        <button
          v-for="item in modules"
          :key="item.route"
          type="button"
          class="module-card"
          :class="`is-${item.tone}`"
          @click="router.push(item.route)"
        >
          <span class="module-index">{{ item.index }}</span>
          <span class="module-icon"><el-icon><component :is="item.icon" /></el-icon></span>
          <strong>{{ item.title }}</strong>
          <small>{{ item.description }}</small>
          <span class="module-io"><b>输入</b>{{ item.input }}<i></i><b>输出</b>{{ item.output }}</span>
          <span class="module-enter">进入模块 <el-icon><ArrowRight /></el-icon></span>
        </button>
      </div>
    </section>

    <section class="pipeline-section">
      <div class="module-heading">
        <div><span>系统检测链路</span><h2>一份抓包，形成完整审计证据</h2></div>
        <p>各模块既可以独立运行，也可以沿统一链路逐步收敛到动作与流程结论。</p>
      </div>
      <div class="pipeline-track">
        <template v-for="(step, index) in pipeline" :key="step">
          <div class="pipeline-step"><span>{{ String(index + 1).padStart(2, '0') }}</span><strong>{{ step }}</strong></div>
          <ArrowRight v-if="index < pipeline.length - 1" class="pipeline-arrow" />
        </template>
      </div>
    </section>

    <section class="capability-section">
      <div><span>平台能力</span><h2>围绕机器人控制链路构建</h2></div>
      <ul><li v-for="item in capabilities" :key="item">{{ item }}</li></ul>
    </section>
  </main>
</template>

<style scoped>
.home {
  min-height: 100vh;
  padding: 0 clamp(18px, 4vw, 64px) 64px;
  background: #eaf0f3;
}

.home-nav {
  display: flex;
  align-items: center;
  justify-content: space-between;
  min-height: 82px;
  max-width: 1440px;
  margin: 0 auto;
}

.home-brand {
  display: flex;
  align-items: center;
  gap: 11px;
  color: #171b24;
  text-decoration: none;
}

.home-brand-mark {
  display: grid;
  width: 36px;
  height: 36px;
  place-items: center;
  border-radius: 7px;
  background: #171b24;
  color: white;
  font-weight: 800;
}

.home-brand > span:last-child {
  display: grid;
}

.home-brand strong {
  font-size: 16px;
}

.home-brand small {
  color: #77828f;
  font-size: 10px;
  text-transform: uppercase;
}

.home-nav-actions {
  display: flex;
  align-items: center;
  gap: 10px;
}

.home-nav-actions > button:first-child,
.text-action {
  border: 0;
  background: transparent;
  color: #3f4a58;
  cursor: pointer;
  font-weight: 650;
}

.home-hero {
  position: relative;
  min-height: clamp(520px, 68vh, 720px);
  max-width: 1440px;
  margin: 0 auto;
  overflow: hidden;
  border-radius: 8px;
  background-position: center;
  background-size: cover;
  box-shadow: 0 24px 70px rgba(30, 42, 54, 0.12);
}

.hero-copy {
  position: absolute;
  top: 50%;
  left: clamp(30px, 6vw, 92px);
  width: min(600px, 50%);
  transform: translateY(-50%);
}

.hero-kicker {
  display: inline-flex;
  align-items: center;
  gap: 9px;
  color: #466172;
  font-size: 12px;
  font-weight: 750;
  text-transform: uppercase;
}

.hero-kicker i {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: #11a5a3;
  box-shadow: 0 0 0 5px rgba(17, 165, 163, 0.12);
}

.hero-copy h1 {
  margin: 22px 0 20px;
  color: #171b24;
  font-size: clamp(42px, 4.5vw, 64px);
  font-weight: 780;
  line-height: 1.07;
}

.hero-copy p {
  max-width: 470px;
  margin: 0;
  color: #526271;
  font-size: 16px;
  line-height: 1.75;
}

.hero-actions {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 18px;
  margin-top: 34px;
}

.hero-status {
  position: absolute;
  right: 30px;
  bottom: 28px;
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 10px 14px;
  border: 1px solid rgba(255, 255, 255, 0.75);
  border-radius: 6px;
  background: rgba(255, 255, 255, 0.78);
  box-shadow: 0 8px 24px rgba(34, 52, 66, 0.08);
  backdrop-filter: blur(12px);
}

.status-pulse {
  width: 9px;
  height: 9px;
  border-radius: 50%;
  background: #1a9b61;
  box-shadow: 0 0 0 5px rgba(26, 155, 97, 0.13);
}

.hero-status div {
  display: grid;
  gap: 2px;
}

.hero-status strong {
  font-size: 12px;
}

.hero-status small {
  color: #72808d;
  font-size: 10px;
}

.module-section {
  max-width: 1260px;
  margin: 58px auto 0;
}

.module-heading {
  display: flex;
  align-items: end;
  justify-content: space-between;
  gap: 32px;
  margin-bottom: 24px;
}

.module-heading span {
  color: #2f6fed;
  font-size: 12px;
  font-weight: 750;
}

.module-heading h2 {
  margin: 8px 0 0;
  font-size: clamp(25px, 3vw, 38px);
}

.module-heading p {
  max-width: 450px;
  margin: 0;
  color: #677582;
  line-height: 1.65;
}

.module-grid {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 16px;
}

.module-card {
  position: relative;
  display: grid;
  min-height: 290px;
  padding: 24px;
  overflow: hidden;
  border: 1px solid #dfe6eb;
  border-radius: 8px;
  background: #fff;
  color: #171b24;
  text-align: left;
  cursor: pointer;
  transition: transform 180ms ease, box-shadow 180ms ease, border-color 180ms ease;
}

.module-card:hover {
  transform: translateY(-3px);
  border-color: #c4d1da;
  box-shadow: 0 16px 36px rgba(39, 54, 68, 0.09);
}

.module-index {
  position: absolute;
  top: 22px;
  right: 22px;
  color: #a4adb6;
  font-size: 12px;
  font-weight: 750;
}

.module-icon {
  display: grid;
  width: 46px;
  height: 46px;
  place-items: center;
  border-radius: 8px;
  font-size: 23px;
}

.is-cyan .module-icon {
  background: #e5f7f7;
  color: #078c8a;
}

.is-coral .module-icon {
  background: #fff0eb;
  color: #df6347;
}

.is-green .module-icon {
  background: #eaf7ef;
  color: #278554;
}

.is-amber .module-icon {
  background: #fff5df;
  color: #b56a13;
}

.module-card > strong {
  align-self: end;
  margin-top: 28px;
  font-size: 18px;
}

.module-card > small {
  margin-top: 8px;
  color: #6a7683;
  font-size: 13px;
  line-height: 1.6;
}

.module-io {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 6px;
  margin-top: 15px;
  color: #6b7783;
  font-size: 11px;
}

.module-io b {
  color: #33404c;
  font-weight: 750;
}

.module-io i {
  width: 1px;
  height: 11px;
  margin: 0 3px;
  background: #dce3e7;
}

.module-enter {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  margin-top: 22px;
  color: #2f6fed;
  font-size: 12px;
  font-weight: 750;
}

.pipeline-section,
.capability-section {
  max-width: 1260px;
  margin: 64px auto 0;
}

.pipeline-track {
  display: grid;
  grid-template-columns: repeat(11, auto);
  align-items: center;
  padding: 24px 26px;
  border-top: 1px solid #dce3e7;
  border-bottom: 1px solid #dce3e7;
}

.pipeline-step {
  display: grid;
  gap: 5px;
}

.pipeline-step span {
  color: #83909b;
  font-size: 10px;
  font-weight: 750;
}

.pipeline-step strong {
  color: #25313c;
  font-size: 13px;
  white-space: nowrap;
}

.pipeline-arrow {
  width: 17px;
  margin: 0 14px;
  color: #a5b0b8;
}

.capability-section {
  display: flex;
  align-items: flex-end;
  justify-content: space-between;
  gap: 32px;
  padding-top: 38px;
  border-top: 1px solid #dce3e7;
}

.capability-section span {
  color: #345d9d;
  font-size: 12px;
  font-weight: 750;
}

.capability-section h2 {
  margin: 8px 0 0;
  font-size: 25px;
}

.capability-section ul {
  display: flex;
  flex-wrap: wrap;
  justify-content: flex-end;
  gap: 8px;
  max-width: 690px;
  margin: 0;
  padding: 0;
  list-style: none;
}

.capability-section li {
  padding: 7px 10px;
  border: 1px solid #dce3e7;
  border-radius: 5px;
  background: rgba(255, 255, 255, 0.56);
  color: #53616e;
  font-size: 12px;
}

@media (max-width: 900px) {
  .home-hero {
    min-height: 650px;
    background-position: 62% center;
  }

  .hero-copy {
    top: 56px;
    left: 28px;
    width: calc(100% - 56px);
    transform: none;
  }

  .hero-copy p {
    max-width: 54%;
  }

  .module-grid {
    grid-template-columns: 1fr;
  }

  .module-heading {
    align-items: flex-start;
    flex-direction: column;
  }

  .pipeline-track {
    grid-template-columns: 1fr;
    gap: 10px;
  }

  .pipeline-arrow {
    margin: 0 0 0 12px;
    transform: rotate(90deg);
  }

  .capability-section {
    align-items: flex-start;
    flex-direction: column;
  }

  .capability-section ul {
    justify-content: flex-start;
  }
}

@media (max-width: 600px) {
  .home {
    padding-inline: 12px;
  }

  .home-nav {
    min-height: 70px;
    gap: 12px;
  }

  .home-nav-actions > button:first-child {
    display: none;
  }

  .home-hero {
    min-height: 680px;
    background-position: 38% center;
  }

  .hero-copy {
    left: 20px;
    width: calc(100% - 40px);
  }

  .hero-copy h1 {
    margin-top: 18px;
    font-size: 34px;
    line-height: 1.14;
  }

  .hero-copy p {
    max-width: 78%;
    padding-right: 16px;
    color: #405260;
    font-size: 14px;
    text-shadow: 0 1px 0 rgba(255, 255, 255, 0.92);
  }

  .hero-status {
    max-width: calc(100% - 36px);
    right: 18px;
    bottom: 18px;
  }

  .hero-actions {
    align-items: flex-start;
    flex-direction: column;
    gap: 12px;
    margin-top: 26px;
  }

  .module-section {
    margin-top: 42px;
  }
}

@media (prefers-reduced-motion: reduce) {
  .module-card {
    transition: none;
  }
}
</style>
