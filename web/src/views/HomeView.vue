<script setup>
import { inject } from 'vue'
import { useRouter } from 'vue-router'
import { ArrowRight, DataLine, Lock, Operation, SetUp } from '@element-plus/icons-vue'

import robotDogHero from '../assets/robot-dog-hero.png'

const router = useRouter()
const openAuth = inject('openAuth')

const modules = [
  {
    title: '连接行为感知',
    label: 'TRAFFIC INTELLIGENCE',
    description: '基于连接特征与侧信道统计，刻画控制链路的访问来源、时序节律与流量形态。',
    route: '/side-channel',
    icon: DataLine,
    tone: 'cyan',
    index: '01',
    input: 'PCAP / 实时流量',
    output: '连接风险画像',
  },
  {
    title: '载荷模式研判',
    label: 'ENCRYPTED TRAFFIC',
    description: '对载荷长度、频率、序列片段与局部模式进行研判，识别正常控制与异常注入。',
    route: '/payload',
    icon: Lock,
    tone: 'coral',
    index: '02',
    input: '加密或明文流量',
    output: '载荷行为判断',
  },
  {
    title: '动作流程校验',
    label: 'ACTION ANALYSIS',
    description: '将动作识别结果与任务序列约束联合分析，判断控制流程是否符合预期演化。',
    route: '/motion',
    icon: Operation,
    tone: 'green',
    index: '03',
    input: '动作序列',
    output: '流程异常结论',
  },
]
</script>

<template>
  <main class="home">
    <header class="home-nav">
      <RouterLink class="home-brand" to="/">
        <img class="home-brand-mark" src="/roboguard-mark.png" alt="" />
        <span><strong>RoboGuard</strong><small>Embodied Security</small></span>
      </RouterLink>
      <div class="home-nav-actions">
        <button type="button" @click="openAuth?.('login')">登录</button>
        <el-button type="primary" @click="router.push('/unified-analysis')">进入工作台</el-button>
      </div>
    </header>

    <section class="home-hero" :style="{ backgroundImage: `url(${robotDogHero})` }">
      <div class="hero-copy">
        <span class="hero-kicker"><i></i> ROBOT TRAFFIC INTELLIGENCE</span>
        <h1>RoboGuard</h1>
        <p class="hero-product-title">面向具身智能控制链路的安全防御系统</p>
        <p class="hero-lead">融合连接侧信道、流量表征与动作时序分析，从原始流量发现风险，并进入受控处置流程。</p>
        <div class="hero-tags">
          <span>Traffic Intelligence</span>
          <span>Encrypted Traffic</span>
          <span>Action Analysis</span>
        </div>
        <div class="hero-actions">
          <el-button type="primary" size="large" @click="router.push('/unified-analysis')">
            进入工作台
            <el-icon class="el-icon--right"><ArrowRight /></el-icon>
          </el-button>
          <button class="text-action" type="button" @click="router.push('/unified-analysis')">查看动作序列</button>
        </div>
      </div>

      <div class="hero-status">
        <span class="status-pulse"></span>
        <div><strong>多模块在线</strong><small>连接、载荷与动作分析均可进入工作台</small></div>
      </div>
    </section>

    <section class="module-section">
      <div class="module-heading">
        <div>
          <span>核心模块</span>
          <h2>围绕控制链路构建的三层检测体系</h2>
        </div>
        <p>从连接、载荷到动作流程，逐层建立可解释、可追溯、可联动的检测链路。</p>
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
          <span class="module-badge">{{ item.label }}</span>
          <span class="module-icon"><el-icon><component :is="item.icon" /></el-icon></span>
          <strong>{{ item.title }}</strong>
          <small>{{ item.description }}</small>
          <span class="module-io"><b>输入</b>{{ item.input }}<i></i><b>输出</b>{{ item.output }}</span>
          <span class="module-enter">进入模块 <el-icon><ArrowRight /></el-icon></span>
        </button>
      </div>
    </section>

    <section class="defense-entry">
      <span class="defense-entry-icon"><el-icon><SetUp /></el-icon></span>
      <div>
        <span>主动防御控制平台</span>
        <h2>从发现风险，到受控处置</h2>
        <p>将检测结果与防御编排联动，在进入原生控制入口前完成记录、告警、降级或拦截。</p>
      </div>
      <el-button size="large" type="primary" @click="router.push('/defense')">
        进入防御控制台
        <el-icon class="el-icon--right"><ArrowRight /></el-icon>
      </el-button>
    </section>
  </main>
</template>

<style scoped>
.home {
  min-height: 100vh;
  padding: 0 clamp(18px, 4vw, 64px) 64px;
  background: var(--page-bg);
}

.home-nav,
.home-hero,
.module-section,
.defense-entry {
  max-width: 1440px;
  margin: 0 auto;
}

.home-nav {
  display: flex;
  align-items: center;
  justify-content: space-between;
  min-height: 82px;
}

.home-brand {
  display: flex;
  align-items: center;
  gap: 12px;
  color: var(--text-primary);
  text-decoration: none;
}

.home-brand-mark {
  display: block;
  width: 38px;
  height: 38px;
  object-fit: contain;
  flex: 0 0 auto;
}

.home-brand strong {
  font-size: 16px;
  font-weight: 700;
}

.home-brand small {
  display: block;
  color: var(--text-muted);
  font-size: 10px;
  letter-spacing: 0.06em;
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
  color: var(--text-secondary);
  cursor: pointer;
  font-weight: 650;
}

.home-nav-actions > button:first-child:hover,
.text-action:hover {
  color: var(--primary-strong);
}

.home-hero {
  position: relative;
  min-height: clamp(520px, 68vh, 720px);
  overflow: hidden;
  border-radius: var(--radius-card);
  background-position: center;
  background-size: cover;
  box-shadow: var(--shadow-raised);
}

.home-hero::after {
  content: '';
  position: absolute;
  inset: 0;
  background: linear-gradient(90deg, rgba(244, 248, 248, 0.94) 0%, rgba(244, 248, 248, 0.70) 34%, rgba(244, 248, 248, 0.28) 58%, rgba(244, 248, 248, 0.14) 100%);
  pointer-events: none;
}

.hero-copy {
  position: absolute;
  top: 50%;
  left: clamp(30px, 6vw, 92px);
  width: min(640px, 52%);
  transform: translateY(-50%);
  z-index: 1;
}

.hero-kicker {
  display: inline-flex;
  align-items: center;
  gap: 9px;
  color: var(--text-secondary);
  font-size: 12px;
  font-weight: 700;
  letter-spacing: 0.08em;
  text-transform: uppercase;
}

.hero-kicker i {
  width: 9px;
  height: 9px;
  border-radius: 50%;
  background: var(--primary);
  box-shadow: 0 0 0 5px rgba(99, 180, 179, 0.18);
}

.hero-copy h1 {
  margin: 18px 0;
  color: var(--text-primary);
  font-size: clamp(44px, 5vw, 72px);
  font-weight: 700;
  line-height: 1.04;
  letter-spacing: -0.02em;
}

.hero-copy p {
  margin: 0;
  color: var(--text-secondary);
}

.hero-copy .hero-product-title {
  max-width: 560px;
  margin-bottom: 12px;
  color: var(--text-primary);
  font-size: 22px;
  font-weight: 650;
  line-height: 1.45;
}

.hero-copy .hero-lead {
  max-width: 640px;
  font-size: 14px;
  line-height: 1.65;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.hero-tags {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  margin-top: 18px;
}

.hero-tags span {
  display: inline-flex;
  align-items: center;
  min-height: 30px;
  padding: 0 10px;
  border: 1px solid var(--border);
  border-radius: 999px;
  background: rgba(255, 255, 255, 0.62);
  color: var(--text-secondary);
  font-size: 11px;
  font-weight: 650;
  letter-spacing: 0.05em;
}

.hero-actions {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 16px;
  margin-top: 28px;
}

.hero-status {
  position: absolute;
  right: 30px;
  bottom: 28px;
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 10px 14px;
  border: 1px solid var(--border-light);
  border-radius: var(--radius-control);
  background: rgba(255, 255, 255, 0.88);
  box-shadow: var(--shadow-card);
  backdrop-filter: blur(8px);
  z-index: 1;
}

.status-pulse {
  width: 9px;
  height: 9px;
  border-radius: 50%;
  background: var(--primary);
  box-shadow: 0 0 0 5px rgba(99, 180, 179, 0.16);
}

.hero-status div {
  display: grid;
  gap: 2px;
}

.hero-status strong {
  font-size: 12px;
  color: var(--text-primary);
}

.hero-status small {
  color: var(--text-muted);
  font-size: 10px;
}

.module-section {
  margin-top: 56px;
}

.module-heading {
  display: flex;
  align-items: end;
  justify-content: space-between;
  gap: 32px;
  margin-bottom: 24px;
}

.module-heading span {
  color: var(--primary-strong);
  font-size: 11px;
  font-weight: 700;
  letter-spacing: 0.08em;
}

.module-heading h2 {
  margin: 8px 0 0;
  color: var(--text-primary);
  font-size: clamp(25px, 3vw, 38px);
  font-weight: 700;
}

.module-heading p {
  max-width: 470px;
  margin: 0;
  color: var(--text-secondary);
  line-height: 1.7;
}

.module-grid {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 16px;
}

.module-card {
  position: relative;
  display: grid;
  min-height: 290px;
  padding: 24px;
  overflow: hidden;
  border: 1px solid var(--border);
  border-radius: var(--radius-card);
  background: var(--surface);
  color: var(--text-primary);
  text-align: left;
  cursor: pointer;
  transition: transform 180ms ease, box-shadow 180ms ease, border-color 180ms ease;
}

.module-card:hover {
  transform: translateY(-3px);
  border-color: #c5dcdd;
  box-shadow: var(--shadow-raised);
}

.module-index {
  position: absolute;
  top: 22px;
  right: 22px;
  color: #9bb8ba;
  font-size: 12px;
  font-weight: 700;
}

.module-badge {
  display: inline-flex;
  align-items: center;
  width: fit-content;
  min-height: 28px;
  padding: 0 10px;
  border-radius: 999px;
  background: var(--surface-soft);
  color: var(--text-muted);
  font-size: 10px;
  font-weight: 700;
  letter-spacing: 0.08em;
}

.module-icon {
  display: grid;
  width: 46px;
  height: 46px;
  margin-top: 8px;
  place-items: center;
  border-radius: var(--radius-control);
  font-size: 22px;
}

.is-cyan .module-icon {
  background: #e8f5f4;
  color: var(--primary);
}

.is-coral .module-icon {
  background: #f5eeea;
  color: #a96f60;
}

.is-green .module-icon {
  background: var(--primary-light);
  color: #4d8f72;
}

.module-card > strong {
  align-self: end;
  margin-top: 18px;
  font-size: 18px;
  font-weight: 700;
}

.module-card > small {
  margin-top: 8px;
  color: var(--text-secondary);
  font-size: 13px;
  line-height: 1.65;
}

.module-io {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 6px;
  margin-top: 15px;
  color: var(--text-muted);
  font-size: 11px;
}

.module-io b {
  color: var(--text-secondary);
  font-weight: 700;
}

.module-io i {
  width: 1px;
  height: 11px;
  margin: 0 3px;
  background: var(--border);
}

.module-enter {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  margin-top: 22px;
  color: var(--primary-strong);
  font-size: 12px;
  font-weight: 700;
}

.defense-entry {
  display: grid;
  grid-template-columns: 56px minmax(0, 1fr) auto;
  align-items: center;
  gap: 22px;
  margin-top: 54px;
  padding: 28px 30px;
  border-top: 1px solid var(--border);
  border-bottom: 1px solid var(--border);
  background: linear-gradient(180deg, rgba(232, 244, 243, 0.88), rgba(248, 251, 251, 0.94));
  border-radius: var(--radius-card);
}

.defense-entry-icon {
  display: grid;
  width: 52px;
  height: 52px;
  place-items: center;
  border-radius: var(--radius-control);
  background: var(--primary);
  color: white;
  font-size: 24px;
}

.defense-entry > div > span {
  color: var(--primary-strong);
  font-size: 11px;
  font-weight: 700;
  letter-spacing: 0.08em;
}

.defense-entry h2 {
  margin: 6px 0 6px;
  color: var(--text-primary);
  font-size: 22px;
  font-weight: 700;
}

.defense-entry p {
  max-width: 720px;
  margin: 0;
  color: var(--text-secondary);
  font-size: 13px;
  line-height: 1.7;
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

  .defense-entry {
    grid-template-columns: 52px minmax(0, 1fr);
  }

  .defense-entry .el-button {
    grid-column: 2;
    justify-self: start;
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
  }

  .hero-copy .hero-product-title {
    font-size: 18px;
    line-height: 1.42;
  }

  .hero-copy p {
    max-width: 78%;
    padding-right: 16px;
    color: var(--text-secondary);
    font-size: 14px;
    text-shadow: 0 1px 0 rgba(255, 255, 255, 0.92);
  }

  .hero-copy .hero-lead {
    max-width: 100%;
    white-space: normal;
    overflow: visible;
    text-overflow: clip;
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
</style>
