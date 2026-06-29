<script setup>
import { inject } from 'vue'
import { useRouter } from 'vue-router'

const router = useRouter()
const openAuth = inject('openAuth')

const features = ['侧信道分析', 'ET-BERT 双粒度检测', '动作序列识别', 'PAPB 流程校验']
</script>

<template>
  <main class="home">
    <!-- 缓慢漂浮的极光光晕（纯装饰，置于内容下层） -->
    <div class="home-aurora" aria-hidden="true">
      <span class="home-grid"></span>
      <span class="home-ring"></span>
      <span class="blob blob-a"></span>
      <span class="blob blob-b"></span>
      <span class="blob blob-c"></span>
    </div>

    <section class="home-hero">
      <span class="home-kicker">Robot Security System</span>
      <div class="home-title-wrap">
        <h1>机器人控制流量审计台</h1>
      </div>
      <p>
        面向比赛演示与本地复核的安全分析工具。把侧信道、ET-BERT 双粒度检测、运动时序和 PAPB
        流程校验放进同一个工作台，从一份流量证据追到具体异常。
      </p>
      <div class="home-actions">
        <el-button type="primary" size="large" @click="router.push('/side-channel')">
          开始分析
        </el-button>
        <el-button size="large" @click="openAuth?.('login')">登录</el-button>
      </div>

      <div class="home-modules">
        <span v-for="f in features" :key="f">{{ f }}</span>
      </div>
    </section>
  </main>
</template>

<style scoped>
.home {
  position: relative;
  min-height: 100vh;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 48px 24px;
  overflow: hidden;
  background:
    radial-gradient(circle at top, rgba(30, 90, 168, 0.12), transparent 34%),
    radial-gradient(circle at 80% 15%, rgba(15, 118, 110, 0.1), transparent 26%),
    linear-gradient(180deg, #f8fbff 0%, #f4f7fb 100%);
}

/* ── 氛围背景：三团缓慢漂浮、模糊的色光 ── */
.home-aurora {
  position: absolute;
  inset: 0;
  z-index: 0;
  pointer-events: none;
}

.home-grid {
  position: absolute;
  inset: -10%;
  background-image:
    linear-gradient(rgba(30, 90, 168, 0.05) 1px, transparent 1px),
    linear-gradient(90deg, rgba(30, 90, 168, 0.05) 1px, transparent 1px);
  background-size: 72px 72px;
  mask-image: radial-gradient(circle at center, black 42%, transparent 82%);
  opacity: 0.45;
  transform: perspective(1200px) rotateX(64deg) translateY(16%);
  transform-origin: center top;
  animation: grid-drift 22s linear infinite;
}

.home-ring {
  position: absolute;
  left: 50%;
  top: 50%;
  width: min(72vw, 760px);
  aspect-ratio: 1;
  transform: translate(-50%, -48%);
  border-radius: 50%;
  border: 1px solid rgba(30, 90, 168, 0.14);
  box-shadow:
    inset 0 0 40px rgba(30, 90, 168, 0.08),
    0 0 120px rgba(30, 90, 168, 0.08);
  opacity: 0.65;
}

.home-ring::before,
.home-ring::after {
  content: '';
  position: absolute;
  inset: -12px;
  border-radius: 50%;
  border: 1px solid rgba(15, 118, 110, 0.08);
}

.home-ring::before {
  transform: scale(0.88) rotate(18deg);
  animation: spin-slow 34s linear infinite;
}

.home-ring::after {
  transform: scale(1.08) rotate(-22deg);
  animation: spin-slower 46s linear infinite reverse;
}

.blob {
  position: absolute;
  border-radius: 50%;
  filter: blur(80px);
  opacity: 0.55;
}

.blob-a {
  width: 560px;
  height: 560px;
  top: -180px;
  left: 50%;
  margin-left: -480px;
  background: radial-gradient(circle, rgba(30, 90, 168, 0.22), transparent 68%);
  animation: drift-a 24s ease-in-out infinite;
}

.blob-b {
  width: 500px;
  height: 500px;
  top: -140px;
  left: 50%;
  margin-left: 40px;
  background: radial-gradient(circle, rgba(15, 118, 110, 0.18), transparent 68%);
  animation: drift-b 28s ease-in-out infinite;
}

.blob-c {
  width: 460px;
  height: 460px;
  bottom: -220px;
  left: 50%;
  margin-left: -230px;
  background: radial-gradient(circle, rgba(30, 90, 168, 0.12), transparent 70%);
  animation: drift-c 32s ease-in-out infinite;
}

@keyframes drift-a {
  0%, 100% { transform: translate(0, 0) scale(1); }
  50% { transform: translate(46px, 34px) scale(1.1); }
}

@keyframes drift-b {
  0%, 100% { transform: translate(0, 0) scale(1); }
  50% { transform: translate(-52px, 22px) scale(1.08); }
}

@keyframes drift-c {
  0%, 100% { transform: translate(0, 0) scale(1); }
  50% { transform: translate(30px, -28px) scale(1.12); }
}

@keyframes grid-drift {
  from { background-position: 0 0, 0 0; }
  to { background-position: 72px 72px, 72px 72px; }
}

@keyframes spin-slow {
  from { transform: scale(0.88) rotate(18deg); }
  to { transform: scale(0.88) rotate(378deg); }
}

@keyframes spin-slower {
  from { transform: scale(1.08) rotate(-22deg); }
  to { transform: scale(1.08) rotate(-382deg); }
}

/* ── 居中 hero ── */
.home-hero {
  position: relative;
  z-index: 1;
  display: flex;
  flex-direction: column;
  align-items: center;
  text-align: center;
  max-width: 760px;
}

.home-title-wrap {
  position: relative;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  padding: 0 0 12px;
  margin-inline: auto;
}

.home-title-wrap::before {
  content: none;
}

.home-title-wrap::after {
  content: '';
  position: absolute;
  inset: auto 14% 0;
  height: 3px;
  border-radius: 999px;
  background: linear-gradient(90deg, transparent, rgba(30, 90, 168, 0.4), rgba(15, 118, 110, 0.55), transparent);
  filter: blur(1px);
  animation: title-scan 4.8s ease-in-out infinite;
}

/* 进场：逐行上浮淡入 */
.home-hero > * {
  opacity: 0;
  animation: rise 0.72s cubic-bezier(0.2, 0.7, 0.2, 1) forwards;
}

.home-kicker { animation-delay: 0.05s; }
.home-hero h1 { animation-delay: 0.16s; }
.home-hero p { animation-delay: 0.29s; }
.home-actions { animation-delay: 0.42s; }
.home-modules { animation-delay: 0.54s; }

@keyframes rise {
  from { opacity: 0; transform: translateY(16px); }
  to { opacity: 1; transform: translateY(0); }
}

@keyframes title-scan {
  0%, 100% { transform: translateX(-8%); opacity: 0.65; }
  50% { transform: translateX(8%); opacity: 1; }
}

.home-kicker {
  margin-bottom: 24px;
  padding: 6px 15px;
  border-radius: 999px;
  background: var(--accent-soft);
  color: var(--accent);
  font-size: 12px;
  font-weight: 700;
  letter-spacing: 0.14em;
  text-transform: uppercase;
}

.home-hero h1 {
  margin: 0;
  position: relative;
  z-index: 1;
  font-family: 'PingFang SC', 'Noto Sans SC', 'Microsoft YaHei UI', 'Microsoft YaHei', sans-serif;
  font-size: clamp(38px, 6.4vw, 66px);
  font-weight: 850;
  line-height: 1.04;
  letter-spacing: -0.06em;
  color: transparent;
  background: linear-gradient(135deg, #0d1725 0%, #123966 36%, #1e5aa8 64%, #0f766e 100%);
  -webkit-background-clip: text;
  background-clip: text;
  text-shadow: 0 2px 18px rgba(30, 90, 168, 0.08);
  filter: drop-shadow(0 12px 28px rgba(22, 32, 46, 0.12));
}

.home-hero p {
  margin: 24px 0 36px;
  max-width: 600px;
  color: var(--muted);
  font-size: 17px;
  line-height: 1.7;
}

.home-hero p::selection,
.home-hero h1::selection,
.home-kicker::selection {
  background: rgba(30, 90, 168, 0.18);
}

.home-actions {
  display: flex;
  flex-wrap: wrap;
  justify-content: center;
  gap: 12px;
}

/* 底部模块名：细竖线分隔的轻量列表 */
.home-modules {
  display: flex;
  flex-wrap: wrap;
  justify-content: center;
  margin-top: 44px;
  color: var(--muted);
  font-size: 13px;
  font-weight: 600;
}

.home-modules span {
  position: relative;
  padding: 0 18px;
}

.home-modules span:not(:last-child)::after {
  content: '';
  position: absolute;
  right: 0;
  top: 50%;
  width: 1px;
  height: 12px;
  background: var(--line);
  transform: translateY(-50%);
}

@media (max-width: 640px) {
  .home {
    padding-inline: 16px;
  }

  .home-title-wrap {
    padding-bottom: 10px;
  }

  .home-modules span {
    padding: 0 12px;
  }
}

/* 尊重「减少动态效果」的系统设置 */
@media (prefers-reduced-motion: reduce) {
  .home-hero > * {
    opacity: 1;
    animation: none;
  }

  .blob {
    animation: none;
  }

  .home-grid,
  .home-ring::before,
  .home-ring::after,
  .home-title-wrap::after {
    animation: none;
  }
}
</style>
