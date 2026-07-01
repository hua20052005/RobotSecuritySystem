import { createRouter, createWebHistory } from 'vue-router'

import HomeView from '../views/HomeView.vue'

// 入口页 HomeView 静态引入保证首屏即时渲染；其余页面按需懒加载，
// 各自打成独立 chunk（含 ECharts 的页面只在进入时才下载）。
const SideChannelView = () => import('../views/SideChannelView.vue')
const MotionView = () => import('../views/MotionView.vue')
const EtBertView = () => import('../views/EtBertView.vue')
const HistoryView = () => import('../views/HistoryView.vue')
const ProfileView = () => import('../views/ProfileView.vue')

const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/', name: 'home', component: HomeView },
    { path: '/side-channel', name: 'side-channel', component: SideChannelView, meta: { title: '侧信道流量分析', description: '从通信元数据、IP 与端口行为中定位可疑连接和异常数据包。' } },
    { path: '/payload', name: 'payload', component: EtBertView, meta: { title: '通信载荷检测', description: '使用 ET-BERT 包级与流级模型识别载荷异常和未知通信模式。' } },
    { path: '/motion', name: 'motion', component: MotionView, meta: { title: '动作序列识别与异常分析', description: '恢复机器狗动作时间线，并检查上下文转移与任务流程一致性。' } },
    { path: '/papb', redirect: '/motion' },
    { path: '/history', name: 'history', component: HistoryView, meta: { title: '审计历史', description: '检索、复核并导出历史检测任务与审计证据。', requiresAuth: true } },
    { path: '/profile', name: 'profile', component: ProfileView, meta: { title: '账户设置', description: '管理本地审计账户与个人偏好。', requiresAuth: true } },
  ],
  scrollBehavior() {
    return { top: 0 }
  },
})

router.beforeEach((to) => {
  if (to.meta.requiresAuth && !localStorage.getItem('rss_token')) {
    ElMessage.warning('请先登录后再访问账户和历史记录。')
    return '/side-channel'
  }
  return true
})

export default router
