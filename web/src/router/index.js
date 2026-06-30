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
    { path: '/side-channel', name: 'side-channel', component: SideChannelView, meta: { title: '侧信道流量分析' } },
    { path: '/payload', name: 'payload', component: EtBertView, meta: { title: '通信载荷检测' } },
    { path: '/motion', name: 'motion', component: MotionView, meta: { title: '动作序列识别与异常分析' } },
    { path: '/papb', redirect: '/motion' },
    { path: '/history', name: 'history', component: HistoryView, meta: { title: '审计历史', requiresAuth: true } },
    { path: '/profile', name: 'profile', component: ProfileView, meta: { title: '账户设置', requiresAuth: true } },
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
