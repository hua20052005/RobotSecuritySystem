import { createRouter, createWebHistory } from 'vue-router'
import { ElMessage } from 'element-plus'

import HomeView from '../views/HomeView.vue'
import SideChannelView from '../views/SideChannelView.vue'
import PayloadView from '../views/PayloadView.vue'
import MotionView from '../views/MotionView.vue'
import HistoryView from '../views/HistoryView.vue'
import ProfileView from '../views/ProfileView.vue'

const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/', name: 'home', component: HomeView },
    { path: '/side-channel', name: 'side-channel', component: SideChannelView, meta: { title: '侧信道分析' } },
    { path: '/payload', name: 'payload', component: PayloadView, meta: { title: '载荷检测' } },
    { path: '/motion', name: 'motion', component: MotionView, meta: { title: '运动时序建模' } },
    { path: '/history', name: 'history', component: HistoryView, meta: { title: '历史记录', requiresAuth: true } },
    { path: '/profile', name: 'profile', component: ProfileView, meta: { title: '个人主页', requiresAuth: true } },
  ],
  scrollBehavior() {
    return { top: 0 }
  },
})

router.beforeEach((to) => {
  if (to.meta.requiresAuth && !localStorage.getItem('rss_token')) {
    ElMessage.warning('请先登录后再访问这个页面。')
    return '/side-channel'
  }
  return true
})

export default router
