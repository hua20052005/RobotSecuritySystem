import { createApp } from 'vue'

import './style.css'
import './styles/aqua-theme.css'
import App from './App.vue'
import router from './router'

// Element Plus 鏀逛负鎸夐渶寮曞叆锛堣 vite.config.js锛夈€傜粍浠舵牱寮忕敱 unplugin 鑷姩娉ㄥ叆锛?
// 涓枃 locale 涓嶅啀閫氳繃鍏ㄥ眬 app.use 璁剧疆锛屾敼鐢?App.vue 閲岀殑 <el-config-provider>銆?
createApp(App).use(router).mount('#app')
