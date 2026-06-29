import { createApp } from 'vue'

import './style.css'
import App from './App.vue'
import router from './router'

// Element Plus 改为按需引入（见 vite.config.js）。组件样式由 unplugin 自动注入；
// 中文 locale 不再通过全局 app.use 设置，改用 App.vue 里的 <el-config-provider>。
createApp(App).use(router).mount('#app')
