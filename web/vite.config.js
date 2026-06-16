import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

// https://vite.dev/config/
export default defineConfig({
  plugins: [vue()],
  build: {
    // 把体积较大的第三方库拆成独立 chunk，浏览器可单独缓存，
    // 业务代码改动时不会让用户重新下载 element-plus / echarts。
    // 注：Vite 8 使用 Rolldown，manualChunks 必须是函数形式。
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (!id.includes('node_modules')) return
          if (id.includes('echarts') || id.includes('zrender')) return 'echarts'
          if (id.includes('element-plus')) return 'element-plus'
        },
      },
    },
    chunkSizeWarningLimit: 1100,
  },
})
