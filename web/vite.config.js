import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import AutoImport from 'unplugin-auto-import/vite'
import Components from 'unplugin-vue-components/vite'
import { ElementPlusResolver } from 'unplugin-vue-components/resolvers'

// https://vite.dev/config/
export default defineConfig({
  plugins: [
    vue(),
    // 按需引入 Element Plus，替代过去的全量注册 + 全量 CSS。
    // AutoImport：ElMessage / ElMessageBox / ElLoading 等 JS API（并自动注入其样式）。
    // Components：模板里的 <el-xxx> 组件与 v-loading 等指令（同样自动注入样式）。
    AutoImport({ resolvers: [ElementPlusResolver()] }),
    Components({ resolvers: [ElementPlusResolver()] }),
  ],
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
