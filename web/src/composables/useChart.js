import { onBeforeUnmount, onMounted } from 'vue'
import echarts from '../lib/echarts'

// 封装单个 ECharts 实例的生命周期：懒初始化、窗口 resize 自适应、卸载时销毁。
// 之前 SideChannelView / PayloadView 各自手写了 init/resize/dispose 样板。
//
// 用法：
//   const chart = useChart(domRef)
//   chart.setOption(option)            // 首次调用自动 init
//   chart.setOption(option, true)      // notMerge=true，整图重绘
export function useChart(domRef) {
  let instance = null

  const resize = () => instance?.resize()

  const setOption = (option, notMerge = false) => {
    if (!instance && domRef.value) {
      instance = echarts.init(domRef.value)
    }
    if (!instance) return
    instance.setOption(option, notMerge)
    // 某些布局首帧尺寸为 0，绘制后再强制 resize 一次。
    requestAnimationFrame(resize)
  }

  onMounted(() => window.addEventListener('resize', resize))
  onBeforeUnmount(() => {
    window.removeEventListener('resize', resize)
    instance?.dispose()
    instance = null
  })

  return { setOption, resize }
}
