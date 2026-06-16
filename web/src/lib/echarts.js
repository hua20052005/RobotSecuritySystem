// 按需引入 ECharts，避免把整个库（~1MB）打进主包。
// 只注册当前前端用到的图表与组件：散点图、柱状图、提示框、网格、视觉映射。
import * as echarts from 'echarts/core'
import { ScatterChart, BarChart } from 'echarts/charts'
import {
  GridComponent,
  TooltipComponent,
  VisualMapComponent,
} from 'echarts/components'
import { CanvasRenderer } from 'echarts/renderers'

echarts.use([
  ScatterChart,
  BarChart,
  GridComponent,
  TooltipComponent,
  VisualMapComponent,
  CanvasRenderer,
])

export default echarts
