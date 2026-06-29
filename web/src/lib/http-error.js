// 统一的后端错误解析。合并了原先散落在 App.vue / MotionView / PapbView
// 三处实现的全部分支，行为是各版本的并集：
//   - detail 为数组（FastAPI 校验错误）：按字段拼接每条 msg
//   - detail 为字符串：直接返回
//   - detail.message 存在：返回 message
//   - 网络不可达（ERR_NETWORK）：给出启动后端的提示
//   - 其余：返回调用方传入的 fallback
export const errorText = (error, fallback = '请求失败，请检查服务状态。') => {
  const detail = error?.response?.data?.detail
  if (Array.isArray(detail)) {
    return detail
      .map((item) => {
        const field = item.loc?.slice(-1)?.[0]
        return field ? `${field}: ${item.msg}` : item.msg
      })
      .join('；')
  }
  if (typeof detail === 'string') return detail
  if (detail?.message) return detail.message
  if (error?.code === 'ERR_NETWORK') return '无法连接后端服务，请先启动 127.0.0.1:8010。'
  return fallback
}
