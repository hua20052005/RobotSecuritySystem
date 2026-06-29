// 浏览器端文件下载工具：把字符串/对象生成 Blob 并触发下载。
// 各分析页面之前各自复制了一份，统一收口到这里。

const triggerDownload = (filename, blob) => {
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = filename
  link.click()
  URL.revokeObjectURL(url)
}

export const downloadText = (filename, text, mime = 'text/markdown;charset=utf-8') => {
  triggerDownload(filename, new Blob([text], { type: mime }))
}

export const downloadJson = (filename, data) => {
  triggerDownload(filename, new Blob([JSON.stringify(data, null, 2)], {
    type: 'application/json;charset=utf-8',
  }))
}
