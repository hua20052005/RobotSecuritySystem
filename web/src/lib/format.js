// 时间格式化：空值显示为 '-'，否则用本地时区可读字符串。
export const formatTime = (value) => (value ? new Date(value).toLocaleString() : '-')
