import { ref } from 'vue'

// 单文件上传的状态与处理：el-upload 的 :file-list / :on-change / :on-remove。
// 四个分析页面之前各自重复了一份完全相同的实现。
export function useSingleUpload() {
  const fileList = ref([])
  const selectedFile = ref(null)

  const handleChange = (file) => {
    selectedFile.value = file.raw
    fileList.value = [file]
  }

  const handleRemove = () => {
    selectedFile.value = null
    fileList.value = []
  }

  return { fileList, selectedFile, handleChange, handleRemove }
}
