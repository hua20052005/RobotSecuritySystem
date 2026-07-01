<script setup>
import { computed } from 'vue'
import { Delete, Document, UploadFilled } from '@element-plus/icons-vue'

const props = defineProps({
  fileList: { type: Array, default: () => [] },
  selectedFile: { type: Object, default: null },
  accept: { type: String, default: '.pcap,.pcapng,.cap' },
  disabled: { type: Boolean, default: false },
  error: { type: String, default: '' },
})
const emit = defineEmits(['change', 'remove'])

const sizeText = computed(() => {
  const bytes = props.selectedFile?.size
  if (!Number.isFinite(bytes)) return ''
  return bytes < 1024 * 1024 ? `${(bytes / 1024).toFixed(1)} KB` : `${(bytes / 1024 / 1024).toFixed(2)} MB`
})
const formatText = computed(() => props.selectedFile?.name?.split('.').pop()?.toUpperCase() || '')
</script>

<template>
  <div class="upload-panel" :class="{ 'has-file': selectedFile, 'has-error': error }">
    <el-upload
      drag
      :auto-upload="false"
      :limit="1"
      :file-list="fileList"
      :show-file-list="false"
      :disabled="disabled"
      :on-change="(file) => emit('change', file)"
      :on-remove="() => emit('remove')"
      :accept="accept"
    >
      <el-icon class="upload-panel-icon"><UploadFilled /></el-icon>
      <strong>{{ selectedFile ? '重新选择抓包文件' : '上传 PCAP 抓包文件' }}</strong>
      <span>拖拽至此处，或点击浏览本地文件</span>
    </el-upload>
    <div v-if="selectedFile" class="upload-file-row">
      <el-icon><Document /></el-icon>
      <div><strong :title="selectedFile.name">{{ selectedFile.name }}</strong><span>{{ sizeText }} · {{ formatText }} · 已就绪</span></div>
      <el-button text type="danger" :icon="Delete" aria-label="删除文件" @click="emit('remove')" />
    </div>
    <p v-if="error" class="upload-error">{{ error }}</p>
  </div>
</template>
