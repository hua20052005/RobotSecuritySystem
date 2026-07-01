<script setup>
import { computed } from 'vue'
import { CopyDocument, Download } from '@element-plus/icons-vue'

import { downloadJson } from '../lib/download'

const props = defineProps({
  data: { type: [Object, Array, String, Number, Boolean], required: true },
  filename: { type: String, default: 'result.json' },
  title: { type: String, default: 'JSON 结果' },
})
const text = computed(() => JSON.stringify(props.data, null, 2))

const copy = async () => {
  try {
    await navigator.clipboard.writeText(text.value)
    ElMessage.success('JSON 已复制')
  } catch {
    ElMessage.warning('复制失败，请展开 JSON 后手动复制')
  }
}
</script>

<template>
  <div class="json-viewer">
    <div class="json-viewer-toolbar">
      <strong>{{ title }}</strong>
      <div>
        <el-button text :icon="CopyDocument" @click="copy">复制</el-button>
        <el-button text :icon="Download" @click="downloadJson(filename, data)">下载</el-button>
      </div>
    </div>
    <el-collapse>
      <el-collapse-item title="展开原始 JSON" name="json">
        <pre>{{ text }}</pre>
      </el-collapse-item>
    </el-collapse>
  </div>
</template>
