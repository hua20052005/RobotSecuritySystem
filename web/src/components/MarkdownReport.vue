<script setup>
import { computed } from 'vue'
import { marked } from 'marked'
import DOMPurify from 'dompurify'

const props = defineProps({
  content: { type: String, default: '' },
})

// 用成熟的 marked 解析 Markdown，再用 DOMPurify 清洗，杜绝 XSS。
// 替代了之前手写的正则解析器（功能有限、易出 bug）。
const html = computed(() => {
  const raw = marked.parse(props.content || '', { breaks: true, gfm: true })
  return DOMPurify.sanitize(raw)
})
</script>

<template>
  <article class="markdown-report" v-html="html"></article>
</template>
