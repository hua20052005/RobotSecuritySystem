<script setup>
import { computed } from 'vue'

const props = defineProps({
  content: { type: String, default: '' },
})

const escapeHtml = (value) => String(value)
  .replace(/&/g, '&amp;')
  .replace(/</g, '&lt;')
  .replace(/>/g, '&gt;')
  .replace(/"/g, '&quot;')
  .replace(/'/g, '&#039;')

const renderInline = (value) => escapeHtml(value)
  .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
  .replace(/`([^`]+)`/g, '<code>$1</code>')

const html = computed(() => {
  const lines = props.content.split(/\r?\n/)
  const output = []
  let inList = false

  const closeList = () => {
    if (inList) {
      output.push('</ul>')
      inList = false
    }
  }

  lines.forEach((line) => {
    const trimmed = line.trim()
    if (!trimmed) {
      closeList()
      return
    }

    const heading = trimmed.match(/^(#{1,4})\s+(.+)$/)
    if (heading) {
      closeList()
      const level = Math.min(heading[1].length + 1, 5)
      output.push(`<h${level}>${renderInline(heading[2])}</h${level}>`)
      return
    }

    const bullet = trimmed.match(/^[-*]\s+(.+)$/) || trimmed.match(/^\d+\.\s+(.+)$/)
    if (bullet) {
      if (!inList) {
        output.push('<ul>')
        inList = true
      }
      output.push(`<li>${renderInline(bullet[1])}</li>`)
      return
    }

    closeList()
    output.push(`<p>${renderInline(trimmed)}</p>`)
  })

  closeList()
  return output.join('')
})
</script>

<template>
  <article class="markdown-report" v-html="html"></article>
</template>
